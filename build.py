"""Transform local allowlisted metadata into a dated snapshot and report."""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import date, datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys

from controls import GRAPH_RULES, GUIDANCE, M365_RULES, NIS2, QUESTIONS, RULES, WEB, findings
from evidence import (PROWLER_CATALOGS, SHAREPOINT_SHARING_CAPABILITIES, TYPES, EvidenceError, graph_config, m365_config,
                      project_costs, project_functions, project_inventory, project_posture, prowler_config, read_archive)
from microsoft_guidance import FINDING_REFERENCES, SECTION_REFERENCES, entra_review, reference_rows, url
from report import render
from tab_review import CONFIG_REVIEW, REVIEW_PLANS

BASE = Path(__file__).resolve().parent
SNAPSHOT = re.compile(r"\d{8}T\d{6}Z-[a-f0-9]{10}")
EMAIL = re.compile(r"[^\s\"'<>,;()=@]+@[\w-]+(?:\.[\w-]+)*", re.I)
RETENTION_DAYS = 30
PRIORITY = {"High": 0, "Medium": 1, "Low": 2}
INVITATION_POLICIES = {"none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"}
REVIEW_FIELDS = {
    "httpsOnly": bool, "minTlsVersion": {"1.0", "1.1", "1.2", "1.3"},
    "minScmTlsVersion": {"1.0", "1.1", "1.2", "1.3"}, "anonymousHttpEnabled": bool,
    "scmBasicAuthEnabled": bool, "ftpBasicAuthEnabled": bool, "ftpsState": {"AllAllowed", "FtpsOnly", "Disabled"},
    "remoteDebuggingEnabled": bool, "corsAnyOrigin": bool, "runtimeStatus": {"supported", "within_120_days", "out_of_support"},
    "secretLikeStickySettingPresent": bool, "requests30d": {"zero", "nonzero"}, "allowBlobPublicAccess": bool,
    "secureTransferRequired": bool, "enablePurgeProtection": bool, "publicTriggerEnabled": bool,
    "diagnosticsConfigured": bool, "outsideEEARegion": bool, "reportOnlyPresent": bool,
    "guestInvitationPolicy": INVITATION_POLICIES, "defaultAppRegistration": bool, "smsOrVoiceEnabled": bool,
    "sharingCapability": SHAREPOINT_SHARING_CAPABILITIES, "isLegacyAuthProtocolsEnabled": bool,
    "isResharingByExternalUsersEnabled": bool, "guestSettings.allowCreateUpdateChannels": bool,
    "guestSettings.allowDeleteChannels": bool,
}

AREAS = (
    "Summary", "Systems", "Resilience & DR", "Findings", "Resources", "Resource groups",
    "Access (RBAC)", "Security posture", "Network", "Databases", "Storage", "Apps", "Containers",
    "Integration", "Servers", "Secrets & identities", "Monitoring & logging", "Cost", "Method and limits",
    "Microsoft 365",
)


def system_map():
    filename = BASE / "scripts" / "system_map.csv"
    assignments = {}
    with filename.open(newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames != ["resource_group_id", "system_id", "likely_personal_data"]:
            raise EvidenceError("The system_map.csv header does not match the documented schema.")
        for row in reader:
            group, system, likely = (row.get(k) or "" for k in reader.fieldnames)
            if (not re.fullmatch(r"rg-[0-9a-f]{20}", group) or
                    not re.fullmatch(r"SYS-[0-9]{3,15}", system) or likely not in {"yes", "no", "unknown"}):
                raise EvidenceError("system_map.csv accepts only group aliases, numeric SYS codes, and yes/no/unknown.")
            if group in assignments:
                raise EvidenceError("A group appears more than once in system_map.csv.")
            assignments[group] = (system, {"yes": True, "no": False}.get(likely))
    return assignments


def pseudonym_key():
    value = os.getenv("ASSESSMENT_PSEUDONYM_KEY")
    if value is None:
        return secrets.token_bytes(32)
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise EvidenceError("ASSESSMENT_PSEUDONYM_KEY must contain 64 hexadecimal digits.")
    return bytes.fromhex(value)


def assure_safe(text):
    if EMAIL.search(text):
        raise EvidenceError("Build blocked: the output contains a value that resembles an email address or UPN.")
    return text


def csv_data(columns, records):
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(columns)
    for row in records:
        writer.writerow([("'" + v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@"))
                          else v) for v in row])
    return assure_safe(buf.getvalue())


def graph_evidence(graph):
    states = {(source, field.split(" · ", 1)[0]): value for source, field, value in graph}
    settings = {}
    statuses = ("enabled", "disabled", "enabledForReportingButNotEnforced")
    conditional = "conditionalAccessPolicies.json"
    if all((conditional, state) in states for state in statuses):
        any_report_only = states[conditional, statuses[-1]] > 0
        paginated = any(source == conditional and "more pages" in field for source, field, _ in graph)
        if any_report_only or not paginated:
            settings["reportOnlyPresent"] = any_report_only
    methods = "authenticationMethodsPolicy.json"
    voice, sms = (states.get((methods, method)) for method in ("Voice", "Sms"))
    if "enabled" in (voice, sms) or voice == sms == "disabled":
        settings["smsOrVoiceEnabled"] = "enabled" in (voice, sms)
    auth = "authorizationPolicy.json"
    for source_field, target_field in (("allowInvitesFrom", "guestInvitationPolicy"),
                                       ("allowedToCreateApps", "defaultAppRegistration")):
        if (auth, source_field) in states:
            settings[target_field] = states[auth, source_field]
    return {"id": "Entra policy configuration", "type": "microsoft.graph", "group": None,
            "properties": settings, "source": "ZIP — Microsoft Graph", "evidence_sources": {}}


def model_evidence(resources, graph, m365):
    ledger = {}
    patterns = {}
    batches = {"posture": [], "compliance": []}
    scopes = (("posture", RULES, resources), ("compliance", GRAPH_RULES, [graph_evidence(graph)]),
              ("compliance", M365_RULES, m365))
    for role, rules, scope in scopes:
        for resource in scope:
            for rule in rules:
                field = rule.field
                if not rule.applies_to(resource) or field not in resource["properties"]:
                    continue
                value = resource["properties"][field]
                expected = rule.expected
                if field == "requests30d":
                    value, expected = ("zero" if value == 0 else "nonzero"), "zero"
                accepted = REVIEW_FIELDS[field]
                if (accepted is bool and type(value) is not bool) or (
                    accepted is not bool and (not isinstance(value, str) or value not in accepted)
                ):
                    raise EvidenceError("A projected evidence value is not in the approved Foundry schema.")
                pattern = role, rule.key, value
                if pattern not in patterns:
                    anchor = len(ledger) + 1
                    patterns[pattern] = anchor
                    ledger[anchor] = []
                    batches[role].append({"id": anchor, "control": rule.key, "setting": field, "observed": value,
                                          "finding_when": expected, "typical_severity": rule.severity})
                ledger[patterns[pattern]].append((rule, resource, role))
    return batches, ledger


def finding_record(entry, count, reviews, anonymous_functions, model_selected):
    rule, resource, system, level, raised = entry
    settings = resource["properties"]
    sources = resource["evidence_sources"]
    guide = GUIDANCE[rule.key]
    context = []
    for field in guide.related_fields:
        if field in settings:
            value = settings[field]
            value = "Yes" if value is True else "No" if value is False else value
            context.append(f"{field}: {value} ({sources.get(field, resource['source'])})")
    missing = [field for field in guide.related_fields if field not in settings]
    if rule.key == "APP-FUNC-ANON":
        ids = anonymous_functions.get(resource["id"], [])
        if ids:
            suffix = f"; plus {len(ids) - 5} more in Apps" if len(ids) > 5 else ""
            context.append(f"{len(ids)} enabled anonymous HTTP function(s) in this export: " + ", ".join(sorted(ids)[:5]) + suffix)
        else:
            missing.append("individual function records; only the app-level flag was supplied")
    base = ({"Medium": "Low", "High": "Medium"}[level] if raised else level)
    rating = ("Foundry severity" if model_selected else "Base severity") + f": {base}."
    if raised:
        rating += f" Shown as {level} under the personal-data policy. The owner must confirm the system classification."
    rating += " This is a configuration priority, not an incident classification."
    mapping = f"NIS2 Article 21(2): {', '.join(rule.nis2)}"
    if rule.gdpr:
        mapping += f"; GDPR: {', '.join(rule.gdpr)}"
    primary, *follow_up = FINDING_REFERENCES[rule.key]
    return (rule.key, level, rule.title, count, resource["id"], system, rule.field, settings[rule.field],
            sources.get(rule.field, resource["source"]), rule.why, rule.action, raised,
            QUESTIONS.get(reviews.get("posture", {}).get((resource["id"], rule.key))),
            QUESTIONS.get(reviews.get("compliance", {}).get((resource["id"], rule.key))), "Owner confirmation required",
            guide.owners, guide.limit, " • ".join(context) or None, "; ".join(missing) or None, rating,
            guide.verify, guide.change, guide.close, mapping, url(primary), url(follow_up[0]) if follow_up else None)


def dataset(blob, live, reviews, review_status, timestamp, key, assignments, prepared_archive=None,
            review_mode="off", assess=None):
    uploaded = blob is not None or prepared_archive is not None
    config, skipped = prepared_archive if prepared_archive is not None else (
        read_archive(blob) if blob is not None else ({}, 0))
    sources = []
    if "assessment-v1.json" in config:
        raw = config["assessment-v1.json"]
        sources.append((raw, False))
    if live is not None:
        sources.append((live, True))
    resources, groups, subs, rbac, overlap, omitted, suggestions = project_inventory(sources, key)
    graph, graph_omitted = graph_config(config)
    m365 = m365_config(config, key)
    m365_ids = {scope["id"] for scope in m365}
    version, checks = prowler_config(config.get("prowler-summary.json"),
                                     {name: config[name] for name in PROWLER_CATALOGS if name in config})
    system_assignments = {group: (system, None) for group, system in suggestions.items()} | assignments
    personal_systems = {system for system, likely in system_assignments.values() if likely is True}
    effective_assignments = {group: (system, True if system in personal_systems else likely)
                             for group, (system, likely) in system_assignments.items()}
    functions = project_functions(sources, key)
    anonymous_functions = defaultdict(list)
    for parent, function, trigger, auth, disabled in functions:
        if trigger == "httpTrigger" and auth == "anonymous" and disabled is False:
            anonymous_functions[parent].append(function)
    for resource in resources:
        settings = resource["properties"]
        if "runtimeEosDate" in settings:
            days = (date.fromisoformat(settings["runtimeEosDate"]) - timestamp.date()).days
            settings["runtimeStatus"] = "out_of_support" if days < 0 else "within_120_days" if days <= 120 else "supported"
        if resource["id"] in anonymous_functions and resource["type"] in WEB:
            settings["anonymousHttpEnabled"] = True
            resource["evidence_sources"]["anonymousHttpEnabled"] = "ZIP — function configuration"
    model_selected = review_mode == "model"
    model_rows = []
    model_pattern_count = 0
    foundry_receipts = []
    if model_selected:
        if assess is None:
            raise EvidenceError("A Foundry assessment requires model decisions; no local fallback is permitted.")
        batches, ledger = model_evidence(resources, graph, m365)
        decisions, review_status, foundry_receipts = assess(batches)
        if decisions.keys() != ledger.keys():
            raise EvidenceError("Foundry did not return results covering the submitted evidence.")
        reviews = {"posture": {}, "compliance": {}}
        model_pattern_count = len(ledger)
        active = []
        for anchor, entries in ledger.items():
            verdict, severity, question = decisions[anchor]
            for rule, resource, role in entries:
                model_rows.append((rule.key, resource["id"], rule.field, resource["properties"][rule.field],
                                   resource["evidence_sources"].get(rule.field, resource["source"]), verdict, severity))
                if verdict != "finding":
                    continue
                group = resource["group"]
                if resource["id"] in m365_ids:
                    unassigned = "Microsoft 365 policy (not a resource group)"
                else:
                    unassigned = "Entra policy (not a resource group)" if role == "compliance" else group or "Unassigned"
                system, likely = effective_assignments.get(group, (unassigned, None))
                raised = likely is True and severity != "High"
                level = {"Low": "Medium", "Medium": "High"}[severity] if raised else severity
                reviews[role][resource["id"], rule.key] = question
                active.append((rule, resource, system, level, raised))
    else:
        active = findings(resources, effective_assignments)
    active.sort(key=lambda x: (PRIORITY[x[3]], x[0].key, x[1]["id"]))
    costs = project_costs(sources, key)
    posture = project_posture(sources, key)
    tables = {area: [] for area in AREAS}

    def add(area, slug, label, headers, records, note=None):
        tables[area].append((slug, label, tuple(headers), list(records), note))

    counts = Counter(level for _, _, _, level, _ in active)
    occurrences = Counter((rule.key, level) for rule, _, _, level, _ in active)
    by_key = {rule.key: rule for rule, *_ in active}
    ranked = sorted(occurrences, key=lambda pair: (PRIORITY[pair[1]], -occurrences[pair], pair[0]))
    priority = [{"title": by_key[key].title, "severity": level, "key": key,
                 "affected": occurrences[key, level], "action": by_key[key].action} for key, level in ranked[:3]]
    eligible = Counter()
    observed = Counter()
    for resource in resources:
        for rule in RULES:
            if rule.applies_to(resource):
                eligible[rule.key] += 1
                if rule.field in resource["properties"]:
                    observed[rule.key] += 1
    has_evidence = bool(resources or rbac or graph or m365 or costs or posture or functions
                        or any(row[4] in {"pass", "fail"} for row in checks))
    summary = {"resources": len(resources), "findings": len(active), "high": counts["High"],
               "skipped": skipped, "eligible_files": len(config), "graph_observations": len(graph),
               "m365_observations": sum(len(scope["properties"]) for scope in m365),
               "controls_with_evidence": len(observed), "available_controls": len(RULES),
               "priority": priority,
               "has_evidence": has_evidence, "live_azure": live is not None,
               "analysis_mode": "Foundry" if model_selected else "Local rules",
               "model_evidence_rows": len(model_rows), "model_patterns": model_pattern_count,
               "foundry_requests": len(foundry_receipts),
               "model_insufficient": sum(row[-2] == "insufficient" for row in model_rows)}
    attention = [
        ("Breach status", "Not assessed. These sources neither confirm nor rule out an incident."),
        ("Resources with metadata", len(resources)),         ("Findings (control/evidence pairs)", len(active)),
        ("Assessment engine", summary["analysis_mode"]),
        ("High", counts["High"]), ("Medium", counts["Medium"]), ("Low", counts["Low"]),
        ("Subscriptions observed", len(subs)), ("Resource groups observed", len(groups)),
        ("Recognized configuration types", len(config)), ("Entries skipped", skipped),
        ("Graph configuration observations", len(graph)),
        ("Microsoft 365 configuration observations", summary["m365_observations"]),
        ("Resource controls with evidence", len(observed)),
    ]
    if not has_evidence:
        attention.append(("Coverage", "No usable configuration evidence. Do not interpret zero findings as a favorable result."))
    add("Summary", "overview", "What needs attention", ("Indicator", "Value"), attention)
    if model_selected:
        scope_count = len({resource["id"] for _, resource, _, _, _ in active if not resource["type"].startswith("microsoft.graph")})
        no_finding = sum(row[-2] == "no_finding" for row in model_rows)
        missing = sum(eligible.values()) - sum(observed.values())
        if active:
            label = "finding" if len(active) == 1 else "findings"
            headline = (f"Foundry identified {len(active)} {label} ({counts['High']} high, {counts['Medium']} medium, "
                        f"{counts['Low']} low) affecting {scope_count} of {len(resources)} inventoried Azure resources.")
            if any(resource["type"] == "microsoft.graph" for _, resource, _, _, _ in active):
                headline += " The total also includes Entra policy findings."
            if any(resource["id"] in m365_ids for _, resource, _, _, _ in active):
                headline += " The total also includes Microsoft 365 findings."
            lead = summary["priority"][0]
            next_step = f"Start with {lead['key']} ({lead['severity']}; {lead['affected']} affected scope entries). {lead['action']}"
        else:
            headline = "Foundry reported no findings in the submitted configuration. This does not establish that the tenant is secure."
            next_step = "Review coverage gaps and confirm the export scope before drawing a conclusion."
        summary["executive"] = [
            ("Outcome", headline),
            ("First action", next_step),
            ("Scope", f"{len(config)} recognized configuration types; {skipped} entries skipped. "
                      f"{len(resources)} Azure resources, {len(graph)} Entra observations, and "
                      f"{summary['m365_observations']} Microsoft 365 observations were read from the upload."),
            ("Evidence gaps", f"{no_finding} evidence rows returned no finding; {summary['model_insufficient']} were insufficient. "
                              f"{missing} resource/control pairs had no supported field in the upload and were not sent."),
            ("Foundry calls", f"{len(foundry_receipts)} completed responses covering {model_pattern_count} distinct patterns. "
                              "See Method and limits for request IDs, model metadata, and timings when available."),
        ]
        add("Summary", "executive-summary", "Executive summary", ("Topic", "Conclusion"), summary["executive"])
    hits = Counter(rule.key for rule, *_ in active)
    coverage_rows = [(rule.key, rule.title, observed[rule.key], eligible[rule.key] - observed[rule.key], hits[rule.key],
                      "No resources in scope" if not eligible[rule.key] else
                      "No evidence" if not observed[rule.key] else
                      "Partial evidence" if observed[rule.key] < eligible[rule.key] else "Evidence available")
                     for rule in sorted(RULES, key=lambda rule: (not hits[rule.key], rule.key))]
    add("Summary", "resource-coverage", "Resource control coverage",
        ("Key", "Control", "Resources with evidence", "Resources without evidence", "Findings", "Status"),
        coverage_rows, "Resources in scope are determined by type in this snapshot. Evidence availability is not a pass, and does not measure tenant-wide coverage. Graph and Prowler evidence are shown in Security posture.")
    system_counts = defaultdict(Counter)
    groups_by_system = defaultdict(list)
    for group in groups:
        system, likely = effective_assignments.get(group, (group, None))
        groups_by_system[system].append(likely)
    for item in resources:
        system, _ = effective_assignments.get(item["group"], (item["group"] or "Unassigned", None))
        system_counts[system]["resources"] += 1
        if item["properties"].get("publicNetworkAccess") == "Enabled":
            system_counts[system]["public"] += 1
        if item["properties"].get("publicNetworkAccess") is None:
            system_counts[system]["public_unknown"] += 1
    for _, resource, system, level, _ in active:
        if not resource["type"].startswith("microsoft.graph"):
            system_counts[system][level] += 1
    registered_systems = sorted(system_counts.keys() | groups_by_system.keys())
    def classification(system):
        labels = groups_by_system.get(system, [])
        if True in labels:
            return "Yes — to confirm"
        return "No — to confirm" if labels and all(x is False for x in labels) else "Unknown"
    add("Systems", "system-risk", "System risk matrix",
        ("System", "Groups", "Likely to process personal data", "Resources", "Public access enabled", "Exposure unknown",
         "High", "Medium", "Low", "Observed risk"),
        ((s, len(groups_by_system[s]), classification(s), (c := system_counts[s])["resources"], c["public"],
          c["public_unknown"], c["High"], c["Medium"], c["Low"],
          next((k for k in ("High", "Medium", "Low") if c[k]), "Inconclusive"))
         for s in registered_systems),
        "Public access enabled does not prove anonymous access or reachability. Name-based groupings are suggestions.")
    add("Resource groups", "groups", "Resource groups and system assignments to confirm",
        ("Group (alias)", "System", "Likely to process personal data"),
        ((g, effective_assignments[g][0], classification(effective_assignments[g][0])) for g in groups))
    add("Resource groups", "subscriptions", "Subscriptions observed", ("Subscription (alias)",),
        ((s,) for s in subs))
    add("Resilience & DR", "configuration", "Observed capabilities, not test results",
        ("Resource", "System", "Zones", "Zone redundancy", "Replicas", "Backup", "Deletion protection"),
        ((r["id"], effective_assignments.get(r["group"], (r["group"], None))[0],
          (p := r["properties"]).get("zoneCount"), p.get("zoneRedundant"), p.get("replicaCount"),
          p.get("backupConfigured"), p.get("deleteProtection", p.get("enablePurgeProtection")))
         for r in resources if any(k in r["properties"] for k in ("zoneCount", "zoneRedundant", "replicaCount",
                    "backupConfigured", "deleteProtection", "enablePurgeProtection"))),
        "No restore, failover, or DORA exercises were performed. Unobserved regional topology and backups remain unknown.")
    dr = defaultdict(Counter)
    locations = defaultdict(set)
    for r in resources:
        system = effective_assignments.get(r["group"], (r["group"] or "Unassigned", None))[0]
        p = r["properties"]
        counts_for_system = dr[system]
        if r["location"] not in (None, "global"):
            locations[system].add(r["location"])
        counts_for_system.update(field for field, yes in (
            ("zones", (p.get("zoneCount") or 0) > 1 or p.get("zoneRedundant") is True),
            ("replicas", (p.get("replicaCount") or 0) > 0),
            ("backup", p.get("backupConfigured") is True),
            ("delete", p.get("deleteProtection") is True or p.get("enablePurgeProtection") is True),
        ) if yes)
    add("Resilience & DR", "systems", "Resilience indicators by system",
        ("System", "Distinct regions observed", "Multizone resources", "Resources with replicas", "Resources with backups",
         "Resources with deletion protection"),
        ((system, len(locations[system]), *(c[k] for k in ("zones", "replicas", "backup", "delete")))
         for system, c in sorted(dr.items())),
        "Counts reflect indicators in the available configuration. Zero indicators do not prove a control is absent. Multiple regions do not prove failover capability.")
    add("Findings", "details", "Findings to confirm, not evidence of compromise",
        ("Key", "Severity", "Control", "Affected (control and severity)", "Resource", "System", "Field", "Value", "Source",
         "Why it matters", "Proposed action", "Severity raised (personal data)", "Foundry question — posture",
         "Foundry question — compliance", "Status", "Suggested owners", "What this does not prove",
         "Related evidence", "Related evidence not observed", "Severity rationale",
         "1. Verify before acting", "2. Plan the change", "3. Evidence to close", "Technical compliance mapping",
         "Microsoft Learn — primary", "Microsoft Learn — follow-up"),
        (finding_record(entry, occurrences[entry[0].key, entry[3]], reviews, anonymous_functions, model_selected) for entry in active))
    if model_selected:
        add("Findings", "foundry-decisions", "Foundry evidence decisions",
            ("Control", "Evidence scope", "Observed field", "Observed value", "Source", "Model decision", "Model severity"),
            model_rows, "Decisions are from Foundry. Identical control values share the same model decision. "
            "No finding does not mean the service or tenant is secure. "
            "Imported inventories, costs, and compliance summaries are context, not independent LLM checks.")
    add("Findings", "privacy-fields", "Potentially identifying fields omitted",
        ("Source", "Omitted field", "Action"), ((src, field, "Value omitted. Confirm minimization at the source.")
                                                for src, field in sorted(set(omitted + graph_omitted))))
    inventory_headers = ("Resource (alias)", "Type", "Region", "Subscription", "Group", "Source", "Public access (configuration)")

    def inventory_row(r):
        return r["id"], r["type"], r["location"], r["sub"], r["group"], r["source"], r["properties"].get("publicNetworkAccess")

    add("Resources", "inventory", "Inventory", inventory_headers, (inventory_row(r) for r in resources))
    for area in ("Network", "Databases", "Storage", "Containers", "Integration", "Servers", "Secrets & identities", "Monitoring & logging"):
        add(area, "inventory", "Configuration inventory", inventory_headers,
            (inventory_row(r) for r in resources if TYPES.get(r["type"]) == area),
            "A missing row does not prove the resource or control is absent.")
    add("Access (RBAC)", "assignments", "RBAC assignments", ("Scope (alias)", "Object ID", "Principal type", "Role definition ID"), rbac,
        "Principal IDs are not resolved. Role IDs alone do not establish effective permissions or access to values.")
    app_resources = [r for r in resources if r["type"] in WEB]
    add("Apps", "summary", "Application coverage", ("Indicator", "Value"),
        (("Sites and slots observed", len(app_resources)),
         ("Plans observed", sum(r["type"] == "microsoft.web/serverfarms" for r in resources))))
    app_sections = (
        ("exposure", "Exposure", ("publicNetworkAccess", "accessRestrictionCount", "mainDefaultAction",
            "scmRestrictionCount", "scmUsesMainRestrictions", "scmDefaultAction",
            "privateEndpointCount", "customDomainCount", "hostNameStateCount")),
        ("functions", "HTTP functions without a key", ("anonymousHttpEnabled",)),
        ("security", "Security configuration", ("httpsOnly", "minTlsVersion", "minScmTlsVersion", "ftpsState",
             "ftpBasicAuthEnabled", "scmBasicAuthEnabled", "remoteDebuggingEnabled", "authenticationEnabled",
             "http20Enabled", "clientCertEnabled", "corsAnyOrigin", "detailedErrorsEnabled")),
        ("secrets", "Secrets", ("managedIdentityEnabled", "keyVaultReferenceIdentityConfigured",
                               "stickySettingCount", "secretLikeStickySettingCount")),
        ("deployment", "Deployment and source control", ("deploymentType", "repositoryHost",
            "lastDeploymentDate", "lastDeploymentStatus")),
        ("runtimes", "Runtimes", ("runtimeStack", "runtimeVersion", "runtimeEosDate", "runtimeStatus")),
        ("scaling", "Plans and scaling", ("planId", "alwaysOn", "healthCheckConfigured", "autoHealEnabled", "workers", "zoneRedundant")),
        ("backup", "Resilience", ("backupConfigured", "lastBackupDate", "zoneCount")),
        ("logging", "Logging and usage", ("httpLoggingEnabled", "diagnosticsConfigured", "requests30d",
                                          "http4xx30d", "http5xx30d")),
    )
    for slug, title, fields in app_sections:
        add("Apps", slug, title, ("Resource", *fields),
            ((r["id"], *(r["properties"].get(k) for k in fields)) for r in app_resources
             if any(k in r["properties"] for k in fields)),
            "Only observed fields or fields supplied in the normalized export are shown. Other fields were not assessed.")
    add("Apps", "function-config", "Functions from the normalized export", ("App", "Function", "Trigger", "Auth", "Disabled"),
        functions, "An enabled function without a key requires httpTrigger, anonymous auth, and disabled=false. A missing field leaves the result unknown.")
    app_plan_use = Counter(r["properties"].get("planId") for r in app_resources if r["type"] == "microsoft.web/sites")
    add("Apps", "plans", "App Service plans", ("Plan", "SKU", "Workers", "Zone redundancy", "Linked sites observed"),
        ((r["id"], (p := r["properties"]).get("planSku"), p.get("planWorkers"), p.get("zoneRedundant"),
          app_plan_use[r["id"]]) for r in resources if r["type"] == "microsoft.web/serverfarms"),
        "Zero linked sites in the inventory does not establish that the plan is empty or safe to decommission.")
    add("Apps", "logic", "Logic Apps and API connections", (*inventory_headers, "Reported public trigger"),
        ((*inventory_row(r), r["properties"].get("publicTriggerEnabled")) for r in resources
         if r["type"] in {"microsoft.logic/workflows", "microsoft.web/connections"}))
    app_ids = {r["id"] for r in app_resources}
    add("Apps", "access", "Access — direct assignments observed", ("Resource", "Object ID", "Type", "Role definition ID"),
        (row for row in rbac if row[0] in app_ids))
    add("Apps", "inventory", "All apps", inventory_headers, (inventory_row(r) for r in app_resources))
    add("Security posture", "entra-review", "Entra: how to interpret the evidence",
        ("Review area", "Observed in the export", "Not established", "Recommended verification",
         "Microsoft Learn — primary", "Microsoft Learn — follow-up"),
        entra_review(graph), "These are configuration review prompts, not new findings or proof of tenant-wide enforcement.")
    add("Security posture", "entra", "Entra — Graph configuration summary", ("Source", "Control", "Value"), graph)
    add("Microsoft 365", "configuration", "SharePoint, OneDrive, and Teams configuration",
        ("Evidence scope", "Source", "Setting", "Observed value"),
        ((scope["id"], scope["source"], field, value) for scope in m365
         for field, value in sorted(scope["properties"].items())),
        "Only tenant settings for SharePoint and OneDrive and guest channel settings for supplied Teams are shown. "
        "Missing settings, other workloads, and content are not assessed.")
    add("Microsoft 365", "foundry-decisions", "Microsoft 365 decisions from Foundry",
        ("Control", "Evidence scope", "Setting", "Observed value", "Source", "Decision", "Model severity"),
        (row for row in model_rows if row[1] in m365_ids),
        "Team IDs are pseudonymized. A tenant setting or team guest permission does not prove that content was shared.")
    add("Security posture", "azure-posture", "Defender for Cloud and Azure Policy — aggregates",
        ("Subscription", "Indicator", "Source", "Value"), posture,
        "Only visible aggregates are shown. Defender assessments and Azure Policy states are not counts of unique resources. Active alerts are counted by severity without entities or descriptions. A missing row does not establish that there are no alerts.")
    add("Security posture", "prowler", "CIS Azure and NIS2 — imported results",
        ("Benchmark", "Benchmark version", "Section", "Requirement", "Result", "NIS2 point", "Exclusion"), checks,
        f"Reported Prowler version: {version or 'unavailable'}. Catalog import is not a scan. Requirements without a result were not assessed.")
    nis_rows = [(p, NIS2[p], rule.key, level, r["id"]) for rule, r, _, level, _ in active for p in rule.nis2]
    nis_counts = Counter((p, level) for p, _, _, level, _ in nis_rows)
    nis_status = Counter((point, status if status in {"pass", "fail"} else "other")
                         for b, _, _, _, status, point, _ in checks if b == "NIS2-2024-2690")
    points = {p for p, _ in nis_status}
    add("Security posture", "nis2", "NIS2 Article 21(2) — findings and imported checks",
        ("Point", "Measure", "High", "Medium", "Low", "Prowler Pass", "Prowler Fail", "Prowler Other"),
        ((p, label, *(nis_counts[p, k] for k in ("High", "Medium", "Low")),
          *(nis_status[p, k] if p in points else None for k in ("pass", "fail", "other"))) for p, label in NIS2.items()))
    add("Security posture", "nis2-map", "Finding-to-NIS2 mapping", ("Point", "Measure", "Key", "Severity", "Resource"), nis_rows)
    add("Security posture", "gdpr-map", "GDPR mapping where technical evidence is relevant",
        ("Article", "Key", "Control", "Severity", "Resource"),
        ((art, rule.key, rule.title, level, r["id"]) for rule, r, _, level, _ in active for art in rule.gdpr),
        "This mapping supports the DPO and legal team. It does not certify compliance. Policies, training, supplier contracts, lawful basis, data subject rights, and incident procedures are out of scope.")
    add("Security posture", "coverage", "Collection limits",
        ("Area", "Limit"), (
            ("Defender for Cloud", "Aggregates only. No individual alert records, entities, or descriptions."),
            ("Azure Policy", "Aggregates only. No assignment parameters, details, or definitions."),
            ("Monitoring", "Missing logs or metrics do not establish that no activity or incident occurred."),
        ))
    release = timestamp + timedelta(days=RETENTION_DAYS)
    add("Method and limits", "protection", "Data protection",
        ("Topic", "Policy"), (
            ("Purpose", "Configuration and security posture due diligence, not an investigation of individuals."),
            ("Identity", "Dedicated Azure CLI account if live collection was approved. The mandate requires Reader at the tenant root; the app does not certify that role."),
            ("Excluded", "Data-plane content, sign-in or audit events, IP addresses, customer data, settings values, names, URLs, and free text from exports."),
            ("Limits", "ARM Reader does not grant access to Entra, data-plane content, separate B2C tenants, or the retired classic admin API."),
            ("Storage", "The pseudonymized snapshot, HTML, and CSVs remain in the approved local directory. "
                        "A web upload is streamed to a temporary file there and closed after parsing."),
            ("Access", "Assessment team, authorized owners, DPO, and legal team. Use a company-managed device with access controls and encryption."),
            ("Proposed retention", f"{RETENTION_DAYS} days. Delete the snapshot by {release.date().isoformat()}, subject to DPO approval."),
            ("Cloud", "When approved, Foundry receives allowlisted configuration indicators and per-run row numbers. "
                      "The ZIP, identifiers, logs, raw metrics, costs, and reports are not sent."),
            ("DPO", "Confirm retention, access, Article 30 records, and whether an Article 35 DPIA is needed."),
        ))
    add("Method and limits", "input", "Sources and coverage", ("Area", "Status", "Detail"), [
        ("ZIP", "imported" if uploaded else "not_collected", "Only recognized configuration entries are opened. Imported inventories are not guaranteed complete."),
        ("Live Azure inventory", "run" if live is not None else "not_collected", "Requires separate approval."),
        *list((item["area"], item["status"], item["detail"]) for item in (live or {}).get("coverage", [])),
        ("Security Posture review", review_status.get("posture", "Not called"), "Allowlisted Azure evidence only."),
        ("Compliance review", review_status.get("compliance", "Not called"), "Allowlisted Entra and Microsoft 365 evidence only."),
    ])
    add("Method and limits", "cross-check", "ARG ↔ ARM reconciliation", ("Resource", "Sources"), overlap,
        "Check coverage status. Differences may reflect indexing delays, child resources, incomplete pagination, or missing access.")
    if model_selected:
        add("Method and limits", "foundry-receipts", "Foundry request receipts",
            ("Agent", "Request start (UTC)", "Round trip (ms)", "HTTP status", "Patterns", "Model reported by Azure",
             "Azure request ID", "Responses API ID", "Input tokens", "Output tokens"),
            ((receipt.agent, receipt.requested_at, receipt.duration_ms, receipt.http_status,
              receipt.evidence_patterns, receipt.provider_model, receipt.request_id, receipt.response_id,
              receipt.input_tokens, receipt.output_tokens) for receipt in foundry_receipts),
            "One row per completed request with valid decisions. Metadata not returned by Azure is blank. The provider model "
            "can differ from the deployment name. Correlate timestamps or request IDs in approved Azure diagnostics when available.")
    audit = list((live or {}).get("audit", []))
    if review_status:
        audit += [f"Azure OpenAI Responses [{role}]: {review_status[role]}" for role in ("posture", "compliance")
                  if role in review_status]
    add("Method and limits", "audit", "Approved commands and operations (templates)", ("Operation",),
        ((line,) for line in audit))
    add("Cost", "totals", "Aggregate cost by subscription and group", ("Subscription", "Group", "Currency", "Source", "Amount"), costs,
        "Amounts from different sources or currencies are not added together. An empty table does not mean zero cost. Live Cost Management uses the previous calendar month.")
    system_cost = defaultdict(float)
    for _, group, currency, source, amount in costs:
        system = effective_assignments.get(group, (group, None))[0]
        system_cost[(system, currency, source)] += amount
    add("Systems", "costs", "Aggregate cost by system", ("System", "Currency", "Source", "Amount"),
        ((*scope, round(amount, 4)) for scope, amount in sorted(system_cost.items())))

    systems_by_resource = {r["id"]: effective_assignments.get(r["group"], (r["group"] or "Unassigned", None))[0]
                           for r in resources}
    scope_counts = defaultdict(Counter)
    source_counts = Counter((r["type"], r["source"]) for r in resources)
    for r in resources:
        if r["group"]:
            group_counts = scope_counts[r["group"]]
            group_counts["resources"] += 1
            group_counts["enabled"] += r["properties"].get("publicNetworkAccess") == "Enabled"
            group_counts["unknown"] += "publicNetworkAccess" not in r["properties"]
    for _, r, _, level, _ in active:
        if r["group"]:
            scope_counts[r["group"]][level] += 1
    add("Resource groups", "review-by-group", "Review queue by resource group",
        ("Group", "System", "Resources", "High", "Medium", "Low", "Public access enabled", "Exposure unknown"),
        ((group, effective_assignments[group][0], *(scope_counts[group][key] for key in
                    ("resources", "High", "Medium", "Low", "enabled", "unknown"))) for group in
         sorted(groups, key=lambda group: (-scope_counts[group]["High"], -scope_counts[group]["Medium"], group))),
        "Exposure unknown means this source supplied no public network access flag for that resource, not that it is reachable.")
    add("Resources", "source-breakdown", "Inventory by service type and source",
        ("Type", "Inventory source", "Distinct resources"),
        ((*scope, count) for scope, count in sorted(source_counts.items())),
        "A resource is counted under the source selected for its inventory record. See Method and limits for ARG ↔ ARM reconciliation.")
    scope_labels = {"sub": "Subscription", "rg": "Resource group"}
    add("Access (RBAC)", "assignment-profile", "Observed assignment profile",
        ("Scope kind", "Principal type", "Assignments"),
        ((*scope, count) for scope, count in sorted(Counter(
            (scope_labels.get(scope_id.split("-", 1)[0], "Resource or other scope"), principal_type)
            for scope_id, _, principal_type, _ in rbac).items())),
        "Counts are for observed role assignments. They are not counts of distinct people or effective access.")
    billing = defaultdict(list)
    for sub, group, currency, source, amount in costs:
        billing[sub, currency, source].append((group, amount))
    add("Cost", "billing-reconciliation", "Billing totals and unmatched allocations",
        ("Subscription", "Currency", "Source", "Total", "Mapped to observed groups", "Unmatched"),
        ((*scope, round(sum(amount for _, amount in entries), 4),
          round(sum(amount for group, amount in entries if group in effective_assignments), 4),
          round(sum(amount for group, amount in entries if group not in effective_assignments), 4))
         for scope, entries in sorted(billing.items())),
        "Unmatched charges may lack a group or refer to a group not in this snapshot. Negative adjustments are retained.")
    benchmark_states = Counter((name, version, status) for name, version, _, _, status, _, _ in checks)
    add("Security posture", "benchmark-status", "Benchmark evidence by status",
        ("Benchmark", "Version", "Status", "Requirements"),
        ((*scope, count) for scope, count in sorted(benchmark_states.items())),
        "Only imported requirements are counted. Manual review, needs Entra access, and not applicable stay separate from pass and fail.")

    domain_resources = defaultdict(list)
    for r in resources:
        area = TYPES.get(r["type"])
        if area in CONFIG_REVIEW:
            domain_resources[area].append(r)
        if area != "Network" and "publicNetworkAccess" in r["properties"]:
            domain_resources["Network"].append(r)
        if area != "Monitoring & logging" and ("diagnosticsConfigured" in r["properties"] or r["type"] in WEB):
            domain_resources["Monitoring & logging"].append(r)
        if area != "Resilience & DR" and (
            area in ("Apps", "Databases", "Storage", "Containers", "Servers", "Secrets & identities")
            or any(field in r["properties"] for field, _ in CONFIG_REVIEW["Resilience & DR"])
        ):
            domain_resources["Resilience & DR"].append(r)

    for area, fields in CONFIG_REVIEW.items():
        scope = domain_resources[area]
        add(area, "review-evidence", "Configuration evidence and gaps",
            ("Resource", "System", *[label for _, label in fields]),
            ((r["id"], systems_by_resource[r["id"]], *(r["properties"].get(field, "Not observed") for field, _ in fields))
             for r in scope),
            "Not observed means the field was not supplied or does not apply to this resource type. Verify applicability with the owner; do not interpret it as disabled or passed.")
        scope_ids = {r["id"] for r in scope}
        add(area, "linked-findings", "Findings linked to this scope",
            ("Severity", "Key", "Resource", "Control", "Proposed action"),
            ((level, rule.key, r["id"], rule.title, rule.action) for rule, r, _, level, _ in active if r["id"] in scope_ids),
            "This is a view of findings from the same snapshot, not a separate set of tests. See Findings for the full plan and evidence.")

    for area, plans in REVIEW_PLANS.items():
        add(area, "review-plan", "Review and closure checklist",
            ("Review task", "Suggested owners", "Evidence to obtain", "Decision or closure criteria"), plans,
            "These are recommended review steps, not actions that the assessment has taken.")

    for area, articles in SECTION_REFERENCES.items():
        add(area, "microsoft-guidance", "Microsoft Learn guidance",
            ("Article", "Microsoft Learn URL", "How to use it"), reference_rows(articles),
            "Public reference links open in a new tab. They are documentation, not evidence that a control passed.")

    return tables, summary, suggestions


def safe_dir(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400)


def output_root(path):
    absolute = Path(path).absolute()
    if os.name == "nt":
        from ctypes import windll

        if absolute.anchor.startswith("\\\\") or windll.kernel32.GetDriveTypeW(absolute.anchor) in (0, 1, 4):
            raise EvidenceError("Storage on network drives is not permitted.")
    if any(not safe_dir(directory) for directory in (absolute, *absolute.parents)):
        raise EvidenceError("The approved directory must exist and its path must not cross symlinks or junctions.")
    return absolute


def run(output_directory, blob=None, live=None, reviews=None, review_status=None, *,
        prepared_archive=None, review_mode="off", assess=None):
    output = output_root(output_directory)
    timestamp = datetime.now(timezone.utc)
    snapshot_id = timestamp.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(5)
    assignments = system_map()
    tables, summary, suggestions = dataset(blob, live, reviews or {}, review_status or {}, timestamp,
                                           pseudonym_key(), assignments, prepared_archive, review_mode, assess)
    report = assure_safe(render(tables, timestamp, summary))
    snap = assure_safe(json.dumps({"snapshot_id": snapshot_id, "utc": timestamp.isoformat(),
                                  "summary": summary, "tables": tables}, ensure_ascii=False))
    export = {Path("report.html"): report, Path("snapshot.json"): snap}
    for area, contents in tables.items():
        group = re.sub(r"[^a-z0-9]+", "-", area.lower()).strip("-")
        for slug, _, headers, records, _ in contents:
            export[Path("csv", group, f"{slug}.csv")] = csv_data(headers, records)
    export[Path("csv", "resource-groups", "system-map-candidates.csv")] = csv_data(
        ("resource_group_id", "system_id", "likely_personal_data"),
        ((group, *assignments[group][:1], {True: "yes", False: "no", None: "unknown"}[assignments[group][1]])
         if group in assignments else (group, system, "unknown")
         for group, system in sorted(suggestions.items())))
    staging = output / f".pending-{snapshot_id}"
    staging.mkdir(mode=0o700)
    try:
        for relative, content in export.items():
            path = staging / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8", newline="") as file:
                file.write(content)
        staging.rename(output / snapshot_id)
    except OSError:
        shutil.rmtree(staging)
        raise
    return snapshot_id, summary


def delete_snapshot(directory, snapshot_id):
    if not SNAPSHOT.fullmatch(snapshot_id):
        raise EvidenceError("Invalid snapshot ID.")
    snapshot = output_root(directory) / snapshot_id
    if not safe_dir(snapshot) or not (snapshot / "snapshot.json").is_file() or not (snapshot / "report.html").is_file():
        raise EvidenceError("The snapshot does not exist or is not a recognized report directory.")
    for item in snapshot.rglob("*"):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise EvidenceError("Deletion blocked: the snapshot contains symlinks or junctions.")
    shutil.rmtree(snapshot)


def main():
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(description="Transform configuration metadata into a local report.")
    parser.add_argument("--output", type=Path, required=True)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--zip", type=Path)
    operation.add_argument("--delete-snapshot")
    parser.add_argument("--confirm", action="store_true", help="Confirm the mandate and the selected operation.")
    args = parser.parse_args()
    if not args.confirm:
        parser.error("Read mandate.txt, review the categories in the README, and explicitly approve with --confirm.")
    try:
        if args.delete_snapshot:
            delete_snapshot(args.output, args.delete_snapshot)
            print("Snapshot deleted.")
        else:
            with args.zip.open("rb") as file:
                prepared_archive = read_archive(file)
            snapshot_id, _ = run(args.output, prepared_archive=prepared_archive)
            print(f"Local snapshot: {snapshot_id}")
    except EvidenceError as exc:
        parser.exit(1, f"{exc}\n")
    except OSError:
        parser.exit(1, "Local operation failed. Check the directory, input size, and permissions.\n")


if __name__ == "__main__":
    main()
