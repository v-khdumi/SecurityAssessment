"""Local, allowlisted evidence adapters. No archive member is extracted to disk."""

import csv
import hashlib
import hmac
import io
import json
import re
import stat
import zipfile
import zlib
from codecs import BOM_UTF16_BE, BOM_UTF16_LE, BOM_UTF32_BE, BOM_UTF32_LE, BOM_UTF8
from collections import Counter
from dataclasses import dataclass
from datetime import date

MIB = 1024 * 1024
MAX_ZIP = 512 * MIB
MAX_MEMBER = 32 * MIB
MAX_CONFIG_BYTES = 64 * MIB
MAX_MEMBERS = 4_000
MAX_ROWS = 60_000
MEMBERS = {
    "assessment-v1.json", "authorizationPolicy.json", "authenticationMethodsPolicy.json",
    "conditionalAccessPolicies.json", "prowler-summary.json",
    "prowler-cis-azure.json", "prowler-nis2-azure.json",
    "sharepointSettings.json", "teamsConfiguration.json",
}
SHAREPOINT_SHARING_CAPABILITIES = {
    "disabled", "externalUserSharingOnly", "externalUserAndGuestSharing", "existingExternalUserSharingOnly",
}
PROWLER_CATALOGS = {"prowler-cis-azure.json": "CIS", "prowler-nis2-azure.json": "NIS2"}
NATIVE_AZURE = "Azure ARM or Resource Graph inventory"
CONDITIONAL_ACCESS_STATES = ("enabled", "disabled", "enabledForReportingButNotEnforced")
SHAREPOINT_FLAGS = ("isLegacyAuthProtocolsEnabled", "isResharingByExternalUsersEnabled",
                    "isRequireAcceptingUserToMatchInvitedUserEnabled", "isUnmanagedSyncAppForTenantRestricted")
TEAM_GUEST_FLAGS = ("allowCreateUpdateChannels", "allowDeleteChannels")
NON_CONFIGURATION_MEMBERS = {
    "sha256sumserrors", "error", "errors", "exporterrors", "signins", "signinlogs", "auditlogs",
    "directoryaudits", "applicationlogs",
}
CHECKSUM_DISPOSITION = "Checksum manifest (not assessment evidence)"
GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.I)
SCOPE = re.compile(
    r"/(?:subscriptions/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
    r"|providers/Microsoft\.Management/managementGroups/[a-z0-9_.()-]+)"
    r"(?:/[^/\x00-\x1f\x7f\ud800-\udfff]+)*", re.I,
)

TYPES = {
    "microsoft.web/sites": "Apps", "microsoft.web/sites/slots": "Apps",
    "microsoft.web/serverfarms": "Apps", "microsoft.web/apimanagement": "Integration",
    "microsoft.web/connections": "Integration", "microsoft.logic/workflows": "Integration",
    "microsoft.servicebus/namespaces": "Integration", "microsoft.apimanagement/service": "Integration",
    "microsoft.datafactory/factories": "Integration",
    "microsoft.storage/storageaccounts": "Storage",
    "microsoft.keyvault/vaults": "Secrets & identities",
    "microsoft.managedidentity/userassignedidentities": "Secrets & identities",
    "microsoft.containerservice/managedclusters": "Containers",
    "microsoft.containerregistry/registries": "Containers",
    "microsoft.compute/virtualmachines": "Servers",
    "microsoft.compute/virtualmachinescalesets": "Servers",
    "microsoft.hybridcompute/machines": "Servers",
    "microsoft.automation/automationaccounts": "Servers",
    "microsoft.sql/servers": "Databases", "microsoft.sql/servers/databases": "Databases",
    "microsoft.sql/managedinstances": "Databases", "microsoft.azurearcdata/sqlserverinstances": "Databases",
    "microsoft.dbforpostgresql/flexibleservers": "Databases",
    "microsoft.dbformysql/flexibleservers": "Databases",
    "microsoft.documentdb/databaseaccounts": "Databases",
    "microsoft.recoveryservices/vaults": "Resilience & DR",
    "microsoft.dataprotection/backupvaults": "Resilience & DR",
    "microsoft.insights/components": "Monitoring & logging",
    "microsoft.operationalinsights/workspaces": "Monitoring & logging",
    "microsoft.insights/diagnosticsettings": "Monitoring & logging",
    "microsoft.insights/autoscalesettings": "Monitoring & logging",
}
NETWORK_TYPES = {"virtualnetworks", "networksecuritygroups", "publicipaddresses", "privateendpoints",
                 "firewalls", "loadbalancers", "applicationgateways", "trafficmanagerprofiles",
                 "networkinterfaces", "privatednszones", "routetables"}
TYPES.update({f"microsoft.network/{kind}": "Network" for kind in NETWORK_TYPES})
CURRENT_REGIONS = set("""
global eastus eastus2 westus westus2 westus3 centralus northcentralus southcentralus westcentralus
canadacentral canadaeast brazilsouth brazilsoutheast mexicocentral northeurope westeurope uksouth ukwest
francecentral francesouth germanywestcentral germanynorth swedencentral swedensouth norwayeast norwaywest
switzerlandnorth switzerlandwest polandcentral italynorth spaincentral austriaeast belgiumcentral
australiaeast australiasoutheast australiacentral australiacentral2 eastasia southeastasia koreacentral
koreasouth japaneast japanwest centralindia southindia westindia jioindiacentral jioindiawest
southafricanorth southafricawest uaenorth uaecentral qatarcentral israelcentral newzealandnorth
indonesiacentral malaysiawest chilecentral taiwannorth
""".split())
EEA_REGIONS = set("""
northeurope westeurope francecentral francesouth germanywestcentral germanynorth swedencentral swedensouth
norwayeast norwaywest polandcentral italynorth spaincentral austriaeast belgiumcentral
""".split())
NON_EEA_DATA_TYPES = {
    "microsoft.storage/storageaccounts", "microsoft.sql/servers/databases", "microsoft.sql/managedinstances",
    "microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers",
    "microsoft.documentdb/databaseaccounts", "microsoft.recoveryservices/vaults", "microsoft.dataprotection/backupvaults",
}
TLS = {"1.0", "1.1", "1.2", "1.3"}
BOOLEANS = (
    "httpsOnly", "allowBlobPublicAccess", "enablePurgeProtection", "secureTransferRequired",
    "remoteDebuggingEnabled", "anonymousHttpEnabled", "scmBasicAuthEnabled", "ftpBasicAuthEnabled",
    "corsAnyOrigin", "authenticationEnabled", "http20Enabled", "clientCertEnabled",
    "alwaysOn", "healthCheckConfigured", "autoHealEnabled", "zoneRedundant", "backupConfigured",
    "diagnosticsConfigured", "detailedErrorsEnabled", "publicTriggerEnabled", "managedIdentityEnabled",
    "keyVaultReferenceIdentityConfigured", "deleteProtection", "httpLoggingEnabled",
    "scmUsesMainRestrictions",
)
COUNTS = ("zoneCount", "privateEndpointCount", "customDomainCount", "workers", "replicaCount", "retentionDays",
          "scmRestrictionCount", "accessRestrictionCount", "secretLikeStickySettingCount",
          "hostNameStateCount", "stickySettingCount", "requests30d", "http4xx30d", "http5xx30d", "planWorkers")
ENUMS = {
    "minTlsVersion": TLS, "minScmTlsVersion": TLS,
    "publicNetworkAccess": {"Enabled", "Disabled", "SecuredByPerimeter"},
    "ftpsState": {"AllAllowed", "FtpsOnly", "Disabled"},
    "runtimeStatus": {"supported", "within_120_days", "out_of_support"},
    "deploymentType": {"pipeline", "service principal", "user (pseudonymised)"},
    "repositoryHost": {"GitHub", "Azure DevOps", "Other"},
    "mainDefaultAction": {"Allow", "Deny"}, "scmDefaultAction": {"Allow", "Deny"},
    "lastDeploymentStatus": {"succeeded", "failed", "in_progress", "cancelled"},
    "runtimeStack": {"dotnet", "node", "python", "php", "java", "ruby", "powershell", "custom"},
    "planSku": {"F1", "D1", "B1", "B2", "B3", "S1", "S2", "S3", "P1", "P2", "P3", "P1V2", "P2V2", "P3V2",
                "P0V3", "P1V3", "P2V3", "P3V3", "P1MV3", "P2MV3", "P3MV3", "P4MV3", "P5MV3",
                "P0V4", "P1V4", "P2V4", "P3V4", "I1V2", "I2V2", "I3V2", "I4V2", "I5V2", "I6V2",
                "Y1", "FC1", "EP1", "EP2", "EP3", "WS1", "WS2", "WS3"},
}
PRINCIPALS = {"User", "Group", "ServicePrincipal", "ForeignGroup", "Device", "Unknown"}
STATUSES = {"pass", "fail", "manual_review", "needs_entra_access", "not_applicable"}
BENCHMARK_EXCLUSIONS = {"not_run", "privacy", "data_plane", "entra_permissions", "not_supported", "scope"}
IGNORED_FIELD_LABELS = {
    "displayName": "displayName", "userPrincipalName": "userPrincipalName",
    "email": "email", "ipAddress": "ipAddress", "tags": "tags",
    "description": "description", "createdBy": "createdBy",
    "userDisplayName": "userDisplayName", "initiatedBy": "initiatedBy", "mail": "mail",
}


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class ArchiveImport:
    config: dict
    skipped: int
    decisions: list[tuple[int, str, str]]

    def coverage_issues(self):
        return Counter(reason for _, status, reason in self.decisions
                       if status != "Imported" and reason != CHECKSUM_DISPOSITION)

    def require_all_evidence_entries(self):
        issues = self.coverage_issues()
        if issues:
            details = "; ".join(f"{count} × {reason}" for reason, count in issues.most_common(3))
            if len(issues) > 3:
                details += "; additional reasons are available in the ZIP inspection"
            raise EvidenceError(
                f"Assessment not started: {sum(issues.values())} ZIP entries could not be fully imported. "
                f"{details}. Correct the export or run ZIP inspection for the full breakdown. No data was sent to Foundry."
            )


def parse_json(raw):
    try:
        return json.loads(raw, parse_constant=lambda _: None)
    except (ValueError, RecursionError) as exc:
        raise EvidenceError("A recognized configuration file contains invalid JSON.") from exc


def as_dict(value):
    return value if isinstance(value, dict) else {}


def rows(value):
    if not isinstance(value, list) or len(value) > MAX_ROWS:
        raise EvidenceError("A configuration collection is invalid or exceeds the row limit.")
    return (item for item in value if isinstance(item, dict))


def integer(value, cap=10**12):
    return value if type(value) is int and 0 <= value <= cap else None


def checked(value, choices, fallback=None):
    return value if isinstance(value, str) and value in choices else fallback


def is_guid(value):
    return isinstance(value, str) and GUID.fullmatch(value) is not None


def is_scope(value):
    return isinstance(value, str) and len(value) <= 2048 and SCOPE.fullmatch(value) is not None


def alias(key, kind, value):
    digest = hmac.new(key, f"{kind}:{value.lower()}".encode(), hashlib.sha256).hexdigest()[:20]
    return f"{kind}-{digest}"


def properties(raw):
    result = {k: raw[k] for k in BOOLEANS if type(raw.get(k)) is bool}
    result.update({k: raw[k] for k in COUNTS if integer(raw.get(k)) is not None})
    result.update({k: raw[k] for k in ENUMS if checked(raw.get(k), ENUMS[k]) is not None})
    if "secretLikeStickySettingCount" in result:
        result["secretLikeStickySettingPresent"] = result["secretLikeStickySettingCount"] > 0
    for field in ("lastDeploymentDate", "lastBackupDate", "runtimeEosDate"):
        value = raw.get(field)
        if isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            try:
                result[field] = date.fromisoformat(value).isoformat()
            except ValueError:
                continue
    runtime = raw.get("runtimeVersion")
    if isinstance(runtime, str) and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,4}){0,3}", runtime):
        result["runtimeVersion"] = runtime
    return result


def scope_parts(scope):
    bits = scope.split("/")
    sub = bits[2] if bits[1].lower() == "subscriptions" and is_guid(bits[2]) else None
    group = "/".join(bits[:5]) if sub and len(bits) >= 5 and bits[3].lower() == "resourcegroups" else None
    return sub, group


def system_candidate(key, group):
    subscription, _ = scope_parts(group)
    segments = [s for s in re.split(r"[-_. ]+", group.rsplit("/", 1)[-1].lower()) if s]
    qualifiers = {"rg", "resourcegroup", "prod", "production", "preprod", "test", "dev", "qa", "uat", "stage",
                  "staging", "sandbox", "nonprod"}
    while segments and segments[0] in qualifiers:
        segments.pop(0)
    while segments and segments[-1] in qualifiers:
        segments.pop()
    scope = f"{subscription}:{' '.join(segments)}" if segments else group
    digest = alias(key, "system", scope).split("-", 1)[1]
    return f"SYS-{int(digest, 16) % 10**15:015d}"


def project_inventory(inputs, key):
    resources, groups, subs, rbac = {}, set(), set(), set()
    suggestions = {}
    omitted = set()
    overlap = []

    def register_group(group):
        group_alias = alias(key, "rg", group)
        groups.add(group_alias)
        suggestions[group_alias] = system_candidate(key, group)
        return group_alias

    for data, live in inputs:
        if not isinstance(data, dict):
            raise EvidenceError("The inventory must be a JSON object.")
        for field in ("resources", "subscriptions", "groups", "rbac"):
            if field in data and not isinstance(data[field], list):
                raise EvidenceError("An inventory field does not match the schema.")
            if len(data.get(field, [])) > MAX_ROWS:
                raise EvidenceError("The inventory exceeds the row limit.")
        for sub in data.get("subscriptions", []):
            if is_guid(sub):
                subs.add(alias(key, "sub", sub))
        for group in data.get("groups", []):
            if is_scope(group) and scope_parts(group)[1] == group:
                register_group(group)
        arm_ids = {x.lower() for x in data.get("arm_ids", []) if is_scope(x)} if live else set()
        arg_ids = set()
        for item in rows(data.get("resources", [])):
            if not live:
                omitted.update(("Inventar", x) for x in IGNORED_FIELD_LABELS if x in item)
            rid = item.get("id")
            if not is_scope(rid):
                continue
            src = checked(item.get("source"), {"ARG", "ARM"}) if live else "ZIP"
            if src == "ARG":
                arg_ids.add(rid.lower())
            rid_alias = alias(key, "res", rid)
            sub, group = scope_parts(rid)
            sub_alias = alias(key, "sub", sub) if sub else None
            group_alias = register_group(group) if group else None
            if sub_alias:
                subs.add(sub_alias)
            kind = item.get("type")
            kind = kind.lower() if isinstance(kind, str) else None
            old = resources.get(rid_alias)
            if old and not live:
                # Contradictory duplicate input must not yield an invented finding.
                raise EvidenceError("The ZIP inventory contains duplicate resource IDs.")
            public_type = checked(kind, TYPES, "other")
            location = checked(item.get("location"), CURRENT_REGIONS)
            settings = properties(item)
            plan = item.get("planId")
            if (is_scope(plan) and re.fullmatch(r".+/providers/Microsoft\.Web/serverfarms/[^/]+", plan, re.I)):
                settings["planId"] = alias(key, "res", plan)
            if public_type in NON_EEA_DATA_TYPES and location and location != "global":
                settings["outsideEEARegion"] = location not in EEA_REGIONS
            resources[rid_alias] = {
                "id": rid_alias, "sub": sub_alias, "group": group_alias,
                "type": public_type, "location": location,
                "source": src or "ARM",
                "properties": settings,
                "evidence_sources": ({field: "Azure Monitor" for field in ("requests30d", "http4xx30d", "http5xx30d")} |
                                     {field: "ARM" for field in ("scmBasicAuthEnabled", "ftpBasicAuthEnabled",
                                       "stickySettingCount", "secretLikeStickySettingCount",
                                       "secretLikeStickySettingPresent", "diagnosticsConfigured")}) if live else {},
            }
        if live:
            overlap = [(alias(key, "res", x), "ARG + ARM" if x in arg_ids and x in arm_ids else
                        "ARG only" if x in arg_ids else "ARM only") for x in sorted(arg_ids | arm_ids)]
        for item in rows(data.get("rbac", [])):
            if not live:
                omitted.update(("RBAC", x) for x in IGNORED_FIELD_LABELS if x in item)
            scope, principal, role = (item.get(k) for k in ("scope", "principalId", "roleDefinitionId"))
            if not isinstance(role, str):
                continue
            role = role.rsplit("/", 1)[-1]
            if is_scope(scope) and is_guid(principal) and is_guid(role):
                kind = checked(item.get("principalType"), PRINCIPALS, "Unknown")
                sub, group = scope_parts(scope)
                scope_id = (alias(key, "sub", scope[15:]) if sub and len(scope.split("/")) == 3 else
                            alias(key, "rg", group) if group and group.lower() == scope.lower() else
                            alias(key, "res", scope))
                rbac.add((scope_id, principal.lower(), kind, role.lower()))
    return (sorted(resources.values(), key=lambda x: x["id"]), sorted(groups), sorted(subs), sorted(rbac),
            overlap, sorted(omitted), suggestions)


def configuration_document(document, conditional_access_hint=False):
    body = as_dict(document)
    if "error" in body:
        return None
    if "schema_version" in body and body.keys() & {"resources", "subscriptions", "groups", "rbac", "functions", "costs", "posture"}:
        if type(body["schema_version"]) is not int or body["schema_version"] != 1:
            raise EvidenceError("The normalized assessment inventory must declare schema_version: 1.")
        return "assessment-v1.json", body
    for name, framework in PROWLER_CATALOGS.items():
        if body.get("Framework") == framework and "Requirements" in body:
            return name, body
    if "version" in body and body.keys() & {"requirements", "checks"}:
        return "prowler-summary.json", body

    source = body.get("value", document)
    settings = as_dict(source)
    signatures = {
        "authorizationPolicy.json": {"allowInvitesFrom", "defaultUserRolePermissions"},
        "authenticationMethodsPolicy.json": {"authenticationMethodConfigurations"},
        "sharepointSettings.json": {"sharingCapability", "idleSessionSignOut", *SHAREPOINT_FLAGS},
    }
    matches = [name for name, fields in signatures.items() if settings.keys() & fields]
    if len(matches) > 1:
        raise EvidenceError("A JSON document matches multiple configuration formats. Export each configuration separately.")
    if matches:
        return matches[0], settings

    items = source if isinstance(source, list) else [source]
    if len(items) > MAX_ROWS:
        raise EvidenceError("A JSON collection exceeds the row limit.")
    if all(isinstance(item, dict) for item in items) and any(
        as_dict(item.get("guestSettings")).keys() & set(TEAM_GUEST_FLAGS) for item in items
    ):
        return "teamsConfiguration.json", {"value": items}
    context = body.get("@odata.context")
    conditional_access = conditional_access_hint or (
        isinstance(context, str) and context.split("#", 1)[-1].lower().removesuffix("/$entity")
        in {"identity/conditionalaccess/policies", "conditionalaccesspolicies", "collection(microsoft.graph.conditionalaccesspolicy)"}
    )
    if (items or conditional_access) and all(
        isinstance(item, dict) and item.get("state") in CONDITIONAL_ACCESS_STATES
        and (conditional_access or (is_guid(item.get("id")) and isinstance(item.get("conditions"), dict))
             or item.get("@odata.type") == "#microsoft.graph.conditionalAccessPolicy")
        for item in items
    ):
        if "@odata.nextLink" in body:
            return "conditionalAccessPolicies.json", {"value": items, "@odata.nextLink": None}
        return "conditionalAccessPolicies.json", {"value": items}
    return None


def text_encoding(prefix):
    for bom, encoding in ((BOM_UTF32_BE, "utf-32"), (BOM_UTF32_LE, "utf-32"),
                          (BOM_UTF16_BE, "utf-16"), (BOM_UTF16_LE, "utf-16"), (BOM_UTF8, "utf-8-sig")):
        if prefix.startswith(bom):
            return encoding
    return "utf-8"


def azure_resource_row(record):
    row = as_dict(record)
    rid, kind = row.get("id"), row.get("type")
    if not is_scope(rid) or not isinstance(kind, str):
        return None
    kind = kind.lower()
    sub, group = scope_parts(rid)
    if kind == "microsoft.resources/subscriptions" and sub and rid.lower() == f"/subscriptions/{sub.lower()}":
        return "subscriptions", sub.lower()
    if kind in {"microsoft.resources/subscriptions/resourcegroups", "microsoft.resources/resourcegroups"} and group == rid:
        return "groups", group
    if "/providers/" not in rid.lower():
        return None
    parts = re.split(r"/providers/", rid, flags=re.I)[-1].split("/")
    if len(parts) < 3 or len(parts) % 2 == 0 or "/".join([parts[0], *parts[1::2]]).lower() != kind:
        return None
    settings = as_dict(row.get("properties"))
    if kind == "microsoft.authorization/roleassignments":
        scope, principal, role_id = (settings.get(field, row.get(field))
                                     for field in ("scope", "principalId", "roleDefinitionId"))
        if not (is_scope(scope) and is_guid(principal) and isinstance(role_id, str)
                and is_guid(role_id.rsplit("/", 1)[-1])):
            return None
        return "rbac", {"scope": scope, "principalId": principal, "roleDefinitionId": role_id.rsplit("/", 1)[-1],
                        "principalType": checked(settings.get("principalType", row.get("principalType")), PRINCIPALS, "Unknown")}
    projected = properties(row)
    projected.update({field: settings[field] for field in ("publicNetworkAccess",) if field in settings})
    if kind in {"microsoft.web/sites", "microsoft.web/sites/slots"}:
        site = as_dict(settings.get("siteConfig"))
        for field in ("httpsOnly", "clientCertEnabled"):
            if field in settings:
                projected[field] = settings[field]
        for field, source in (
            ("minTlsVersion", "minTlsVersion"), ("minScmTlsVersion", "scmMinTlsVersion"),
            ("remoteDebuggingEnabled", "remoteDebuggingEnabled"), ("ftpsState", "ftpsState"),
        ):
            if source in site:
                projected[field] = site[source]
        origins = as_dict(site.get("cors")).get("allowedOrigins")
        if isinstance(origins, list) and all(isinstance(origin, str) for origin in origins):
            projected["corsAnyOrigin"] = "*" in origins
    elif kind == "microsoft.storage/storageaccounts":
        for field, source in (("allowBlobPublicAccess", "allowBlobPublicAccess"),
                              ("secureTransferRequired", "supportsHttpsTrafficOnly"),
                              ("minTlsVersion", "minimumTlsVersion")):
            if source in settings:
                projected[field] = settings[source]
        tls = projected.get("minTlsVersion")
        if isinstance(tls, str) and re.fullmatch(r"TLS1_[0-3]", tls):
            projected["minTlsVersion"] = tls[3:].replace("_", ".")
    elif kind == "microsoft.keyvault/vaults" and "enablePurgeProtection" in settings:
        projected["enablePurgeProtection"] = settings["enablePurgeProtection"]
    resource = {"id": rid, "type": kind, **properties(projected)}
    if location := checked(row.get("location"), CURRENT_REGIONS):
        resource["location"] = location
    return "resources", resource


def azure_export(document):
    body = as_dict(document)
    source = body.get("data", body.get("value", body.get("resources", document)))
    raw_table = as_dict(source)
    if isinstance(raw_table.get("columns"), list) and isinstance(raw_table.get("rows"), list):
        columns = [as_dict(column).get("name") for column in raw_table["columns"]]
        if not all(isinstance(name, str) for name in columns) or not {"id", "type"}.issubset(columns):
            return None
        if len(columns) != len(set(columns)) or len(raw_table["rows"]) > MAX_ROWS:
            raise EvidenceError("The Azure Resource Graph table has duplicate columns or exceeds the row limit.")
        source = (dict(zip(columns, values)) if isinstance(values, list) and len(values) == len(columns)
                  else None for values in raw_table["rows"])
    elif isinstance(source, list):
        if len(source) > MAX_ROWS:
            raise EvidenceError("The Azure export exceeds the row limit.")
    else:
        source = [source]
    inventory = {field: [] for field in ("resources", "subscriptions", "groups", "rbac")}
    unrecognized = []
    for row in source:
        match = azure_resource_row(row)
        if match is None:
            unrecognized.append(row)
        else:
            field, value = match
            inventory[field].append(value)
    if not any(inventory.values()):
        return None
    truncated = (bool(body.get("nextLink") or body.get("$skipToken") or body.get("skipToken"))
                 or str(body.get("resultTruncated")).lower() == "true"
                 or (type(body.get("count")) is int and type(body.get("totalRecords")) is int
                     and body["count"] < body["totalRecords"]))
    return inventory, unrecognized, truncated


def azure_csv_header(first_line):
    for delimiter in (",", ";", "\t"):
        try:
            fields = next(csv.reader(io.StringIO(first_line), delimiter=delimiter, strict=True))
        except csv.Error:
            continue
        except StopIteration:
            return None
        columns = [name.strip().lower() for name in fields]
        if {"id", "type"}.issubset(columns):
            if len(columns) != len(set(columns)):
                raise EvidenceError("The Azure CSV has duplicate column names.")
            return delimiter, columns
    return None


def azure_csv_document(raw, header, encoding):
    delimiter, columns = header
    names = {field.lower(): field for field in ("id", "type", "location", *BOOLEANS, *ENUMS, *COUNTS)}
    data = []
    try:
        reader = csv.reader(io.StringIO(raw.decode(encoding)), delimiter=delimiter, strict=True)
        next(reader)
        for values in reader:
            if not values:
                continue
            if len(data) >= MAX_ROWS:
                raise EvidenceError("The Azure CSV exceeds the row limit.")
            if len(values) != len(columns):
                raise EvidenceError("An Azure CSV row does not match the header column count.")
            row = {}
            for name, value in zip(columns, values):
                field = names.get(name)
                if field is None or not value.strip():
                    continue
                value = value.strip()
                if field in BOOLEANS and value.lower() in {"true", "false"}:
                    row[field] = value.lower() == "true"
                elif field in COUNTS and re.fullmatch(r"[0-9]{1,13}", value):
                    row[field] = int(value)
                else:
                    row[field] = value
            data.append(row)
    except (UnicodeError, csv.Error) as exc:
        raise EvidenceError("The Azure CSV has invalid text encoding or quoting.") from exc
    return {"data": data}


def configuration_records(document, conditional_access_hint=False, *, allow_batch=True):
    body = as_dict(document)
    if "error" in body:
        yield None, "API error response"
        return
    match = configuration_document(document, conditional_access_hint)
    if match is not None:
        name, configuration = match
        if name == "teamsConfiguration.json":
            teams = configuration["value"]
            supported = [team for team in teams if as_dict(team.get("guestSettings")).keys() & set(TEAM_GUEST_FLAGS)]
            if len(supported) != len(teams):
                yield None, "Teams record has no supported guest configuration"
                match = name, {"value": supported}
        if "@odata.nextLink" in body:
            yield None, "Graph export indicates incomplete pagination"
        yield match, None
        return
    native = azure_export(document)
    if native is not None:
        inventory, unrecognized, truncated = native
        yield (NATIVE_AZURE, inventory), None
        for row in unrecognized:
            match = configuration_document(row)
            yield match, None if match is not None else "Azure export has rows outside the supported metadata format"
        if truncated:
            yield None, "Azure export indicates incomplete pagination"
        return
    batch = body.get("responses")
    if allow_batch and isinstance(batch, list) and all(type(as_dict(row).get("status")) is int for row in batch):
        if len(batch) > MAX_ROWS:
            raise EvidenceError("The Graph batch exceeds the row limit.")
        for row in batch:
            if not 200 <= row["status"] < 300 or "error" in as_dict(row.get("body")):
                yield None, "API error response"
                continue
            for matched, reason in configuration_records(row.get("body"), allow_batch=False):
                if reason in {"JSON content has no supported configuration", "Collection item has no supported configuration"}:
                    reason = "Batch body has no supported configuration"
                yield matched, reason
        if not batch:
            yield None, "Empty Graph batch"
        return
    records = body.get("value", document)
    if isinstance(records, list) and records:
        if "@odata.nextLink" in body:
            yield None, "Graph export indicates incomplete pagination"
        for record in records:
            match = configuration_document(record, conditional_access_hint)
            yield match, None if match is not None else "Collection item has no supported configuration"
        return
    yield None, "JSON content has no supported configuration"


def json_documents(raw, encoding):
    try:
        document = parse_json(raw)
    except EvidenceError:
        try:
            lines = io.StringIO(raw.decode(encoding))
        except UnicodeError:
            yield None, "Invalid JSON"
            return
        for index, line in enumerate(lines, start=1):
            if index > MAX_ROWS:
                raise EvidenceError("The newline-delimited JSON exceeds the line limit.")
            if not line.strip():
                continue
            try:
                document = parse_json(line)
            except EvidenceError:
                yield None, "Invalid JSON"
                continue
            yield document, None
    else:
        yield document, None


def add_configuration(config, name, body):
    if name not in config:
        config[name] = body
        return
    if name == NATIVE_AZURE:
        for field, entries in body.items():
            saved = config[name][field]
            if len(saved) + len(entries) > MAX_ROWS:
                raise EvidenceError("The combined Azure exports exceed the row limit.")
            saved.extend(entries)
        return
    if name not in {"teamsConfiguration.json", "conditionalAccessPolicies.json"}:
        raise EvidenceError(f"The ZIP contains more than one {name} configuration. Include only one copy, even across folders.")
    entries = config[name]["value"]
    if len(entries) + len(body["value"]) > MAX_ROWS:
        raise EvidenceError(f"The combined {name} configurations exceed the row limit.")
    entries.extend(body["value"])
    if "@odata.nextLink" in body:
        config[name]["@odata.nextLink"] = None


def zip_inventory(config):
    normalized = config.get("assessment-v1.json")
    native = config.get(NATIVE_AZURE)
    if native is None:
        return normalized
    result = dict(normalized or {})
    for field in ("groups", "subscriptions", "rbac"):
        items = result.get(field, [])
        if not isinstance(items, list):
            raise EvidenceError("An inventory field does not match the schema.")
        result[field] = items + native[field]
    existing = {}
    items = result.get("resources", [])
    for item in rows(items):
        rid = item.get("id")
        if is_scope(rid):
            if rid.lower() in existing:
                raise EvidenceError("The ZIP inventory contains duplicate resource IDs.")
            existing[rid.lower()] = dict(item)
    for item in native["resources"]:
        resource = existing.setdefault(item["id"].lower(), {})
        for field, value in item.items():
            previous = resource.get(field)
            if isinstance(previous, str) and isinstance(value, str) and field in {"id", "type"}:
                previous = previous.lower()
                value = value.lower()
            if previous is not None and (type(previous) is not type(value) or previous != value):
                raise EvidenceError("The Azure inventory has conflicting values for one resource. Export a consistent snapshot.")
            resource[field] = value
    result["resources"] = list(existing.values())
    return result


def read_archive(source, *, recover_members=False):
    file = io.BytesIO(source) if isinstance(source, bytes) else source
    size = file.seek(0, io.SEEK_END)
    if not 0 < size <= MAX_ZIP:
        raise EvidenceError(f"Upload a ZIP no larger than {MAX_ZIP // MIB} MiB. For larger exports, split by assessment scope.")
    file.seek(0)
    try:
        with zipfile.ZipFile(file) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise EvidenceError(f"The ZIP exceeds {MAX_MEMBERS:,} entries. Repackage only the required configuration files.")
            config = {}
            parsed_bytes = 0
            decisions = []
            skipped = 0
            for index, entry in enumerate(infos, start=1):
                parts = entry.filename.replace("\\", "/").split("/")
                filename = parts[-1]
                if not filename:
                    continue
                member_keys = [re.sub(r"[-_ .]", "", re.sub(r"\.(?:json|ndjson|jsonl)$", "", part.lower()))
                               for part in parts]
                if any(name in NON_CONFIGURATION_MEMBERS for name in member_keys):
                    skipped += 1
                    decisions.append((index, "Skipped", "Excluded log or export error file"))
                    continue
                if member_keys[-1] == "sha256sums":
                    skipped += 1
                    decisions.append((index, "Skipped", CHECKSUM_DISPOSITION))
                    continue
                if "" in parts or ".." in parts or any(":" in part for part in parts) or "\x00" in entry.orig_filename:
                    raise EvidenceError("The ZIP contains an unsafe path for a file.")
                mode = entry.external_attr >> 16
                if entry.flag_bits & 1 or stat.S_ISLNK(mode):
                    raise EvidenceError("A ZIP entry is encrypted or unsafe to expand.")
                if entry.file_size > MAX_MEMBER:
                    skipped += 1
                    decisions.append((index, "Skipped", f"File exceeds {MAX_MEMBER // MIB} MiB uncompressed"))
                    continue
                if entry.file_size > max(1, entry.compress_size) * 200:
                    skipped += 1
                    decisions.append((index, "Skipped", "File exceeds the safe expansion ratio"))
                    continue
                with archive.open(entry) as stream:
                    prefix = stream.read(4096)
                    encoding = text_encoding(prefix)
                    text = prefix.decode(encoding, errors="replace")
                    is_json = text.lstrip().startswith(("{", "["))
                    try:
                        csv_header = None if is_json else azure_csv_header(text.partition("\n")[0])
                    except EvidenceError as exc:
                        if not recover_members:
                            raise
                        skipped += 1
                        decisions.append((index, "Skipped", str(exc)))
                        continue
                    if not is_json and csv_header is None:
                        reason = "Not recognized as structured JSON or Azure inventory CSV"
                        if filename in MEMBERS:
                            if not recover_members:
                                raise EvidenceError("A recognized configuration file contains invalid JSON.")
                            reason = "Invalid JSON"
                        skipped += 1
                        decisions.append((index, "Skipped", reason))
                        continue
                    parsed_bytes += entry.file_size
                    if parsed_bytes > MAX_CONFIG_BYTES:
                        raise EvidenceError(f"Structured files exceed {MAX_CONFIG_BYTES // MIB} MiB in total uncompressed. Split by assessment scope.")
                    raw = prefix + stream.read(MAX_MEMBER + 1 - len(prefix))
                imported = set()
                omitted = set()
                try:
                    documents = ((azure_csv_document(raw, csv_header, encoding), None),) if csv_header else json_documents(raw, encoding)
                except EvidenceError as exc:
                    if not recover_members:
                        raise
                    skipped += 1
                    decisions.append((index, "Skipped", str(exc)))
                    continue
                for document, reason in documents:
                    if reason is not None:
                        omitted.add(reason)
                        continue
                    records = configuration_records(document, filename == "conditionalAccessPolicies.json")
                    while True:
                        try:
                            match, reason = next(records)
                        except StopIteration:
                            break
                        except EvidenceError as exc:
                            if not recover_members:
                                raise
                            omitted.add(str(exc))
                            break
                        if match is not None:
                            name, body = match
                            add_configuration(config, name, body)
                            imported.add(name)
                        else:
                            omitted.add(reason)
                if not imported:
                    if not recover_members and filename in MEMBERS and omitted == {"Invalid JSON"}:
                        raise EvidenceError("A recognized configuration file contains invalid JSON.")
                    skipped += 1
                    decisions.append((index, "Skipped", "; ".join(sorted(omitted or {"No supported records"}))))
                    continue
                details = ", ".join(sorted(imported))
                if omitted:
                    details += "; omitted: " + "; ".join(sorted(omitted))
                decisions.append((index, "Partial" if omitted else "Imported", details))
            return ArchiveImport(config, skipped, decisions)
    except (zipfile.BadZipFile, NotImplementedError, OSError, RuntimeError, EOFError, zlib.error) as exc:
        raise EvidenceError("The ZIP archive could not be opened safely.") from exc


def conditional_access_config(config, key):
    source = "conditionalAccessPolicies.json"
    if source not in config:
        return []
    result = []
    seen = set()
    known_grants = {"block", "mfa", "compliantDevice", "domainJoinedDevice", "approvedApplication",
                    "compliantApplication", "passwordChange", "riskRemediation"}
    for index, policy in enumerate(rows(config[source]["value"]), start=1):
        state = checked(policy.get("state"), CONDITIONAL_ACCESS_STATES)
        if state is None:
            continue
        reference = policy["id"] if is_guid(policy.get("id")) else f"export-row-{index}"
        policy_id = alias(key, "ca", reference)
        if policy_id in seen:
            raise EvidenceError("Conditional Access configuration contains a duplicate policy.")
        seen.add(policy_id)
        props = {"policyState": state, "reportOnlyPresent": state == "enabledForReportingButNotEnforced"}
        conditions = as_dict(policy.get("conditions"))
        users = as_dict(conditions.get("users"))
        apps = as_dict(conditions.get("applications"))
        for field, targets, include in (("userScope", users, "includeUsers"), ("applicationScope", apps, "includeApplications")):
            listed = targets.get(include)
            if isinstance(listed, list) and listed:
                props[field] = "all" if "All" in listed else "selected"
        exclusion_fields = ((users, ("excludeUsers", "excludeGroups", "excludeRoles", "excludeGuestsOrExternalUsers")),
                            (apps, ("excludeApplications",)))
        if any(isinstance(targets.get(field), (list, dict)) and targets[field]
               for targets, fields in exclusion_fields for field in fields):
            props["exclusionsObserved"] = True
        grants = as_dict(policy.get("grantControls"))
        operator = checked(grants.get("operator"), {"AND", "OR"})
        if operator:
            props["grantOperator"] = operator
        controls = grants.get("builtInControls")
        known = {value for value in controls if checked(value, known_grants)} if isinstance(controls, list) else set()
        strength = bool(as_dict(grants.get("authenticationStrength")))
        if "block" in known:
            props["authenticationGrant"] = "block"
        elif "mfa" in known or strength:
            alternative = bool(known - {"mfa"}) or any(
                isinstance(grants.get(field), list) and grants[field] for field in ("termsOfUse", "customAuthenticationFactors")
            )
            if operator == "OR" and alternative:
                props["authenticationGrant"] = "alternative"
            elif operator == "AND" or (operator == "OR" and not alternative and isinstance(controls, list)
                                       and all(checked(value, known_grants) for value in controls)):
                props["authenticationGrant"] = "required"
            else:
                props["authenticationGrant"] = "configured"
        if state == "enabled" and props.get("authenticationGrant") in {"alternative", "required", "block"}:
            props["enabledAlternativeAuthentication"] = props["authenticationGrant"] == "alternative"
        result.append({"id": policy_id, "type": "microsoft.graph/conditionalaccess", "group": None,
                       "properties": props, "source": "ZIP — Conditional Access", "evidence_sources": {}})
    return result


def graph_config(config):
    result, omitted = [], set()
    graph_members = {"authorizationPolicy.json", "authenticationMethodsPolicy.json", "conditionalAccessPolicies.json"}
    for name in sorted(graph_members & config.keys()):
        body = as_dict(config[name])
        omitted.update((name, x) for x in IGNORED_FIELD_LABELS if x in body)
        if name == "authorizationPolicy.json":
            defaults = as_dict(body.get("defaultUserRolePermissions"))
            result += [(name, field, body[field]) for field in ("allowInvitesFrom",)
                       if checked(body.get(field), {"none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"})]
            result += [(name, field, defaults[field]) for field in ("allowedToCreateApps", "allowedToCreateSecurityGroups",
                       "allowedToReadOtherUsers") if type(defaults.get(field)) is bool]
        elif name == "authenticationMethodsPolicy.json":
            for method in rows(body.get("authenticationMethodConfigurations", [])):
                kind = checked(method.get("id"), {"Fido2", "MicrosoftAuthenticator", "TemporaryAccessPass",
                               "Email", "Sms", "Voice", "SoftwareOath", "X509Certificate", "HardwareOath"})
                status = checked(method.get("state"), {"enabled", "disabled"})
                if kind and status:
                    result.append((name, kind, status))
        else:
            counts = dict.fromkeys(CONDITIONAL_ACCESS_STATES, 0)
            if "value" not in body:
                continue
            observed = 0
            for policy in rows(body["value"]):
                status = checked(policy.get("state"), counts)
                if status:
                    counts[status] += 1
                    observed += 1
                omitted.update((name, x) for x in IGNORED_FIELD_LABELS if x in policy)
            if body["value"] and not observed:
                continue
            scope = "Supplied page (the export indicates more pages)" if "@odata.nextLink" in body else "Supplied page"
            result += [(name, f"{status} · {scope}", count) for status, count in counts.items()]
    return result, sorted(omitted)


def m365_config(config, key):
    scopes = []
    if "sharepointSettings.json" in config:
        body = config["sharepointSettings.json"]
        settings = as_dict(body["value"]) if "value" in body else body
        props = {field: settings[field] for field in SHAREPOINT_FLAGS if type(settings.get(field)) is bool}
        sharing = checked(settings.get("sharingCapability"), SHAREPOINT_SHARING_CAPABILITIES)
        if sharing is not None:
            props["sharingCapability"] = sharing
        signout = as_dict(settings.get("idleSessionSignOut")).get("isEnabled")
        if type(signout) is bool:
            props["idleSessionSignOutEnabled"] = signout
        if props:
            scopes.append({"id": "SharePoint and OneDrive tenant settings", "type": "microsoft.graph/sharepoint",
                           "group": None, "properties": props, "source": "ZIP — sharepointSettings.json",
                           "evidence_sources": {}})
    if "teamsConfiguration.json" in config:
        body = config["teamsConfiguration.json"]
        items = rows(body["value"]) if "value" in body else [body]
        seen = set()
        for team in items:
            guests = as_dict(team.get("guestSettings"))
            props = {f"guestSettings.{field}": guests[field]
                     for field in TEAM_GUEST_FLAGS if type(guests.get(field)) is bool}
            if not props:
                continue
            if not is_guid(team.get("id")):
                raise EvidenceError("Teams configuration requires the Graph team ID for each supplied team.")
            reference = alias(key, "team", team["id"])
            if reference in seen:
                raise EvidenceError("Teams configuration contains a duplicate team.")
            seen.add(reference)
            scopes.append({"id": reference, "type": "microsoft.graph/team", "group": None, "properties": props,
                           "source": "ZIP — teamsConfiguration.json", "evidence_sources": {}})
    return scopes


def prowler_config(document, catalogs=None):
    body = as_dict(document)
    version = body.get("version")
    if document is not None and (not isinstance(version, str) or not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){1,3}", version, re.ASCII)):
        raise EvidenceError("The Prowler summary must declare the exact Prowler version.")
    catalog, results = {}, {}

    def requirement(item):
        benchmark = checked(item.get("benchmark"), {"CIS-Azure", "NIS2-2024-2690"})
        req, section = item.get("requirement"), item.get("section")
        pattern = r"\d{1,3}(?:\.(?:\d{1,3}|[a-z])){0,7}"
        if not benchmark or not all(isinstance(s, str) and re.fullmatch(pattern, s, re.ASCII) for s in (req, section)):
            return None
        benchmark_version = item.get("benchmarkVersion")
        if benchmark_version is None:
            benchmark_version = "2024/2690" if benchmark == "NIS2-2024-2690" else "—"
        elif not isinstance(benchmark_version, str) or not re.fullmatch(r"[0-9]{1,4}(?:[./][0-9]{1,4}){0,3}", benchmark_version):
            return None
        point = checked(item.get("point"), set("abcdefghij")) if benchmark != "CIS-Azure" else None
        return (benchmark, benchmark_version, section, req), point or "—"

    for name, raw in (catalogs or {}).items():
        framework = PROWLER_CATALOGS[name]
        if raw.get("Framework") != framework or raw.get("Provider") != "Azure" or "Requirements" not in raw:
            raise EvidenceError("The Prowler catalog does not match the expected Azure benchmark.")
        kind = "CIS-Azure" if framework == "CIS" else "NIS2-2024-2690"
        benchmark_version = "2024/2690" if framework == "NIS2" else raw.get("Version")
        for item in rows(raw["Requirements"]):
            identifier = item.get("Id")
            if not isinstance(identifier, str) or len(identifier) > 40:
                continue
            point = None
            if framework == "NIS2":
                attributes = item.get("Attributes")
                sections = [a.get("Section") for a in attributes if isinstance(a, dict)] if isinstance(attributes, list) else []
                points = {match.lower() for section in sections if isinstance(section, str)
                          for match in re.findall(r"ARTICLE\s+21\(2\),\s*POINT\s+\(([a-j])\)", section, re.I | re.ASCII)}
                point = next(iter(points)) if len(points) == 1 else None
            entry = requirement({"benchmark": kind, "benchmarkVersion": benchmark_version, "requirement": identifier,
                                 "section": identifier.split(".", 1)[0], "point": point})
            if entry:
                key, point = entry
                catalog[key] = ("manual_review", point, "not_run")

    for item in rows(body.get("requirements", [])):
        if entry := requirement(item):
            key, point = entry
            if point == "—" and key in catalog:
                point = catalog[key][1]
            exclusion = checked(item.get("exclusion"), BENCHMARK_EXCLUSIONS, "not_run")
            status = "needs_entra_access" if exclusion == "entra_permissions" else "manual_review"
            catalog[key] = (status, point, exclusion)
    for item in rows(body.get("checks", [])):
        entry = requirement(item)
        status = checked(item.get("status"), STATUSES)
        if not entry or not status:
            continue
        key, point = entry
        exclusion = checked(item.get("exclusion"), BENCHMARK_EXCLUSIONS, "—")
        if key in catalog and (point == "—" or exclusion == "—" and status not in {"pass", "fail"}):
            _, catalog_point, catalog_exclusion = catalog[key]
            point = catalog_point if point == "—" else point
            if exclusion == "—" and status not in {"pass", "fail"}:
                exclusion = catalog_exclusion
        if status in {"pass", "fail"} and exclusion != "—":
            raise EvidenceError("An evaluated Prowler result cannot have an exclusion reason.")
        record = (status, point, exclusion)
        if key in results and results[key] != record:
            raise EvidenceError("The Prowler summary contains conflicting results for the same requirement.")
        results[key] = record
    return version, [(*key, *metadata) for key, metadata in sorted((catalog | results).items())]


def project_costs(inputs, key):
    """Keep billing aggregates only; never retain the billing group name."""
    projected = {}
    for data, live in inputs:
        for item in rows(data.get("costs", [])):
            sub, group, amount, unit = (item.get(k) for k in ("subscriptionId", "group", "amount", "currency"))
            if not (is_guid(sub) and type(amount) in (float, int) and abs(amount) <= 10**14
                    and isinstance(unit, str) and re.fullmatch(r"[A-Z]{3}", unit)):
                continue
            if group is not None and not (is_scope(group) and scope_parts(group)[1] == group
                                          and scope_parts(group)[0].lower() == sub.lower()):
                continue
            source = "Cost Management" if live else "ZIP"
            row_key = alias(key, "sub", sub), alias(key, "rg", group) if group else "Unallocated", unit, source
            projected[row_key] = projected.get(row_key, 0) + amount
    return [(*dimensions, round(amount, 4)) for dimensions, amount in sorted(projected.items())]


POSTURE_LABELS = {
    "secure_score_percent": "Defender secure score (%)",
    "defender_free": "Defender · Free plan",
    "defender_standard": "Defender · Standard plan",
    "defender_unhealthy": "Defender · Unhealthy assessments",
    "policy_assignments": "Azure Policy · Visible assignments",
    **{f"defender_alert_{severity.lower()}": f"Defender · Active {severity} alerts"
       for severity in ("Low", "Medium", "High", "Informational")},
    **{f"policy_{state.lower()}": f"Azure Policy · {state}" for state in
       ("Compliant", "NonCompliant", "Conflict", "Exempt", "Unknown", "NotStarted", "Protected")},
}


def project_posture(inputs, key):
    projected = set()
    for document, live in inputs:
        for item in rows(document.get("posture", [])):
            sub, metric, val = (item.get(k) for k in ("subscriptionId", "metric", "value"))
            if not is_guid(sub) or not checked(metric, POSTURE_LABELS):
                continue
            if metric == "secure_score_percent":
                if type(val) not in (int, float) or not 0 <= val <= 100:
                    continue
            elif integer(val) is None:
                continue
            projected.add((alias(key, "sub", sub), POSTURE_LABELS[metric], "ARG" if live else "ZIP", round(val, 3)))
    return sorted(projected)


FUNCTION_TRIGGERS = {"httpTrigger", "timerTrigger", "queueTrigger", "blobTrigger", "serviceBusTrigger",
                     "eventGridTrigger", "eventHubTrigger", "cosmosDBTrigger", "orchestrationTrigger",
                     "activityTrigger", "entityTrigger", "kafkaTrigger", "signalRTrigger", "other"}
FUNCTION_PARENT = re.compile(r".+/providers/Microsoft\.Web/sites/[^/]+(?:/slots/[^/]+)?", re.I)


def project_functions(inputs, key):
    observed = {}
    for data, live in inputs:
        if live:
            continue
        for item in rows(data.get("functions", [])):
            rid = item.get("id")
            if not is_scope(rid):
                continue
            parent, route, name = rid.rsplit("/", 2)
            if route.lower() != "functions" or not name or not FUNCTION_PARENT.fullmatch(parent):
                continue
            function_id = alias(key, "fn", rid)
            trigger = checked(item.get("trigger"), FUNCTION_TRIGGERS, "other")
            auth = checked(item.get("authLevel"), {"anonymous", "function", "admin"})
            disabled = item.get("disabled") if type(item.get("disabled")) is bool else None
            if function_id in observed:
                raise EvidenceError("The inventory contains duplicate function IDs.")
            observed[function_id] = (alias(key, "res", parent), function_id, trigger, auth, disabled)
    return sorted(observed.values())
