"""Reviewed public Microsoft Learn references; never construct URLs from evidence."""

BASE = "https://learn.microsoft.com/en-us/"
ARTICLES = {
    "app-config": ("Configure an App Service app", "azure/app-service/configure-common",
                   "Check HTTPS-only, remote debugging, and site configuration on the affected app or slot."),
    "app-tls": ("TLS settings in Azure App Service", "azure/app-service/overview-tls",
                "Check minimum TLS for the main site and the SCM endpoint separately."),
    "app-basic": ("Disable Basic Auth for App Service deployments", "azure/app-service/configure-basic-auth-disable",
                  "Identify dependent publishing paths before disabling the SCM and FTP policies."),
    "app-ingress": ("Set up App Service access restrictions", "azure/app-service/app-service-ip-restrictions",
                    "Review main-site and SCM restrictions, inherited rules, and the unmatched rule action separately."),
    "function-http": ("Azure Functions HTTP trigger authorization", "azure/azure-functions/functions-bindings-http-webhook-trigger",
                      "Check the trigger's authorization level; a function key is different from identity-based caller authentication."),
    "app-auth": ("App Service and Azure Functions authentication", "azure/app-service/overview-authentication-authorization",
                 "Check how authentication is enforced and what the platform does with unauthenticated requests."),
    "app-ftp": ("App Service FTP/S deployment settings", "azure/app-service/deploy-ftp",
                "Check whether FTP is needed and compare the FTP and FTPS-only settings."),
    "app-cors": ("App Service CORS configuration", "azure/app-service/app-service-web-tutorial-rest-api",
                 "Check the permitted browser origins; treat CORS as separate from API authorization."),
    "app-patch": ("App Service OS and runtime patching", "azure/app-service/overview-patch-os-runtime",
                  "Separate platform patching from runtime-version and application dependency responsibilities."),
    "app-secrets": ("Use Key Vault references in App Service", "azure/app-service/app-service-key-vault-references",
                    "Review reference syntax, the managed identity, and slot behavior without exporting values."),
    "app-metrics": ("Supported App Service metrics", "azure/azure-monitor/reference/supported-metrics/microsoft-web-sites-metrics",
                    "Confirm the request metric definition and scope; a zero aggregate misses non-HTTP workloads."),
    "storage-anon": ("Remediate anonymous Azure Blob access", "azure/storage/blobs/anonymous-read-access-prevent",
                     "Review the account-level setting and understand its effect on container-level public access."),
    "storage-tls": ("Require secure transfer for Azure Storage", "azure/storage/common/storage-require-secure-transfer",
                    "Confirm compatible client protocols and the effect of enabling secure transfer."),
    "vault": ("Key Vault soft delete and purge protection", "azure/key-vault/general/soft-delete-overview",
              "Compare recovery and retention behavior before making an irreversible purge protection change."),
    "logic": ("Secure access and data in Logic Apps", "azure/logic-apps/set-up-security-permissions",
              "Review approved trigger callers, authentication options, and access restrictions."),
    "diag": ("Diagnostic settings in Azure Monitor", "azure/azure-monitor/data-collection/diagnostic-settings",
             "Review supported categories, destinations, and retention policies without reading log entries."),
    "regions": ("List of Azure regions", "azure/reliability/regions-list",
                "Verify the observed Azure region and compare it with approved locations for data, replicas, and backups."),
    "waf": ("Azure Well-Architected security guidance", "azure/well-architected/security/",
            "Use the framework for review planning, not as evidence that the resource meets a control."),
    "recovery": ("Architecture strategies for disaster recovery", "azure/well-architected/reliability/disaster-recovery",
                 "Set recovery objectives and use measured restore or failover exercises to validate them."),
    "arg": ("Azure Resource Graph overview", "azure/governance/resource-graph/overview",
            "Check Resource Graph coverage and access requirements before interpreting gaps."),
    "arm": ("Azure Resource Manager scope and controls", "azure/azure-resource-manager/management/overview",
            "Trace the effects of scope and inheritance before interpreting individual resources or groups."),
    "rbac": ("Best practices for Azure RBAC", "azure/role-based-access-control/best-practices",
             "Review least privilege, narrow assignment scopes, and privileged access safeguards."),
    "score": ("Cloud Secure Score in Defender for Cloud", "azure/defender-for-cloud/secure-score-security-controls",
              "Review how the score is calculated; a score or count cannot establish whether a breach occurred."),
    "policy": ("Get Azure Policy compliance data", "azure/governance/policy/how-to/get-compliance-data",
               "Review evaluation scope and timestamps before treating a policy state as current."),
    "policy-effects": ("Azure Policy effects", "azure/governance/policy/concepts/effect-basics",
                       "Distinguish audit or evaluation from a policy that blocks changes."),
    "private-link": ("Azure Private Endpoint guidance", "azure/private-link/private-endpoint-overview",
                     "Confirm the endpoint targets the intended resource and that DNS and public access are configured separately."),
    "sql-access": ("Secure an Azure SQL database", "azure/azure-sql/database/secure-database-tutorial",
                   "Review network access, identity, and administration for Azure SQL; confirm applicability to other database types."),
    "sql-restore": ("Restore an Azure SQL database from backup", "azure/azure-sql/database/recovery-using-backups",
                    "Compare backup settings with supported restore paths and documented recovery tests."),
    "aks": ("Best practices for AKS cluster security", "azure/aks/operator-best-practices-cluster-security",
            "Review AKS control-plane access and patching without treating cluster inventory as workload-level evidence."),
    "vm-patch": ("Automatic guest patching for Azure VMs", "azure/virtual-machines/automatic-vm-guest-patching",
                 "Check supported VM configurations and responsibilities before treating a patching policy as verified."),
    "ca-report": ("Conditional Access report-only mode", "entra/identity/conditional-access/concept-conditional-access-report-only",
                  "Use report-only to evaluate the expected behavior before enforcing a policy."),
    "ca-mfa": ("Require MFA with Conditional Access", "entra/identity/conditional-access/policy-all-users-mfa-strength",
               "Check target scope and approved exclusions; the number of enabled policies cannot establish MFA coverage."),
    "auth-methods": ("Microsoft Entra authentication methods policy", "entra/identity/authentication/concept-authentication-methods-manage",
                     "Review which groups can use a method without assuming it is registered or enforced."),
    "auth-strength": ("Conditional Access authentication strengths", "entra/identity/authentication/concept-authentication-strengths",
                       "Distinguish which methods are enabled from what a sign-in policy requires."),
    "external": ("Configure external collaboration settings", "entra/external-id/external-collaboration-settings-configure",
                 "Review guest invitations separately from guest directory access and external collaboration restrictions."),
    "app-roles": ("Delegate application management permissions", "entra/identity/role-based-access-control/delegate-app-roles",
                  "Review how application registration and administrative permissions are delegated."),
    "billing": ("Allocate Azure costs", "azure/cost-management-billing/costs/allocate-costs",
                "Review allocation scope and the treatment of shared or unattributed costs."),
    "threat-monitoring": ("Well-Architected monitoring and threat detection", "azure/well-architected/security/monitor-threats",
                          "Identify necessary monitoring signals and validate the response workflow with the owning team."),
}
LINK_TITLES = {BASE + path: title for title, path, _ in ARTICLES.values()}

FINDING_REFERENCES = {
    "APP-HTTPS": ("app-config", "app-tls"),
    "APP-TLS": ("app-tls",),
    "APP-SCM-TLS": ("app-tls", "app-ingress"),
    "APP-FUNC-ANON": ("function-http", "app-auth"),
    "APP-SCM-BASIC": ("app-basic", "app-ingress"),
    "APP-FTP-BASIC": ("app-basic", "app-ftp"),
    "APP-FTP": ("app-ftp", "app-basic"),
    "APP-DEBUG": ("app-config", "app-ingress"),
    "APP-CORS": ("app-cors", "app-auth"),
    "APP-RUNTIME": ("app-patch",),
    "APP-STICKY-SECRET": ("app-secrets",),
    "APP-IDLE-HTTP": ("app-metrics",),
    "STG-ANON": ("storage-anon", "private-link"),
    "STG-HTTPS": ("storage-tls",),
    "KV-PURGE": ("vault",),
    "LOGIC-PUBLIC": ("logic",),
    "MON-DIAG": ("diag", "threat-monitoring"),
    "DATA-REGION-EEA": ("regions", "recovery"),
    "ENTRA-CA-REPORT": ("ca-report", "ca-mfa"),
    "ENTRA-GUEST-INVITES": ("external",),
    "ENTRA-APP-REGISTRATION": ("app-roles",),
    "ENTRA-VOICE-SMS": ("auth-methods", "auth-strength"),
}
SECTION_REFERENCES = {
    "Summary": ("waf", "threat-monitoring"),
    "Systems": ("arm", "waf"),
    "Resilience & DR": ("recovery", "sql-restore"),
    "Findings": ("waf",),
    "Resources": ("arg", "arm"),
    "Resource groups": ("arm", "rbac"),
    "Access (RBAC)": ("rbac", "arm"),
    "Security posture": ("score", "policy", "policy-effects", "ca-mfa"),
    "Network": ("private-link", "app-ingress"),
    "Databases": ("sql-access", "sql-restore"),
    "Storage": ("storage-anon", "storage-tls", "private-link"),
    "Apps": ("app-config", "app-tls", "app-basic", "app-auth"),
    "Containers": ("aks",),
    "Integration": ("logic", "private-link"),
    "Servers": ("vm-patch", "recovery"),
    "Secrets & identities": ("vault", "rbac", "app-secrets"),
    "Monitoring & logging": ("diag", "threat-monitoring"),
    "Cost": ("billing",),
    "Method and limits": ("arg", "arm", "policy"),
}


def url(article):
    return BASE + ARTICLES[article][1]


def reference_rows(articles):
    return ((ARTICLES[key][0], url(key), ARTICLES[key][2]) for key in articles)


def entra_review(graph):
    policies = {}
    for source, field, value in graph:
        policies.setdefault(source, {})[field] = value
    conditional = policies.get("conditionalAccessPolicies.json", {})
    counts = {label.split(" · ", 1)[0]: value for label, value in conditional.items()}
    if counts:
        enrolled = (f"Supplied page: {counts.get('enabled', 0)} enabled, "
                    f"{counts.get('enabledForReportingButNotEnforced', 0)} report-only, "
                    f"{counts.get('disabled', 0)} disabled.")
        if any("more pages" in label for label in conditional):
            enrolled += " The export indicates more pages; totals are incomplete."
        yield ("Conditional Access enforcement", enrolled,
               "Report-only and disabled policies do not enforce controls. The export does not show MFA requirements, policy coverage, or the effect of exclusions.",
               "Confirm policy targets, grant controls, and exclusions with the identity owner. Review report-only outcomes through the approved identity process before enabling enforcement.",
               url("ca-report"), url("ca-mfa"))
    methods = policies.get("authenticationMethodsPolicy.json", {})
    if methods:
        enabled = sorted(name for name, state in methods.items() if state == "enabled")
        observed = "Enabled methods observed: " + (", ".join(enabled) if enabled else "none in the supplied method rows") + "."
        yield ("Authentication methods and MFA", observed,
               "Availability does not demonstrate registration, sign-in use, or a phishing-resistant requirement. Method targets were not interpreted.",
               "Confirm who can register each method and which authentication strengths are actually required for privileged and sensitive access.",
               url("auth-methods"), url("auth-strength"))
    authorization = policies.get("authorizationPolicy.json", {})
    if "allowInvitesFrom" in authorization:
        yield ("Guest invitation permissions", f"Configured invitation policy: {authorization['allowInvitesFrom']}.",
               "The setting indicates who may invite guests, not which guests exist or the access they have.",
               "Confirm that approved invitation roles match the business process and review guest permissions independently with the identity owner.",
               url("external"), None)
    if "allowedToCreateApps" in authorization:
        value = "Yes" if authorization["allowedToCreateApps"] else "No"
        yield ("Default application registration permission", f"Default member role is allowed to create apps: {value}.",
               "The default setting does not establish who has separately delegated rights, what apps exist, or what consent was granted.",
               "Confirm the approved registration process, owner responsibilities, and separately delegated roles.",
               url("app-roles"), None)
