"""Versioned configuration rules; unknown values never count as a failed check."""

from dataclasses import dataclass
from operator import eq, contains


@dataclass(frozen=True)
class Rule:
    key: str
    title: str
    kinds: tuple
    field: str
    expected: object
    severity: str
    why: str
    action: str
    nis2: str
    gdpr: tuple = ("5(1)(f)", "32")

    def applies_to(self, resource):
        return not self.kinds or resource["type"] in self.kinds

    def matches(self, resource):
        props = resource["properties"]
        if not self.applies_to(resource) or self.field not in props:
            return False
        value = props[self.field]
        return contains(self.expected, value) if isinstance(self.expected, tuple) else eq(value, self.expected)


WEB = ("microsoft.web/sites", "microsoft.web/sites/slots")
STORAGE = ("microsoft.storage/storageaccounts",)
VAULT = ("microsoft.keyvault/vaults",)
RULES = (
    Rule("APP-HTTPS", "HTTPS not enforced", WEB, "httpsOnly", False, "Medium",
         "The app may accept unencrypted HTTP connections.", "Confirm dependencies before enforcing HTTPS.", "hi"),
    Rule("APP-TLS", "Legacy TLS on the app", WEB, "minTlsVersion", ("1.0", "1.1"), "Medium",
         "The configuration allows older TLS versions.", "Check client compatibility and plan for TLS 1.2 or higher.", "h"),
    Rule("APP-SCM-TLS", "Legacy TLS on SCM", WEB, "minScmTlsVersion", ("1.0", "1.1"), "Medium",
         "The deployment endpoint accepts an older TLS version.", "Validate the pipeline before raising the SCM TLS minimum.", "eh"),
    Rule("APP-FUNC-ANON", "Enabled HTTP function does not require a function key", WEB, "anonymousHttpEnabled", True, "High",
         "The HTTP function does not require a key at runtime. Other controls may still restrict access.",
         "Confirm upstream authentication and whether anonymous access is needed.", "ei", ("25", "32")),
    Rule("APP-SCM-BASIC", "Basic authentication enabled for SCM publishing", WEB, "scmBasicAuthEnabled", True, "Medium",
         "Publishing accounts provide another way to deploy code.", "Confirm whether the pipeline allows SCM Basic Auth to be disabled.", "ei"),
    Rule("APP-FTP-BASIC", "Basic authentication enabled for FTP publishing", WEB, "ftpBasicAuthEnabled", True, "Medium",
         "FTP publishing may rely on shared credentials.", "Confirm whether the publishing method can be replaced.", "ei"),
    Rule("APP-FTP", "App Service allows unencrypted FTP", WEB, "ftpsState", "AllAllowed", "Medium",
         "FTP does not protect credentials in transit.", "Plan to disable FTP or move to a secure channel.", "eh"),
    Rule("APP-DEBUG", "Remote debugging enabled", WEB, "remoteDebuggingEnabled", True, "Medium",
         "The debug interface adds another administrative entry point.", "Confirm whether it is needed before disabling it in production.", "ei"),
    Rule("APP-CORS", "CORS allows any origin", WEB, "corsAnyOrigin", True, "Low",
         "The CORS policy does not restrict origins. This does not establish unauthorized access.",
         "Limit allowed origins to those approved.", "ei", ("25", "32")),
    Rule("APP-RUNTIME", "Runtime out of support", WEB, "runtimeStatus", "out_of_support", "Medium",
         "Vendor support and security updates may no longer be available.",
         "Verify the version and end-of-support date with the vendor, then plan the upgrade.", "e"),
    Rule("APP-STICKY-SECRET", "Sticky setting name suggests a secret", WEB, "secretLikeStickySettingPresent", True, "Low",
         "The classification uses names only and does not establish that the value is a secret.",
         "Confirm whether Key Vault references and managed identities are used without exporting values.", "ei"),
    Rule("APP-IDLE-HTTP", "No HTTP requests reported in the past 30 days", WEB, "requests30d", 0, "Low",
         "The app may be idle or run non-HTTP jobs. The count alone does not justify decommissioning.",
         "Confirm dependencies, continuity requirements, and metric coverage with the owner.", "ac", ()),
    Rule("STG-ANON", "Storage allows anonymous blob access to be configured", STORAGE, "allowBlobPublicAccess", True, "Medium",
         "This account setting allows containers to be made public. It does not show that any are public.",
         "Confirm approved exceptions before planning to block anonymous access at account level.", "ei", ("25", "32")),
    Rule("STG-HTTPS", "Secure transfer is not required for Storage", STORAGE, "secureTransferRequired", False, "Medium",
         "This setting does not reject unencrypted connections.", "Confirm compatibility before requiring secure transfer.", "h"),
    Rule("KV-PURGE", "Key Vault purge protection disabled", VAULT, "enablePurgeProtection", False, "Medium",
         "Permanent deletion can reduce recovery options.", "Verify retention and recovery requirements before enabling protection.", "c"),
    Rule("LOGIC-PUBLIC", "Logic App trigger reported as public", ("microsoft.logic/workflows",), "publicTriggerEnabled", True, "Medium",
         "The trigger needs an access-control review. This setting does not prove anonymous access.",
         "Confirm network restrictions and authentication without testing callback URLs.", "ei", ("25", "32")),
    Rule("MON-DIAG", "Diagnostic settings reported as absent", (), "diagnosticsConfigured", False, "Medium",
         "Missing telemetry can limit incident investigations.", "Validate telemetry destinations, retention, and minimization.", "bf", ("32", "33")),
    Rule("DATA-REGION-EEA", "Storage or backup service observed outside the EEA", (), "outsideEEARegion", True, "Low",
         "Region is a configuration indicator, not proof of a transfer of personal data.",
         "Ask the DPO to verify the data processed, replica and backup locations, and applicable transfer mechanisms.", "a", ("44–49",)),
)

GRAPH_RULES = (
    Rule("ENTRA-CA-REPORT", "Conditional Access policy in report-only mode", ("microsoft.graph/conditionalaccess",),
         "reportOnlyPresent", True, "Low", "This policy does not enforce its configured controls.",
         "Have the identity owner review this policy's scope, exclusions, and intended enforcement date.", "fi", ("32",)),
    Rule("ENTRA-CA-AUTH-OR", "Conditional Access authentication grant is one of multiple alternatives",
         ("microsoft.graph/conditionalaccess",), "enabledAlternativeAuthentication", True, "Medium",
         "For requests that match this enabled policy, another configured grant may satisfy this policy without its authentication grant.",
         "Verify whether authentication must be required and review overlapping policies before changing the grant operator.", "ij", ("32",)),
    Rule("ENTRA-GUEST-INVITES", "Guest invitations allowed beyond designated roles", (), "guestInvitationPolicy",
         ("everyone", "adminsGuestInvitersAndAllMembers"), "Low",
         "A broader invitation policy can increase the need for external collaboration oversight.",
         "Review which roles should be able to invite guests and how guest access is governed.", "i", ("32",)),
    Rule("ENTRA-APP-REGISTRATION", "Default members can register applications", (), "defaultAppRegistration", True, "Low",
         "Default app registration permissions broaden who can create apps. They do not establish consent or granted privileges.",
         "Confirm whether app registrations should be limited to approved owners or delegated roles.", "i", ("32",)),
    Rule("ENTRA-VOICE-SMS", "SMS or voice enabled in the authentication methods policy", (), "smsOrVoiceEnabled", True, "Low",
         "Method availability does not show registration, use, or whether stronger methods are required.",
         "Verify authentication strength for privileged or sensitive access before changing method availability.", "j", ("32",)),
)
M365_RULES = (
    Rule("M365-SPO-ANYONE", "SharePoint and OneDrive tenant policy permits Anyone links",
         ("microsoft.graph/sharepoint",), "sharingCapability", "externalUserAndGuestSharing", "Medium",
         "The tenant policy allows links that do not require sign-in; it does not establish that a site or file is shared.",
         "Verify tenant and site sharing limits and confirm approved anonymous sharing exceptions.", "ei", ("25", "32")),
    Rule("M365-SPO-LEGACY", "SharePoint legacy authentication protocols enabled",
         ("microsoft.graph/sharepoint",), "isLegacyAuthProtocolsEnabled", True, "Medium",
         "The tenant setting permits older authentication protocols; it does not show client usage or effective Conditional Access.",
         "Confirm legacy client dependencies and plan a transition to modern authentication.", "ij", ("32",)),
    Rule("M365-SPO-RESHARE", "SharePoint permits external guest resharing",
         ("microsoft.graph/sharepoint",), "isResharingByExternalUsersEnabled", True, "Low",
         "A guest may reshare items under the tenant policy when other sharing controls permit it.",
         "Verify external collaboration requirements and site-level restrictions before changing the setting.", "di", ("25", "32")),
    Rule("M365-TEAMS-GUEST-EDIT", "Teams guests can create or update channels",
         ("microsoft.graph/team",), "guestSettings.allowCreateUpdateChannels", True, "Low",
         "The team setting permits guest channel changes; it does not establish that guests are present or allowed at tenant level.",
         "Confirm channel governance requirements with the team owner.", "i", ("32",)),
    Rule("M365-TEAMS-GUEST-DELETE", "Teams guests can delete channels",
         ("microsoft.graph/team",), "guestSettings.allowDeleteChannels", True, "Medium",
         "The team setting permits guest channel deletion if guests have effective access.",
         "Review guest access and channel recovery with the team owner before changing permissions.", "ci", ("32",)),
)


@dataclass(frozen=True)
class FindingGuidance:
    owners: str
    limit: str
    verify: str
    change: str
    close: str
    related_fields: tuple[str, ...] = ()


GUIDANCE = {
    "APP-HTTPS": FindingGuidance(
        "Application owner and ingress or network owner",
        "The site setting does not show whether an upstream gateway already redirects HTTP, whether a direct route exists, or whether anyone used one.",
        "Inventory approved entry points and clients. Check redirects at the gateway and app, including direct ingress paths, callback URLs, and clients that cannot follow redirects.",
        "Test HTTPS enforcement on a staging slot or equivalent test environment. Update client URLs and callbacks before rollout. Agree on a fallback for critical integrations without reopening unrestricted HTTP.",
        "Confirm the current site setting enforces HTTPS. Record approved synthetic results showing that normal HTTPS requests succeed and plain HTTP cannot serve application content.",
        ("publicNetworkAccess", "mainDefaultAction", "minTlsVersion"),
    ),
    "APP-TLS": FindingGuidance(
        "Application owner and client integration owners",
        "The configured TLS minimum does not identify which clients negotiate older protocols. It also does not describe TLS on an upstream gateway or on SCM.",
        "Inventory supported clients, partner integrations, and gateway-to-app connections. Confirm the effective TLS requirements for each approved ingress path.",
        "Plan a baseline of TLS 1.2 or higher as required by policy. Upgrade incompatible clients first, then test on a staging slot and define a rollback threshold for availability or handshake errors.",
        "Recollect the configured minimum and verify, with approved synthetic clients, that supported TLS versions connect and versions below the baseline are rejected.",
        ("publicNetworkAccess", "minScmTlsVersion"),
    ),
    "APP-SCM-TLS": FindingGuidance(
        "Platform engineering and deployment pipeline owner",
        "The SCM minimum applies to the deployment surface; it does not establish exposure or describe TLS on the main application.",
        "Review SCM restrictions and whether it uses the main site's rules. Identify build runners, publishing clients, and any release automation still using legacy TLS.",
        "Update the deployment clients and raise the SCM minimum to the approved baseline on a test slot first. Keep an authorized alternate deployment path available.",
        "Confirm the new SCM minimum in configuration and complete a test deployment using the approved pipeline. Validate that the main application's clients are unaffected.",
        ("scmUsesMainRestrictions", "scmDefaultAction", "minTlsVersion"),
    ),
    "APP-FUNC-ANON": FindingGuidance(
        "Function owner and API gateway or identity owner",
        "A function key is not required by the runtime. That is not proof of internet reachability or unauthenticated end-to-end access. Network rules, a gateway, or platform authentication may still protect it.",
        "Confirm the function, route, and intended callers using approved configuration. Check whether gateway authentication can be bypassed through direct app access, and whether the function performs a sensitive operation.",
        "Protect private operations with an approved identity or authenticated gateway and restrict direct ingress. Validate authorized callers in staging before rollout. For an intentionally public endpoint, document its business purpose, limits, and exception expiry.",
        "Use an approved synthetic request in a test environment to confirm allowed callers can reach the function and unauthorized callers are denied, or record the signed public-access exception. Do not copy invocation URLs or keys into the assessment.",
        ("publicNetworkAccess", "mainDefaultAction", "authenticationEnabled", "privateEndpointCount"),
    ),
    "APP-SCM-BASIC": FindingGuidance(
        "Platform engineering and deployment pipeline owner",
        "The publishing policy permits Basic Auth; it does not prove the credentials are exposed or that the SCM endpoint is publicly reachable.",
        "Identify pipelines, deployment tools, and emergency release procedures that depend on Basic Auth. Confirm which identities are authorized to deploy and how SCM is reached.",
        "Migrate dependent workflows to an approved identity-based deployment path with least-privilege access. Validate releases on a test slot before disabling SCM Basic Auth in production.",
        "Verify SCM Basic Auth is disabled and the replacement pipeline can deploy and revert an approved test release. Record remaining exceptions and their expiry.",
        ("scmUsesMainRestrictions", "scmDefaultAction", "minScmTlsVersion"),
    ),
    "APP-FTP-BASIC": FindingGuidance(
        "Application owner and deployment pipeline owner",
        "The policy permits FTP publishing credentials; this does not prove anyone uses them. Whether the service accepts unencrypted FTP is a separate setting.",
        "Identify deployment jobs or support procedures that still require FTP publishing. Check the transport setting and confirm a replacement mechanism.",
        "Move affected jobs to the approved deployment mechanism; test publishing and recovery in nonproduction. Disable FTP Basic Auth after consumers have migrated.",
        "Confirm the FTP publishing policy is disabled and deployment and rollback succeed without FTP credentials. Document any approved temporary exception.",
        ("ftpsState",),
    ),
    "APP-FTP": FindingGuidance(
        "Application owner and release engineering",
        "The protocol setting permits unencrypted FTP. It does not show that FTP is reachable or that credentials or files were transmitted.",
        "Review deployment jobs, FTP authentication policy, and any support process that relies on direct file publishing.",
        "Prefer disabling FTP. If a temporary dependency makes that impossible, use an approved encrypted path and assign an owner and expiry date to the exception.",
        "Confirm plain FTP is disabled in current configuration and that approved deployment and recovery jobs succeed. Review when any temporary exception can be removed.",
        ("ftpBasicAuthEnabled", "publicNetworkAccess"),
    ),
    "APP-DEBUG": FindingGuidance(
        "Application owner and incident response or support lead",
        "Remote debugging is enabled in configuration. This does not show that anyone attached a debugger or could reach the debug endpoint.",
        "Confirm the slot and environment, approved debugging workflow, and any active exception. Review access controls and determine whether support still needs this setting.",
        "Disable persistent remote debugging on production slots after validating the approved support alternative. For temporary use, require restricted access, an owner, and an expiry.",
        "Recollect the setting and verify the application's health and approved support workflow. If an exception remains, record when it will be rechecked.",
        ("scmDefaultAction", "scmUsesMainRestrictions"),
    ),
    "APP-CORS": FindingGuidance(
        "API owner and frontend integration owners",
        "A wildcard origin allows broad browser cross-origin access. It does not by itself bypass authentication, prove credentialed access, or show data disclosure.",
        "Identify the legitimate browser origins and whether the app or gateway sets CORS headers. Validate the expected authentication and credential behavior with the application owner.",
        "Replace the wildcard with an environment-specific allowlist. Roll it out in staging and check that approved browser clients and preflight requests still work.",
        "Record approved synthetic browser results showing trusted origins work and unapproved origins cannot read the response. Confirm non-browser authorization remains enforced independently.",
        ("authenticationEnabled", "publicNetworkAccess"),
    ),
    "APP-RUNTIME": FindingGuidance(
        "Application owner and runtime or dependency maintainer",
        "End-of-support status depends on the configured stack and available lifecycle evidence. It does not establish that a specific vulnerability is present or exploitable.",
        "Confirm the exact stack and version against the vendor's current maintenance policy. Identify runtime-dependent packages, platform changes, and compatibility tests.",
        "Choose a supported target version and validate it in staging. Rehearse deployment, health checks, and rollback to an approved image or slot before production rollout.",
        "Record the vendor lifecycle source, verify the running version is supported, and attach test results and a date for the next lifecycle review.",
        ("runtimeStack", "runtimeVersion", "runtimeEosDate"),
    ),
    "APP-STICKY-SECRET": FindingGuidance(
        "Application owner and secrets management owner",
        "Only setting names were classified. No values were inspected, and the snapshot cannot establish that a secret exists, is exposed, or is stored as plaintext.",
        "Have the owner verify, in an approved interface, whether the setting is a reference or a value and how it should behave during slot swaps. Do not export the value.",
        "Where necessary, migrate to approved secret storage and managed identity. Confirm least-privilege access and test secret resolution and rotation in a nonproduction slot first.",
        "Record that the owner verified reference resolution and rotation without copying names or values into the report. An unchanged name-only signal can remain as a documented exception, not evidence that migration failed.",
        ("stickySettingCount", "secretLikeStickySettingCount", "managedIdentityEnabled", "keyVaultReferenceIdentityConfigured"),
    ),
    "APP-IDLE-HTTP": FindingGuidance(
        "Application owner, operations, and FinOps",
        "Zero recorded HTTP requests is not proof that the service is unused. Scheduled functions, queue workers, failover capacity, or gaps in monitoring can explain the result.",
        "Confirm the metric window and collection coverage. Ask about background triggers, seasonal traffic, incident standby, upstream dependencies, and retention obligations.",
        "Do not decommission based on HTTP counts alone. If the owner confirms the service is unused, agree on a reversible pause, dependency monitoring, and a recovery window before removal.",
        "Record the owner decision and supporting evidence. If retiring the app, complete the pause and recovery checks before releasing resources; otherwise document why HTTP counts are not a useful usage signal.",
        ("requests30d", "diagnosticsConfigured", "backupConfigured"),
    ),
    "STG-ANON": FindingGuidance(
        "Storage account owner and application or data owners",
        "The account allows containers to opt in to anonymous access. The assessment did not read container settings or blob contents; it cannot establish that a container is public or that data was downloaded.",
        "Ask the owner to confirm the intended publishing use case and known dependencies using approved configuration evidence. Review network controls separately; they do not replace container authorization.",
        "Migrate required clients to authenticated access, or isolate intentionally public assets in a dedicated, approved account. Test application and content delivery paths before disabling anonymous access on this account.",
        "Recollect the account setting and confirm anonymous access is disallowed. Verify approved clients still work in staging, or record the scoped exception and its expiry.",
        ("publicNetworkAccess", "secureTransferRequired"),
    ),
    "STG-HTTPS": FindingGuidance(
        "Storage account owner and client integration owners",
        "The account does not require secure transfer. This does not show which clients use unencrypted transport.",
        "Identify SDKs, proxies, and workloads that read or write to the account, including approved file-share clients. Confirm they support encrypted transport.",
        "Upgrade or reconfigure incompatible clients first. Validate HTTPS or the appropriate encrypted protocol in a test environment before requiring secure transfer.",
        "Verify the current secure-transfer setting and check approved synthetic client operations succeed over encrypted transport. Document any residual compatibility exception.",
        ("publicNetworkAccess", "minTlsVersion"),
    ),
    "KV-PURGE": FindingGuidance(
        "Key Vault owner, recovery owner, and security governance",
        "Purge protection being disabled is a recovery risk. The snapshot does not show that vault objects were purged, that keys are exposed, or that recovery has been rehearsed.",
        "Confirm the vault retention period, who can delete or purge objects, dependencies on the vault, and recovery time requirements.",
        "Obtain explicit approval before enabling purge protection: it cannot be turned off after activation. Review its effect on retention, name reuse, and recovery workflows before changing production.",
        "Recollect purge protection and retention metadata after approval. Rehearse recovery in a safe test vault under a separate change plan; do not delete or purge production objects to validate the finding.",
        ("publicNetworkAccess", "retentionDays"),
    ),
    "LOGIC-PUBLIC": FindingGuidance(
        "Workflow owner and integration or identity owner",
        "The input flags the trigger as public. It does not establish anonymous access, credential disclosure, or whether a gateway is required.",
        "Review the trigger type, authorized callers, access restrictions, and authentication design. Determine whether callers must reach the workflow directly without collecting a callback URL.",
        "Apply the approved ingress and authentication design in nonproduction first. Plan migration for webhook consumers and keep an approved recovery path if deliveries fail.",
        "Confirm approved test callers can trigger the nonproduction workflow and unapproved callers cannot. Record the reviewed configuration rather than a callback URL or token.",
        ("publicNetworkAccess", "authenticationEnabled"),
    ),
    "MON-DIAG": FindingGuidance(
        "Resource owner and security monitoring team",
        "This resource reports no diagnostic settings. It does not show whether another approved telemetry source covers the required events or how long data is retained.",
        "Confirm which events must be observable, whether platform monitoring already covers them, and which destination and retention policy the organization has approved.",
        "Configure only approved categories and destinations. Review retention, access, cost, residency, and personal-data minimization before enabling collection.",
        "Verify the new configuration and retention in metadata. Have the authorized monitoring team confirm delivery with an approved synthetic event while keeping raw log entries out of the report.",
        ("httpLoggingEnabled", "retentionDays"),
    ),
    "DATA-REGION-EEA": FindingGuidance(
        "Data owner, cloud architecture, and data protection or legal team",
        "A non-EEA resource location is a screening signal. It does not prove that personal data is present, that it crossed a border, or that any transfer lacks a lawful mechanism.",
        "Confirm data classifications and the locations of primary services, replicas, backups, and support access. Compare those facts against the recorded data flows and hosting commitments.",
        "If the data owner and legal team identify an unapproved location or transfer, agree on an approved region or safeguards. Plan migration and retention of historical backups before changing replication.",
        "Record the verified locations and DPO or legal decision. If migrated, verify the new primary and secondary locations and confirm how remaining copies are handled.",
        ("backupConfigured", "replicaCount", "zoneRedundant"),
    ),
    "ENTRA-CA-REPORT": FindingGuidance(
        "Identity and Conditional Access owners",
        "The supplied page may be incomplete. The policy state does not establish MFA coverage, targets, exclusions, or effectiveness.",
        "Review policy purpose, target identities and resources, grant controls, and exclusions in the approved identity process.",
        "Use report-only evaluation and a limited rollout before enforcing a policy. Preserve approved emergency access.",
        "Record the owner decision, validated outcomes, and the enforcement schedule or approved exception.",
        ("policyState", "grantOperator", "authenticationGrant", "userScope", "applicationScope", "exclusionsObserved"),
    ),
    "ENTRA-CA-AUTH-OR": FindingGuidance(
        "Identity and Conditional Access owners",
        "This finding concerns one policy. Other policies may still require MFA or a specific authentication strength.",
        "Compare the policy's configured grants and matching scope with the approved authentication requirement.",
        "If authentication is mandatory, have the policy owner test a revised requirement in report-only mode before enforcing it.",
        "Confirm that approved test identities see the expected grant requirements without affecting emergency access.",
        ("policyState", "grantOperator", "authenticationGrant", "userScope", "applicationScope", "exclusionsObserved"),
    ),
    "ENTRA-GUEST-INVITES": FindingGuidance(
        "Identity and external collaboration owners",
        "The invitation setting does not show guest identities, cross-tenant restrictions, or effective guest access.",
        "Confirm the approved invitation process and whether the business needs general member invitations.",
        "If needed, delegate invitations to approved roles and pilot the process with existing collaboration owners.",
        "Confirm the new invitation policy and an approved onboarding test, or document the exception.",
    ),
    "ENTRA-APP-REGISTRATION": FindingGuidance(
        "Identity and application governance owners",
        "The default permission does not show individually delegated permissions, existing applications, or granted consent.",
        "Review the approved application registration and service ownership processes.",
        "If needed, delegate registrations through an approved role or request workflow; verify required developer workflows first.",
        "Confirm the default setting and that an authorized requester can still register an application.",
    ),
    "ENTRA-VOICE-SMS": FindingGuidance(
        "Identity owner and service desk",
        "Enabled methods do not prove that these methods are used or satisfy a particular policy.",
        "Verify registration coverage and the authentication strengths required by actual Conditional Access policies.",
        "Pilot stronger methods with approved groups before removing a method on which recovery or access depends.",
        "Confirm policy enforcement and the approved recovery path with synthetic test identities.",
    ),
    "M365-SPO-ANYONE": FindingGuidance(
        "SharePoint and data owners", "The tenant setting does not prove that any item is publicly shared.",
        "Check approved anonymous sharing use cases and affected site policy through authorized configuration exports.",
        "Pilot narrower sharing defaults and validate that legitimate partners still have access.",
        "Verify tenant and site policy and document any approved public-sharing exception.",
    ),
    "M365-SPO-LEGACY": FindingGuidance(
        "SharePoint and identity owners", "Allowed protocols are not evidence of sign-in activity.",
        "Identify approved workflows that rely on legacy protocols without importing sign-in logs.",
        "Migrate dependent workflows to modern authentication before restricting the older methods.",
        "Confirm the new policy and validate approved integration workflows.",
    ),
    "M365-SPO-RESHARE": FindingGuidance(
        "SharePoint and external collaboration owners", "Site policy and the tenant sharing mode may restrict effective resharing.",
        "Confirm how guests are expected to collaborate and where resharing exceptions are needed.",
        "Pilot narrower guest permissions before expanding restrictions.",
        "Confirm owner-approved guest collaboration still works under the new policy.",
    ),
    "M365-TEAMS-GUEST-EDIT": FindingGuidance(
        "Teams service and team owners", "No channel content, guest membership, or tenant-wide guest access was assessed.",
        "Check whether the team requires guests to create or rename channels.",
        "Narrow guest channel settings only after confirming owner and guest workflows.",
        "Review the updated team setting and confirm approved channel management behavior.",
    ),
    "M365-TEAMS-GUEST-DELETE": FindingGuidance(
        "Teams service and team owners", "The setting does not prove past deletion or that guests are present.",
        "Verify team-level and tenant-level guest access, and confirm the channel recovery process.",
        "Limit deletion to approved roles unless a documented business exception applies.",
        "Confirm the setting and record the recovery and exception decisions with the owner.",
    ),
}

NIS2 = dict(zip("abcdefghij", (
    "Risk analysis and information system security", "Incident handling",
    "Business continuity, backup, and recovery", "Supply chain security",
    "Acquisition, development, and maintenance", "Assessment of control effectiveness",
    "Cyber hygiene and training", "Cryptography and encryption",
    "Human resources security, access control, and asset management", "Strong authentication and secure communications",
)))

QUESTIONS = {
    "EXCEPTION": "Ask the owner whether an approved exception exists and when it will be reviewed.",
    "COMPENSATING": "Request evidence of compensating controls and their limitations.",
    "CHANGE": "Validate the impact of remediation and the rollback plan with the owner.",
    "EVIDENCE": "Confirm the source and date of the evidence before accepting the mapping.",
    "SCOPE": "Confirm the system boundaries and services excluded from the assessment.",
    "DPO": "Ask the DPO to review how the control is interpreted and documented.",
}


def findings(resources, assignments):
    results = []
    levels = ("Low", "Medium", "High")
    for resource in resources:
        for rule in RULES:
            if not rule.matches(resource):
                continue
            system, likely = assignments.get(resource["group"], (resource["group"] or "Unassigned", None))
            severity = levels[min(2, levels.index(rule.severity) + int(likely is True))]
            results.append((rule, resource, system, severity, likely is True and severity != rule.severity))
    return results
