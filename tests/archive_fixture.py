"""Synthetic archive content for tests only."""

GRAPH = "https://graph.microsoft.com/v1.0/$metadata"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SECOND_SUB = "/subscriptions/00000000-0000-0000-0000-000000000002"
GROUP = SUB + "/resourceGroups/rg-demo-orders-test"
PROD = SUB + "/resourceGroups/rg-demo-orders-prod"
DATA = SECOND_SUB + "/resourceGroups/rg-demo-analytics-prod"
PLATFORM = SECOND_SUB + "/resourceGroups/rg-demo-platform"
SITE = GROUP + "/providers/Microsoft.Web/sites/sample-orders-api"
PROD_SITE = PROD + "/providers/Microsoft.Web/sites/sample-orders-prod"
PLAN = PROD + "/providers/Microsoft.Web/serverfarms/sample-prod-plan"


def resource(group, kind, name, location="westeurope", **settings):
    return {"id": f"{group}/providers/{kind}/{name}", "type": kind.lower(), "location": location, **settings}

FILES = {
    "authorizationPolicy.json": {
        "@odata.context": GRAPH + "#policies/authorizationPolicy/$entity",
        "id": "authorizationPolicy",
        "displayName": "Synthetic authorization policy",
        "allowInvitesFrom": "adminsAndGuestInviters",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": False,
            "allowedToCreateSecurityGroups": True,
            "allowedToReadOtherUsers": True,
        },
    },
    "authenticationMethodsPolicy.json": {
        "@odata.context": GRAPH + "#policies/authenticationMethodsPolicy/$entity",
        "id": "authenticationMethodsPolicy",
        "displayName": "Synthetic authentication methods policy",
        "policyVersion": "1.5",
        "authenticationMethodConfigurations": [
            {"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration", "id": "Fido2", "state": "enabled"},
            {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
             "id": "MicrosoftAuthenticator", "state": "enabled"},
            {"@odata.type": "#microsoft.graph.smsAuthenticationMethodConfiguration", "id": "Sms", "state": "disabled"},
            {"id": "TemporaryAccessPass", "state": "enabled"},
            {"id": "Voice", "state": "disabled"},
            {"id": "SoftwareOath", "state": "enabled"},
            {"id": "X509Certificate", "state": "disabled"},
        ],
    },
    "conditionalAccessPolicies.json": {
        "@odata.context": GRAPH + "#identity/conditionalAccess/policies",
        "value": [
            {"id": "00000000-0000-0000-0000-000000000011", "displayName": "Synthetic enforced policy", "state": "enabled"},
            {"id": "00000000-0000-0000-0000-000000000012", "displayName": "Synthetic report-only policy",
             "state": "enabledForReportingButNotEnforced"},
            {"id": "00000000-0000-0000-0000-000000000013", "displayName": "Synthetic disabled policy", "state": "disabled"},
            {"id": "00000000-0000-0000-0000-000000000014", "displayName": "Synthetic admin MFA", "state": "enabled"},
            {"id": "00000000-0000-0000-0000-000000000015", "displayName": "Synthetic device policy",
             "state": "enabledForReportingButNotEnforced"},
            {"id": "00000000-0000-0000-0000-000000000016", "displayName": "Synthetic legacy authentication",
             "state": "enabled"},
        ],
    },
    "assessment-v1.json": {
        "schema_version": 1,
        "subscriptions": [sub.rsplit("/", 1)[-1] for sub in (SUB, SECOND_SUB)],
        "groups": [GROUP, PROD, DATA, PLATFORM],
        "resources": [
            {"id": SITE, "type": "microsoft.web/sites", "location": "westeurope",
             "httpsOnly": False, "minTlsVersion": "1.2", "publicNetworkAccess": "Enabled", "corsAnyOrigin": True},
            {"id": GROUP + "/providers/Microsoft.Storage/storageAccounts/sampleordersdata",
             "type": "microsoft.storage/storageaccounts", "location": "westeurope",
             "secureTransferRequired": True, "allowBlobPublicAccess": True},
            resource(PROD, "Microsoft.Web/sites", "sample-orders-prod", httpsOnly=True, minTlsVersion="1.2",
                     publicNetworkAccess="Disabled", diagnosticsConfigured=True, scmBasicAuthEnabled=False,
                     planId=PLAN, requests30d=85_000, http4xx30d=85, http5xx30d=11, backupConfigured=True),
            resource(PROD, "Microsoft.Web/sites/slots", "sample-orders-prod/slots/staging", httpsOnly=True,
                     minScmTlsVersion="1.0", scmBasicAuthEnabled=True, remoteDebuggingEnabled=True, requests30d=0),
            resource(PROD, "Microsoft.Web/serverfarms", "sample-prod-plan", planSku="P1V3", planWorkers=2, zoneRedundant=True),
            resource(DATA, "Microsoft.Storage/storageAccounts", "sampleanalyticsarchive", location="eastus",
                     publicNetworkAccess="Disabled", secureTransferRequired=True, allowBlobPublicAccess=False),
            resource(DATA, "Microsoft.Storage/storageAccounts", "sampleanalyticsingest"),
            resource(DATA, "Microsoft.Sql/servers/databases", "sample-sql/databases/orders", backupConfigured=True,
                     replicaCount=2, zoneRedundant=True),
            resource(PLATFORM, "Microsoft.KeyVault/vaults", "sample-review-vault", enablePurgeProtection=False,
                     publicNetworkAccess="Disabled"),
            resource(PLATFORM, "Microsoft.ContainerService/managedClusters", "sample-private-cluster", zoneCount=3),
            resource(PLATFORM, "Microsoft.Network/privateEndpoints", "sample-private-endpoint"),
            resource(PLATFORM, "Microsoft.Logic/workflows", "sample-notifications", publicTriggerEnabled=True,
                     diagnosticsConfigured=False),
        ],
        "functions": [
            {"id": SITE + "/functions/sample-health", "trigger": "httpTrigger", "authLevel": "anonymous", "disabled": False},
            {"id": PROD_SITE + "/functions/sample-order", "trigger": "httpTrigger", "authLevel": "function", "disabled": False},
            {"id": PROD_SITE + "/functions/sample-disabled", "trigger": "httpTrigger", "authLevel": "anonymous", "disabled": True},
        ],
        "rbac": [{"scope": PROD, "principalId": "00000000-0000-0000-0000-000000000021", "principalType": "Group",
                  "roleDefinitionId": "00000000-0000-0000-0000-000000000031"}],
        "costs": [{"subscriptionId": group.split("/")[2], "group": group, "amount": amount, "currency": "EUR"}
                  for group, amount in ((GROUP, 85.25), (PROD, 1137.42), (DATA, 304.60), (PLATFORM, 215.90))],
        "posture": [{"subscriptionId": SECOND_SUB.rsplit("/", 1)[-1], "metric": metric, "value": value}
                    for metric, value in (("secure_score_percent", 79.4), ("defender_alert_medium", 2),
                                          ("policy_assignments", 8), ("policy_noncompliant", 3))],
    },
    "prowler-summary.json": {
        "version": "6.1.0",
        "checks": [
            {"benchmark": "CIS-Azure", "section": "2", "requirement": "2.1.1", "status": "manual_review"},
            {"benchmark": "CIS-Azure", "section": "3", "requirement": "3.1", "status": "needs_entra_access"},
            {"benchmark": "NIS2-2024-2690", "section": "9", "requirement": "9.1", "status": "fail", "point": "h"},
        ],
    },
}
