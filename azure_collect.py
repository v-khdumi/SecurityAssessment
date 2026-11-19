"""Read-only Azure public-cloud inventory using an existing Azure CLI session.

collect() returns identifiers in memory for the caller's privacy projection.
The standalone command delegates report writing to that same projection.
"""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit


class CollectionError(RuntimeError):
    """A fixed, safe message suitable for CLI or UI display."""


class CollectionLogin(CollectionError):
    """The Azure CLI needs a usable sign-in for the selected tenant."""


_BAD_TENANT = "A tenant GUID is required."
_AZ_UNAVAILABLE = "A supported Azure CLI installation was not found."
_ACCOUNT_ERROR = "Could not read the Azure CLI subscription cache."
_NO_SUBSCRIPTIONS = (
    "No enabled public-cloud subscriptions for this tenant are cached. "
    "Sign in separately with Azure CLI."
)
_LOGIN_ERROR = "Azure CLI sign-in is required for this tenant. Sign in separately with Azure CLI."
_CONFIRM_ERROR = "Read-only confirmation is required."
_OUTPUT_ERROR = "An existing local output directory is required."
_BUILD_ERROR = "Could not build the report."
_USAGE_ERROR = "Invalid arguments; see --help."

_ARM = "https://management.azure.com"
_ARG_URL = _ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
_MAX_PAGES = 1000
_GUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.I | re.ASCII)
_TYPE = re.compile(r"[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)+", re.ASCII)
_LOCATION = re.compile(r"[a-z][a-z0-9-]{0,62}", re.ASCII)
_GROUP_NAME = re.compile(r"[\w.()-]{1,90}")
_CURRENCY = re.compile(r"[A-Z]{3}", re.ASCII)

_ACCOUNT_TEMPLATE = "az account list [tenant-scoped projection]"
_ARG_RESOURCES_TEMPLATE = "az rest POST [ARM Resource Graph inventory query]"
_ARG_GROUPS_TEMPLATE = "az rest POST [ARM Resource Graph resource group query]"
_ARG_DEFENDER_TEMPLATE = "az rest POST [ARM Resource Graph Defender posture aggregates]"
_ARG_POLICY_TEMPLATE = "az rest POST [ARM Resource Graph Azure Policy aggregates]"
_ARM_RESOURCES_TEMPLATE = "az rest GET [ARM subscription resources page]"
_ARM_RBAC_TEMPLATE = "az rest GET [ARM subscription role assignments page]"
_APP_METRICS_TEMPLATE = "az rest GET [Azure Monitor App Service 30-day totals]"
_APP_PUBLISHING_TEMPLATE = "az rest GET [ARM App Service publishing policies, not credentials]"
_APP_STICKY_TEMPLATE = "az rest GET [ARM App Service sticky setting names, not values]"
_APP_DIAGNOSTICS_TEMPLATE = "az rest GET [ARM App Service diagnostic settings, not events]"
_APP_CONFIG_VERSION = "2025-03-01"
_APP_ID = re.compile(
    r"/subscriptions/([0-9a-f-]{36})/resourceGroups/[\w.()-]+/providers/"
    r"Microsoft\.Web/sites/[a-z0-9_-]+(?:/slots/[a-z0-9_-]+)?", re.I | re.ASCII,
)
_SECRET_LIKE = re.compile(r"secret|token|password|credential|connectionstring|accountkey|apikey|privatekey", re.I)
_APP_METRIC_FIELDS = {"Requests": "requests30d", "Http4xx": "http4xx30d", "Http5xx": "http5xx30d"}
_APP_METRIC_PROJECTION = ("value[].{name:name.value,error:errorCode,unit:unit,"
                          "series:timeseries[].{points:data[].{total:total}}}")
_COST_TEMPLATE = "az rest POST [ARM subscription Cost Management aggregate query]"
_COST_ROUTE = "/providers/Microsoft.CostManagement/query"
_COST_VERSION = "2025-03-01"
_NO_CONTENT = object()

_RESOURCE_QUERY = """Resources
| extend t = tolower(type)
| extend web = t in ('microsoft.web/sites', 'microsoft.web/sites/slots')
| order by id asc
| project id, type, location,
    httpsOnly = iff(t in ('microsoft.web/sites', 'microsoft.web/sites/slots'),
        tobool(properties.httpsOnly), bool(null)),
    minTlsVersion = case(
        t == 'microsoft.storage/storageaccounts', tostring(properties.minimumTlsVersion),
        t in ('microsoft.web/sites', 'microsoft.web/sites/slots'), tostring(properties.siteConfig.minTlsVersion),
        t == 'microsoft.sql/servers', tostring(properties.minimalTlsVersion),
        ''),
    publicNetworkAccess = iff(t in ('microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults',
        'microsoft.keyvault/managedhsms', 'microsoft.web/sites', 'microsoft.web/sites/slots',
        'microsoft.sql/servers', 'microsoft.documentdb/databaseaccounts', 'microsoft.containerregistry/registries',
        'microsoft.cognitiveservices/accounts', 'microsoft.search/searchservices'),
        tostring(properties.publicNetworkAccess), ''),
    allowBlobPublicAccess = iff(t == 'microsoft.storage/storageaccounts',
        tobool(properties.allowBlobPublicAccess), bool(null)),
    enablePurgeProtection = iff(t in ('microsoft.keyvault/vaults', 'microsoft.keyvault/managedhsms'),
        tobool(properties.enablePurgeProtection), bool(null)),
    zoneCount = array_length(zones),
    secureTransferRequired = iff(t == 'microsoft.storage/storageaccounts',
        tobool(properties.supportsHttpsTrafficOnly), bool(null)),
    minScmTlsVersion = iff(t in ('microsoft.web/sites', 'microsoft.web/sites/slots'),
        tostring(properties.siteConfig.scmMinTlsVersion), ''),
    remoteDebuggingEnabled = iff(t in ('microsoft.web/sites', 'microsoft.web/sites/slots'),
        tobool(properties.siteConfig.remoteDebuggingEnabled), bool(null)),
    ftpsState = iff(t in ('microsoft.web/sites', 'microsoft.web/sites/slots'),
        tostring(properties.siteConfig.ftpsState), ''),
    accessRestrictionCount = iff(web, array_length(properties.siteConfig.ipSecurityRestrictions), long(null)),
    scmRestrictionCount = iff(web, array_length(properties.siteConfig.scmIpSecurityRestrictions), long(null)),
    scmUsesMainRestrictions = iff(web, tobool(properties.siteConfig.scmIpSecurityRestrictionsUseMain), bool(null)),
    mainDefaultAction = iff(web, tostring(properties.siteConfig.ipSecurityRestrictionsDefaultAction), ''),
    scmDefaultAction = iff(web, tostring(properties.siteConfig.scmIpSecurityRestrictionsDefaultAction), ''),
    privateEndpointCount = iff(web, array_length(properties.privateEndpointConnections), long(null)),
    hostNameStateCount = iff(web, array_length(properties.hostNameSslStates), long(null)),
    clientCertEnabled = iff(web, tobool(properties.clientCertEnabled), bool(null)),
    http20Enabled = iff(web, tobool(properties.siteConfig.http20Enabled), bool(null)),
    corsAnyOrigin = iff(web and isnotnull(array_length(properties.siteConfig.cors.allowedOrigins)),
        tostring(properties.siteConfig.cors.allowedOrigins) contains '"*"', bool(null)),
    detailedErrorsEnabled = iff(web, tobool(properties.siteConfig.detailedErrorLoggingEnabled), bool(null)),
    httpLoggingEnabled = iff(web, tobool(properties.siteConfig.httpLoggingEnabled), bool(null)),
    alwaysOn = iff(web, tobool(properties.siteConfig.alwaysOn), bool(null)),
    autoHealEnabled = iff(web, tobool(properties.siteConfig.autoHealEnabled), bool(null)),
    workers = iff(web, tolong(properties.siteConfig.numberOfWorkers), long(null)),
    planId = iff(web, tostring(properties.serverFarmId), ''),
    planSku = iff(t == 'microsoft.web/serverfarms', tostring(sku.name), ''),
    planWorkers = iff(t == 'microsoft.web/serverfarms', tolong(sku.capacity), long(null)),
    zoneRedundant = iff(t == 'microsoft.web/serverfarms', tobool(properties.zoneRedundant), bool(null)),
    managedIdentityEnabled = iff(web and isnotempty(tostring(identity.type)), tostring(identity.type) != 'None', bool(null)),
    keyVaultReferenceIdentityConfigured = iff(web and isnotempty(tostring(properties.keyVaultReferenceIdentity)), true, bool(null)),
    healthCheckConfigured = iff(web and isnotempty(tostring(properties.siteConfig.healthCheckPath)), true, bool(null))
"""
_GROUP_QUERY = """ResourceContainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| order by id asc
| project id
"""
_DEFENDER_QUERY = """SecurityResources
| extend kind = tolower(type)
| where kind in ('microsoft.security/securescores', 'microsoft.security/pricings', 'microsoft.security/assessments',
    'microsoft.security/locations/alerts')
| where kind != 'microsoft.security/securescores' or name =~ 'ascScore'
| where kind != 'microsoft.security/locations/alerts' or tostring(properties.Status) =~ 'Active'
| extend state = case(kind == 'microsoft.security/pricings', tostring(properties.pricingTier),
    kind == 'microsoft.security/assessments', tostring(properties.status.code),
    kind == 'microsoft.security/locations/alerts', tostring(properties.Severity), '')
| where kind != 'microsoft.security/assessments' or state =~ 'Unhealthy'
| summarize amount = count(), score = max(100.0 * todouble(properties.score.percentage)) by kind, state
"""
_POLICY_QUERY = """PolicyResources
| extend kind = tolower(type)
| where kind in ('microsoft.authorization/policyassignments', 'microsoft.policyinsights/policystates')
| extend state = iff(kind == 'microsoft.policyinsights/policystates', tostring(properties.complianceState), '')
| summarize amount = count() by kind, state
"""
_ARM_RESOURCE_FIELDS = "{value:value[].{id:id,type:type,location:location},nextLink:nextLink}"
_ARM_RBAC_FIELDS = (
    "{value:value[].{scope:properties.scope,principalId:properties.principalId,"
    "principalType:properties.principalType,roleDefinitionId:properties.roleDefinitionId},nextLink:nextLink}"
)
_COST_FIELDS = (
    "properties.{columns:columns[].{name:name,type:type},nextLink:nextLink,"
    "rows:(length(columns || `[]`) == `3` && "
    "(contains(columns[].name || `[]`, 'PreTaxCost') || contains(columns[].name || `[]`, 'Cost')) && "
    "contains(columns[].name || `[]`, 'ResourceGroup') && "
    "(contains(columns[].name || `[]`, 'Currency') || contains(columns[].name || `[]`, 'BillingCurrency')) && rows)}"
)


def _guid(value: object) -> str | None:
    return value.lower() if isinstance(value, str) and _GUID.fullmatch(value) else None


def _azure_cli_command() -> list[str]:
    path = shutil.which("az")
    if path:
        if os.name != "nt" or Path(path).suffix.lower() == ".exe":
            return [path]
        # Windows MSI installs a batch shim. Avoid cmd.exe parsing of JSON and cursors.
        shim = Path(path)
        python = shim.parent.parent / "python.exe"
        if shim.name.lower() == "az.cmd" and shim.parent.name.lower() == "wbin" and python.is_file():
            return [str(python), "-I", "-B", "-X", "utf8", "-m", "azure.cli"]
    raise CollectionError(_AZ_UNAVAILABLE)


class _CliFailure(Exception):
    def __init__(self, status: str, *, login: bool = False):
        super().__init__(status)
        self.status = status
        self.login = login


class _Cli:
    def __init__(self, audit: list[str]):
        self.command = _azure_cli_command()
        self.audit = audit
        self.rest_successes = 0
        self.login_needed = False
        self.env = os.environ.copy()
        self.env.update(
            AZURE_LOGGING_ENABLE_LOG_FILE="no",
            AZURE_CORE_COLLECT_TELEMETRY="no",
            AZURE_EXTENSION_USE_DYNAMIC_INSTALL="no",
            PYTHONIOENCODING="utf-8",
        )
        self.env.pop("AZURE_CLI_DISABLE_CONNECTION_VERIFICATION", None)

    def _record(self, template: str, result: str) -> None:
        entry = f"{template}: {result}"
        self.audit.append(entry)
        logging.getLogger(__name__).info("%s", entry)

    def run(self, template: str, args: list[str]) -> object:
        try:
            result = subprocess.run(
                self.command + args + ["--only-show-errors", "--output", "json"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=self.env,
                timeout=90,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._record(template, "timeout")
            raise _CliFailure("not_collected") from None
        except (OSError, ValueError):
            self._record(template, "launch_failed")
            raise _CliFailure("not_collected") from None
        if result.returncode:
            stderr = result.stderr.lower()
            login = any(
                marker in stderr
                for marker in (b"az login", b"invalidauthenticationtoken", b"expiredauthenticationtoken",
                               b"interaction_required", b"authenticationfailed")
            )
            denied = any(
                marker in stderr
                for marker in (
                    b"authorizationfailed", b"authorizationpermissionmismatch", b"forbidden",
                    b"unauthorized", b"accessdenied", b"status code: 401", b"status code: 403",
                )
            )
            status = "needs_access" if (denied or login) else "not_collected"
            self._record(template, "login_required" if login else status)
            raise _CliFailure(status, login=login)
        if template == _COST_TEMPLATE and not result.stdout.strip():
            self._record(template, "no_content")
            return _NO_CONTENT
        try:
            data = json.loads(result.stdout)
        except (ValueError, RecursionError):
            self._record(template, "invalid_json")
            raise _CliFailure("not_collected") from None
        self._record(template, "ok")
        return data

    def rest(
        self, template: str, subscription: str, url: str, *, body: dict | None = None,
        projection: str | None = None,
    ) -> object:
        args = [
            "rest", "--method", "post" if body is not None else "get",
            "--url", url, "--subscription", subscription, "--resource", _ARM + "/",
        ]
        if body is not None:
            args.extend(["--body", json.dumps(body, separators=(",", ":"))])
        if projection is not None:
            args.extend(["--query", projection])
        try:
            response = self.run(template, args)
        except _CliFailure as exc:
            self.login_needed |= exc.login
            raise
        self.rest_successes += 1
        return response


def _subscriptions(cli: _Cli, tenant: str) -> tuple[list[str], bool]:
    # No --refresh: inspect the saved context. Support old and new cloud field names.
    selector = (
        f"[?(tenantId == '{tenant}' || tenantId == '{tenant.upper()}')"
        " && (cloudName || environmentName) == 'AzureCloud' && state == 'Enabled']."
        "{id:id,tenantId:tenantId,cloud:cloudName || environmentName,state:state}"
    )
    try:
        rows = cli.run(_ACCOUNT_TEMPLATE, ["account", "list", "--all", "--query", selector])
    except _CliFailure as exc:
        if exc.login:
            raise CollectionLogin(_LOGIN_ERROR) from None
        raise CollectionError(_ACCOUNT_ERROR) from None
    if not isinstance(rows, list):
        raise CollectionError(_ACCOUNT_ERROR)
    ids = set()
    skipped = False
    for row in rows:
        if (
            not isinstance(row, dict) or _guid(row.get("tenantId")) != tenant
            or row.get("cloud") != "AzureCloud" or row.get("state") != "Enabled"
        ):
            continue
        subscription = _guid(row.get("id"))
        if subscription is None:
            skipped = True
        else:
            ids.add(subscription)
    if not ids:
        raise CollectionLogin(_NO_SUBSCRIPTIONS)
    return sorted(ids), skipped


def _arg_pages(cli: _Cli, subscription: str, template: str, query: str) -> tuple[list, str]:
    options = {"$top": 1000, "resultFormat": "objectArray", "allowPartialScopes": False}
    body = {"subscriptions": [subscription], "query": query, "options": options}
    rows = []
    seen = set()
    total = None
    consistent = True
    for page_number in range(_MAX_PAGES):
        try:
            page = cli.rest(template, subscription, _ARG_URL, body=body)
        except _CliFailure as exc:
            return rows, "partial" if page_number else exc.status
        if not isinstance(page, dict) or not isinstance(page.get("data"), list):
            return rows, "partial" if page_number else "not_collected"
        data = page["data"]
        rows.extend(data)
        count = page.get("count")
        page_total = page.get("totalRecords")
        if (
            type(count) is not int or count != len(data) or type(page_total) is not int
            or page_total < len(rows) or (total is not None and total != page_total)
        ):
            consistent = False
        total = page_total
        token = page.get("$skipToken")
        if token is None or token == "":
            truncated = page.get("resultTruncated")
            complete = consistent and total == len(rows) and (
                truncated is False or (isinstance(truncated, str) and truncated.lower() == "false")
            )
            return rows, "complete" if complete else "partial"
        if (
            not isinstance(token, str) or len(token) > 4096 or not token.isascii()
            or not token.isprintable() or token in seen
        ):
            break
        seen.add(token)
        options["$skipToken"] = token
    return rows, "partial"


def _continuation(
    value: object, path: str, version: str, *, alternate_versions: tuple[str, ...] = (),
) -> str | None:
    if (
        not isinstance(value, str) or len(value) > 8192 or not value.isascii()
        or any(c.isspace() for c in value) or "\\" in value or "#" in value
    ):
        return None
    try:
        parts = urlsplit(value)
        pairs = parse_qsl(parts.query, strict_parsing=True, max_num_fields=2)
    except ValueError:
        return None
    if (
        parts.scheme != "https" or parts.netloc.lower() != "management.azure.com"
        or parts.path.lower() != path.lower() or len(pairs) != 2
    ):
        return None
    versions = [v for k, v in pairs if k.lower() == "api-version"]
    cursors = [(k, v) for k, v in pairs if k.lower() in ("$skiptoken", "skiptoken", "$skip")]
    if (
        len(versions) != 1 or versions[0] not in (version, *alternate_versions)
        or len(cursors) != 1 or not cursors[0][1].isascii() or not cursors[0][1].isprintable()
    ):
        return None
    return _ARM + path + "?" + urlencode([("api-version", versions[0]), cursors[0]])


def _arm_pages(
    cli: _Cli, subscription: str, template: str, route: str, version: str, projection: str,
) -> tuple[list, str]:
    path = f"/subscriptions/{subscription}{route}"
    url = f"{_ARM}{path}?api-version={version}"
    seen = {url}
    rows = []
    for page_number in range(_MAX_PAGES):
        try:
            page = cli.rest(template, subscription, url, projection=projection)
        except _CliFailure as exc:
            return rows, "partial" if page_number else exc.status
        if not isinstance(page, dict) or not isinstance(page.get("value"), list):
            return rows, "partial" if page_number else "not_collected"
        rows.extend(page["value"])
        next_link = page.get("nextLink")
        if next_link is None or next_link == "":
            return rows, "complete"
        url = _continuation(next_link, path, version)
        if url is None or url in seen:
            break
        seen.add(url)
    return rows, "partial"


def _scope(value: object, subscription: str) -> tuple[str, str] | None:
    """Recognize resource, group and subscription scopes without using them as URLs."""
    if (
        not isinstance(value, str) or len(value) > 8192 or not value.isprintable()
        or any(c in value for c in "\\?#")
    ):
        return None
    parts = value.split("/")
    if (
        len(parts) < 3 or parts[0] != "" or parts[1].lower() != "subscriptions"
        or _guid(parts[2]) != subscription or any(p in ("", ".", "..") for p in parts[3:])
    ):
        return None
    tail = parts[3:]
    kind = "subscription"
    if len(tail) >= 2 and tail[0].lower() == "resourcegroups":
        kind = "group"
        tail = tail[2:]
    if tail:
        if len(tail) < 4 or len(tail) % 2 or tail[0].lower() != "providers":
            return None
        kind = "resource"
    return value, kind


def _token(value: object, choices: dict[str, str]) -> str | None:
    return choices.get(value.lower()) if isinstance(value, str) else None


_TLS = {
    spelling: version
    for version in ("1.0", "1.1", "1.2", "1.3")
    for spelling in (version, "tls" + version.replace(".", "_"))
}
_PNA = {"enabled": "Enabled", "disabled": "Disabled", "securedbyperimeter": "SecuredByPerimeter"}
_FTPS = {"allallowed": "AllAllowed", "ftpsonly": "FtpsOnly", "disabled": "Disabled"}
_PRINCIPALS = {
    s.lower(): s for s in ("User", "Group", "ServicePrincipal", "ForeignGroup", "Device", "Unknown")
}
_BOOLEAN_FIELDS = (
    "httpsOnly", "allowBlobPublicAccess", "enablePurgeProtection", "secureTransferRequired",
    "remoteDebuggingEnabled", "scmUsesMainRestrictions", "clientCertEnabled", "http20Enabled", "corsAnyOrigin",
    "detailedErrorsEnabled", "httpLoggingEnabled", "alwaysOn", "autoHealEnabled", "zoneRedundant",
    "managedIdentityEnabled", "keyVaultReferenceIdentityConfigured", "healthCheckConfigured",
)
_RESOURCE_COUNTS = ("zoneCount", "accessRestrictionCount", "scmRestrictionCount", "privateEndpointCount",
                    "hostNameStateCount", "workers", "planWorkers")


def _resource(row: object, subscription: str, source: str) -> dict | None:
    if not isinstance(row, dict):
        return None
    scope = _scope(row.get("id"), subscription)
    kind = row.get("type")
    if scope is None or scope[1] != "resource" or not isinstance(kind, str):
        return None
    kind = kind.lower()
    if len(kind) > 512 or not _TYPE.fullmatch(kind):
        return None
    location = row.get("location")
    location = location.lower() if isinstance(location, str) else ""
    item = {
        "id": scope[0], "type": kind, "location": location if _LOCATION.fullmatch(location) else None,
        "source": source,
    }
    if source == "ARG":
        for field in _BOOLEAN_FIELDS:
            value = row.get(field)
            item[field] = value if type(value) is bool else None
        item["minTlsVersion"] = _token(row.get("minTlsVersion"), _TLS)
        item["minScmTlsVersion"] = _token(row.get("minScmTlsVersion"), _TLS)
        item["publicNetworkAccess"] = _token(row.get("publicNetworkAccess"), _PNA)
        item["ftpsState"] = _token(row.get("ftpsState"), _FTPS)
        for field in _RESOURCE_COUNTS:
            value = row.get(field)
            item[field] = value if type(value) is int and value >= 0 else None
        for field in ("mainDefaultAction", "scmDefaultAction"):
            item[field] = _token(row.get(field), {"allow": "Allow", "deny": "Deny"})
        plan = _scope(row.get("planId"), subscription)
        if plan and plan[1] == "resource" and re.fullmatch(
            r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Web/serverfarms/[^/]+",
            plan[0], re.I,
        ):
            item["planId"] = plan[0]
        sku = row.get("planSku")
        if isinstance(sku, str) and len(sku) <= 16:
            item["planSku"] = sku.upper()
    return item


def _assignment(row: object, subscription: str) -> dict | None:
    if not isinstance(row, dict):
        return None
    scope = _scope(row.get("scope"), subscription)
    principal = _guid(row.get("principalId"))
    role_value = row.get("roleDefinitionId")
    role = _guid(role_value)
    if role is None and isinstance(role_value, str):
        pieces = role_value.split("/")
        if pieces[0] == "" and [s.lower() for s in pieces[-4:-1]] == [
            "providers", "microsoft.authorization", "roledefinitions",
        ]:
            role = _guid(pieces[-1])
    if scope is None or principal is None or role is None:
        return None
    return {
        "scope": scope[0], "principalId": principal,
        "principalType": _token(row.get("principalType"), _PRINCIPALS) or "Unknown",
        "roleDefinitionId": role,
    }


def _previous_month(today: date) -> dict[str, str]:
    last_day = today.replace(day=1) - timedelta(days=1)
    return {
        "from": f"{last_day.replace(day=1).isoformat()}T00:00:00Z",
        "to": f"{last_day.isoformat()}T23:59:59Z",
    }


def _cost_columns(columns: object) -> tuple[int, int, int] | None:
    if not isinstance(columns, list) or len(columns) != 3:
        return None
    names = {
        ("PreTaxCost", "Number"): "amount",
        ("Cost", "Number"): "amount",
        ("ResourceGroup", "String"): "group",
        ("Currency", "String"): "currency",
        ("BillingCurrency", "String"): "currency",
    }
    positions = {}
    for index, column in enumerate(columns):
        if not isinstance(column, dict):
            return None
        name, kind = column.get("name"), column.get("type")
        if not isinstance(name, str) or not isinstance(kind, str):
            return None
        field = names.get((name, kind))
        if field is None or field in positions:
            return None
        positions[field] = index
    return positions["amount"], positions["group"], positions["currency"]


def _cost_row(
    row: object, columns: tuple[int, int, int], subscription: str, groups: dict[str, str],
) -> dict | None:
    if not isinstance(row, list) or len(row) != 3:
        return None
    value, name, currency = (row[i] for i in columns)
    if type(value) not in (int, float) or not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        return None
    try:
        if not math.isfinite(value):
            return None
    except OverflowError:
        return None
    if name is None or name == "":
        group = None
    elif isinstance(name, str) and _GROUP_NAME.fullmatch(name) and not name.endswith("."):
        group_id = f"/subscriptions/{subscription}/resourceGroups/{name}"
        group = groups.get(group_id.casefold(), group_id)
    else:
        return None
    return {"subscriptionId": subscription, "group": group, "amount": value, "currency": currency}


def _cost_pages(
    cli: _Cli, subscription: str, period: dict[str, str], groups: dict[str, str],
) -> tuple[list[dict], str]:
    path = f"/subscriptions/{subscription}{_COST_ROUTE}"
    url = f"{_ARM}{path}?api-version={_COST_VERSION}"
    body = {
        "type": "ActualCost",
        "timeframe": "Custom",
        "timePeriod": period,
        "dataset": {
            "granularity": "None",
            "aggregation": {"totalCost": {"name": "PreTaxCost", "function": "Sum"}},
            "grouping": [{"type": "Dimension", "name": "ResourceGroup"}],
        },
    }
    seen_urls = {url}
    seen_groups = set()
    results = []
    consistent = True
    for page_number in range(_MAX_PAGES):
        try:
            page = cli.rest(_COST_TEMPLATE, subscription, url, body=body, projection=_COST_FIELDS)
        except _CliFailure as exc:
            return results, "partial" if page_number else exc.status
        if page is _NO_CONTENT:  # The documented 204 for a query with no data.
            return results, "partial" if page_number else "complete"
        positions = _cost_columns(page.get("columns")) if isinstance(page, dict) else None
        if positions is None or not isinstance(page.get("rows"), list):
            return results, "partial" if page_number else "not_collected"
        for row in page["rows"]:
            item = _cost_row(row, positions, subscription, groups)
            if item is None:
                consistent = False
                continue
            key = ((item["group"] or "").casefold(), item["currency"])
            if key in seen_groups:
                consistent = False
                continue
            seen_groups.add(key)
            results.append(item)
        next_link = page.get("nextLink")
        if next_link is None or next_link == "":
            return results, "complete" if consistent else "partial"
        # Microsoft documents Cost Query links using the older stable version.
        url = _continuation(next_link, path, _COST_VERSION, alternate_versions=("2021-10-01",))
        if url is None or url in seen_urls:
            break
        seen_urls.add(url)
    return results, "partial"


def _status(states: list[str]) -> str:
    return states[0] if all(state == states[0] for state in states) else "partial"


_POSTURE_KIND = {
    ("microsoft.security/securescores", ""): "secure_score_percent",
    ("microsoft.security/pricings", "free"): "defender_free",
    ("microsoft.security/pricings", "standard"): "defender_standard",
    ("microsoft.security/assessments", "unhealthy"): "defender_unhealthy",
    **{("microsoft.security/locations/alerts", severity): "defender_alert_" + severity
       for severity in ("low", "medium", "high", "informational")},
    ("microsoft.authorization/policyassignments", ""): "policy_assignments",
    **{("microsoft.policyinsights/policystates", state): "policy_" + state
       for state in ("compliant", "noncompliant", "conflict", "exempt", "unknown", "notstarted", "protected")},
}


def _posture(cli, sub, template, query):
    rows, status = _arg_pages(cli, sub, template, query)
    if not rows:
        return [], "not_collected" if status == "complete" else status
    result = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        kind, state = row.get("kind"), row.get("state")
        if not isinstance(kind, str) or not isinstance(state, str):
            continue
        metric = _POSTURE_KIND.get((kind.lower(), state.lower()))
        if not metric:
            continue
        value = row.get("score") if metric == "secure_score_percent" else row.get("amount")
        if type(value) not in (int, float) or not 0 <= value <= (100 if metric == "secure_score_percent" else 10**12):
            continue
        result.append({"subscriptionId": sub, "metric": metric, "value": value})
    return result, status if len(result) == len(rows) else "partial"


def _app_subscription(resource_id: str) -> str | None:
    path = _APP_ID.fullmatch(resource_id) if len(resource_id) <= 1024 else None
    sub = _guid(path[1]) if path else None
    return sub if sub and _scope(resource_id, sub) is not None else None


def _app_configuration(cli: _Cli, app: dict) -> str:
    resource_id = app["id"]
    sub = _app_subscription(resource_id)
    if not sub:
        return "not_collected"
    base = _ARM + resource_id
    states = []
    try:
        body = cli.rest(
            _APP_PUBLISHING_TEMPLATE, sub, f"{base}/basicPublishingCredentialsPolicies?api-version={_APP_CONFIG_VERSION}",
            projection="{policies:value[].{kind:name,allow:properties.allow},nextLink:nextLink}",
        )
    except _CliFailure as exc:
        states.append(exc.status)
    else:
        policies = body.get("policies") if isinstance(body, dict) else None
        expected = {"ftp": "ftpBasicAuthEnabled", "scm": "scmBasicAuthEnabled"}
        observed, duplicates = {}, set()
        if isinstance(policies, list):
            for entry in policies:
                if not isinstance(entry, dict):
                    continue
                kind = entry.get("kind")
                name = _token(kind.rsplit("/", 1)[-1], expected) if isinstance(kind, str) else None
                if name is None or type(entry.get("allow")) is not bool:
                    continue
                if name in observed:
                    duplicates.add(name)
                observed[name] = entry["allow"]
        accepted = {field: value for field, value in observed.items() if field not in duplicates}
        app.update(accepted)
        states.append("complete" if len(accepted) == 2 and not body.get("nextLink") else "partial" if accepted else "not_collected")
    try:
        diagnostics = cli.rest(
            _APP_DIAGNOSTICS_TEMPLATE, sub, f"{base}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview",
            projection="{settingCount:length(value),nextLink:nextLink}",
        )
    except _CliFailure as exc:
        states.append(exc.status)
    else:
        count = diagnostics.get("settingCount") if isinstance(diagnostics, dict) else None
        if type(count) is int and count >= 0 and not diagnostics.get("nextLink"):
            app["diagnosticsConfigured"] = count > 0
            states.append("complete")
        else:
            states.append("not_collected")
    if app["type"] == "microsoft.web/sites":
        try:
            sticky = cli.rest(
                _APP_STICKY_TEMPLATE, sub, f"{base}/config/slotConfigNames?api-version={_APP_CONFIG_VERSION}",
                projection="properties.appSettingNames",
            )
        except _CliFailure as exc:
            states.append(exc.status)
        else:
            if isinstance(sticky, list) and all(isinstance(name, str) for name in sticky):
                app["stickySettingCount"] = len(sticky)
                app["secretLikeStickySettingCount"] = sum(bool(_SECRET_LIKE.search(re.sub("[_.-]", "", name))) for name in sticky)
                states.append("complete")
            else:
                states.append("not_collected")
    return _status(states)


def _app_metrics(cli: _Cli, app: dict, timespan: str) -> str:
    resource_id = app["id"]
    sub = _app_subscription(resource_id)
    if not sub:
        return "not_collected"
    params = urlencode({
        "api-version": "2023-10-01", "interval": "FULL", "timespan": timespan,
        "metricnames": ",".join(_APP_METRIC_FIELDS), "aggregation": "Total",
        "metricnamespace": app["type"],
    })
    try:
        series = cli.rest(_APP_METRICS_TEMPLATE, sub, f"{_ARM}{resource_id}/providers/Microsoft.Insights/metrics?{params}",
                          projection=_APP_METRIC_PROJECTION)
    except _CliFailure as exc:
        return exc.status
    if not isinstance(series, list):
        return "not_collected"
    observed = {}
    seen = set()
    for metric in series:
        if not isinstance(metric, dict):
            continue
        name, points = metric.get("name"), metric.get("series")
        if not isinstance(name, str) or name not in _APP_METRIC_FIELDS:
            continue
        field = _APP_METRIC_FIELDS[name]
        if field in seen:
            observed.pop(field, None)
            continue
        seen.add(field)
        if (metric.get("error") not in (None, "Success") or metric.get("unit") != "Count" or
                not isinstance(points, list) or len(points) != 1 or not isinstance(points[0], dict)):
            continue
        observed_points = points[0].get("points")
        if not isinstance(observed_points, list) or len(observed_points) != 1 or not isinstance(observed_points[0], dict):
            continue
        total = observed_points[0].get("total")
        if type(total) in (float, int) and 0 <= total <= 10**12 and total == int(total):
            observed[field] = int(total)
    app.update(observed)
    return "complete" if len(observed) == len(_APP_METRIC_FIELDS) else "partial" if observed else "not_collected"


def collect(tenant_id: str, subscription_id: str | None = None) -> dict:
    """Collect configuration after the caller has confirmed read-only access.

    Identifiers in the returned dict must remain in memory until the caller
    has applied its redaction/pseudonymization policy.
    """
    tenant = _guid(tenant_id)
    if tenant is None:
        raise CollectionError(_BAD_TENANT)
    selected = _guid(subscription_id) if subscription_id is not None else None
    if subscription_id is not None and selected is None:
        raise CollectionError("The pilot requires a valid subscription GUID.")
    audit: list[str] = []
    cli = _Cli(audit)
    subscriptions, bad_account = _subscriptions(cli, tenant)
    if selected:
        if selected not in subscriptions:
            raise CollectionError("The pilot subscription is not visible to the Azure CLI session in the selected tenant.")
        subscriptions = [selected]
    groups: dict[str, str] = {}
    arg: dict[str, dict] = {}
    arm: dict[str, dict] = {}
    assignments: dict[tuple[str, str, str], dict] = {}
    arg_states, group_states, arm_states, rbac_states = [], [], [], []

    for sub in subscriptions:
        rows, status = _arg_pages(cli, sub, _ARG_RESOURCES_TEMPLATE, _RESOURCE_QUERY)
        for row in rows:
            item = _resource(row, sub, "ARG")
            if item is None:
                status = "partial"
                continue
            key = item["id"].casefold()
            if key in arg:
                status = "partial"
            arg[key] = item
        arg_states.append(status)

        rows, status = _arg_pages(cli, sub, _ARG_GROUPS_TEMPLATE, _GROUP_QUERY)
        for row in rows:
            scope = _scope(row.get("id"), sub) if isinstance(row, dict) else None
            if scope is None or scope[1] != "group":
                status = "partial"
                continue
            key = scope[0].casefold()
            if key in groups:
                status = "partial"
            groups[key] = scope[0]
        group_states.append(status)

    for sub in subscriptions:
        rows, status = _arm_pages(
            cli, sub, _ARM_RESOURCES_TEMPLATE, "/resources", "2021-04-01", _ARM_RESOURCE_FIELDS,
        )
        for row in rows:
            item = _resource(row, sub, "ARM")
            if item is None:
                status = "partial"
                continue
            key = item["id"].casefold()
            if key in arm:
                status = "partial"
            arm[key] = item
        arm_states.append(status)

        rows, status = _arm_pages(
            cli, sub, _ARM_RBAC_TEMPLATE, "/providers/Microsoft.Authorization/roleAssignments",
            "2022-04-01", _ARM_RBAC_FIELDS,
        )
        for row in rows:
            item = _assignment(row, sub)
            if item is None:
                status = "partial"
                continue
            assignments[(item["scope"].casefold(), item["principalId"], item["roleDefinitionId"])] = item
        rbac_states.append(status)

    if cli.login_needed and not cli.rest_successes:
        raise CollectionLogin(_LOGIN_ERROR)

    costs = []
    cost_states = []
    period = _previous_month(datetime.now(timezone.utc).date())
    for sub in subscriptions:
        entries, status = _cost_pages(cli, sub, period, groups)
        costs.extend(entries)
        cost_states.append(status)

    arg_status, arm_status = _status(arg_states), _status(arm_states)
    if arg_status == arm_status == "complete":
        check_status = "complete" if arg.keys() == arm.keys() else "partial"
    elif arg_status == arm_status == "needs_access":
        check_status = "needs_access"
    elif "complete" in (arg_status, arm_status) or "partial" in (arg_status, arm_status):
        check_status = "partial"
    else:
        check_status = "not_collected"

    posture = []
    defender_states, policy_states = [], []
    for sub in subscriptions:
        defender, defender_state = _posture(cli, sub, _ARG_DEFENDER_TEMPLATE, _DEFENDER_QUERY)
        policy, policy_state = _posture(cli, sub, _ARG_POLICY_TEMPLATE, _POLICY_QUERY)
        posture.extend(defender + policy)
        defender_states.append(defender_state)
        policy_states.append(policy_state)
    resources = [arg[key] if key in arg else arm[key] for key in sorted(arg.keys() | arm.keys())]
    applications = [item for item in resources if item["type"] in ("microsoft.web/sites", "microsoft.web/sites/slots")]
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=30)
    timespan = f"{start:%Y-%m-%dT%H:%M:%SZ}/{end:%Y-%m-%dT%H:%M:%SZ}"
    checks = [_app_configuration(cli, item) for item in applications[:100]]
    config_status = _status(checks + ["not_collected"] * (len(applications) > 100)) if checks else "not_collected"
    metrics = [_app_metrics(cli, item, timespan) for item in applications[:100]]
    metrics_status = _status(metrics + ["not_collected"] * (len(applications) > 100)) if metrics else "not_collected"
    coverage = [
        ("scope", "partial" if selected else "complete", "Pilot restricted to one explicitly selected subscription."
         if selected else "Review scope is the enabled subscriptions visible to the dedicated CLI session."),
        ("subscriptions", "partial", "Enabled public-cloud subscriptions cached in Azure CLI; may be stale."
         if not bad_account else "Azure CLI cache only; malformed subscription entries were skipped."),
        ("resource_groups", _status(group_states), "Resource groups visible to Resource Graph."),
        ("arg_inventory", arg_status, "Resource Graph inventory within visible, selected subscriptions."),
        ("arm_inventory", arm_status, "Generic ARM list within visible, selected subscriptions."),
        ("inventory_cross_check", check_status, "Compares visible resource IDs, not tenant-wide coverage."),
        ("configuration", "partial" if arg_status == "complete" else arg_status,
         "Allowlisted Resource Graph aliases only; null means unavailable or not applicable."),
        ("rbac", _status(rbac_states), "Visible subscription and descendant assignments only; no directory lookup."),
        ("app_arm_detail", config_status, "App Service FTP/SCM policies, sticky-name counts and diagnostic setting existence; up to 100 observed sites/slots."),
        ("metrics", metrics_status, "Azure Monitor 30-day request and HTTP error totals only; at most 100 observed sites/slots."),
        ("defender", _status(defender_states), "Visible Defender scores, plan tiers, unhealthy assessments and active alert counts. No alert payloads."),
        ("policy", _status(policy_states), "Visible Azure Policy assignments and policy-state row counts, not counts of unique resources."),
        ("costs", _status(cost_states),
         "Cost Management actual costs by resource group and currency for the previous UTC calendar month."),
    ]
    return {
        "subscriptions": subscriptions,
        "groups": [groups[key] for key in sorted(groups)],
        "resources": resources,
        "arm_ids": [arm[key]["id"] for key in sorted(arm)],
        "rbac": [assignments[key] for key in sorted(assignments)],
        "posture": posture,
        "costs": costs,
        "coverage": [{"area": area, "status": status, "detail": detail} for area, status, detail in coverage],
        "audit": audit,
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, _USAGE_ERROR + "\n")


def _output_directory(value: str) -> Path:
    try:
        output = Path(value).absolute()
        if os.name == "nt":
            from ctypes import windll

            root = output.anchor
            if root.startswith("\\\\") or windll.kernel32.GetDriveTypeW(root) in (0, 1, 4):
                raise CollectionError(_OUTPUT_ERROR)
        # Match the builder's directory policy without resolving away junctions or symlinks.
        for directory in reversed((output, *output.parents)):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or (
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise CollectionError(_OUTPUT_ERROR)
        return output
    except (OSError, ValueError):
        raise CollectionError(_OUTPUT_ERROR) from None


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="azure_collect.py", allow_abbrev=False, description=(
        "Build a redacted Azure inventory report. Sign in separately with az login --tenant <GUID>."
    ))
    parser.add_argument("--tenant-id", required=True, metavar="GUID")
    parser.add_argument("--subscription-id", metavar="GUID", help="Limit review to a single pilot subscription.")
    parser.add_argument("--confirm-read-only", action="store_true")
    parser.add_argument("--output", required=True, metavar="DIRECTORY", help="Existing approved local directory.")
    args = parser.parse_args(argv)
    try:
        if not args.confirm_read_only:
            raise CollectionError(_CONFIRM_ERROR)
        if _guid(args.tenant_id) is None:
            raise CollectionError(_BAD_TENANT)
        output = _output_directory(args.output)
        report = collect(args.tenant_id, subscription_id=args.subscription_id) if args.subscription_id else collect(args.tenant_id)
    except CollectionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        from build import run
        from evidence import EvidenceError

        snapshot, _ = run(output, blob=None, live=report)
    except (EvidenceError, OSError):
        print(_BUILD_ERROR, file=sys.stderr)
        return 1
    print(f"Local snapshot: {snapshot}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
