import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from evidence import EvidenceError
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import azure_collect as collector


TENANT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SUB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
OTHER = "cccccccc-cccc-cccc-cccc-cccccccccccc"
PRINCIPAL = "dddddddd-dddd-dddd-dddd-dddddddddddd"
ROLE = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
SCOPE = f"/subscriptions/{SUB}"
GROUP = f"{SCOPE}/resourceGroups/sample"
STORE_TYPE = "Microsoft.Storage/storageAccounts"
STORE = f"{GROUP}/providers/{STORE_TYPE}/first"
SECOND = f"{GROUP}/providers/{STORE_TYPE}/second"
ARM_ONLY = f"{GROUP}/providers/{STORE_TYPE}/arm-only"
ARM_LIST = f"https://management.azure.com{SCOPE}/resources?api-version=2021-04-01"
ACCOUNT = {"id": SUB, "tenantId": TENANT, "cloud": "AzureCloud", "state": "Enabled"}


def argv_value(args, name):
    return args[args.index(name) + 1]


def response(data=None, *, error=None):
    if error is not None:
        return subprocess.CompletedProcess([], 1, b"", error.encode())
    return subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b"")


def arg_response(rows, *, total=None, token=None, truncated="false"):
    data = {"data": rows, "count": len(rows), "totalRecords": len(rows) if total is None else total,
            "resultTruncated": truncated}
    if token is not None:
        data["$skipToken"] = token
    return response(data)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        executable = patch.object(collector, "_azure_cli_command", return_value=["fake-az.exe"])
        self.addCleanup(executable.stop)
        executable.start()
        runner = patch.object(collector.subprocess, "run")
        self.addCleanup(runner.stop)
        self.runner = runner.start()

    def test_scoped_pagination_projection_and_cross_check(self):
        def fake_az(args, **kwargs):
            self.assertEqual(kwargs["env"]["AZURE_LOGGING_ENABLE_LOG_FILE"], "no")
            self.assertEqual(kwargs["env"]["AZURE_CORE_COLLECT_TELEMETRY"], "no")
            if args[1:3] == ["account", "list"]:
                self.assertIn(TENANT, argv_value(args, "--query"))
                self.assertNotIn("--refresh", args)
                return response([
                    ACCOUNT, ACCOUNT, {**ACCOUNT, "id": OTHER, "tenantId": OTHER},
                    {**ACCOUNT, "id": OTHER, "cloud": "AzureUSGovernment"},
                ])
            self.assertEqual(argv_value(args, "--subscription"), SUB)
            url = argv_value(args, "--url")
            parts = urlsplit(url)
            self.assertEqual((parts.scheme, parts.netloc), ("https", "management.azure.com"))
            if argv_value(args, "--method") == "post":
                body = json.loads(argv_value(args, "--body"))
                if parts.path.endswith("/providers/Microsoft.CostManagement/query"):
                    self.assertEqual(body["dataset"]["granularity"], "None")
                    self.assertEqual(body["dataset"]["grouping"], [{"type": "Dimension", "name": "ResourceGroup"}])
                    return response({
                        "columns": [{"name": "PreTaxCost", "type": "Number"}, {"name": "ResourceGroup", "type": "String"},
                                    {"name": "Currency", "type": "String"}],
                        "rows": [[18.25, GROUP.rsplit("/", 1)[-1], "EUR"], [-1, None, "EUR"]],
                    })
                self.assertEqual(parts.path, "/providers/Microsoft.ResourceGraph/resources")
                self.assertEqual(body["subscriptions"], [SUB])
                query = body["query"]
                if query.startswith("SecurityResources"):
                    self.assertNotIn("ResourceIdentifiers", query)
                    return arg_response([
                        {"kind": "microsoft.security/securescores", "state": "", "score": 85},
                        {"kind": "microsoft.security/locations/alerts", "state": "High", "amount": 2},
                    ])
                if query.startswith("PolicyResources"):
                    return arg_response([{"kind": "microsoft.policyinsights/policystates", "state": "NonCompliant", "amount": 12}])
                if query.startswith("ResourceContainers"):
                    self.assertTrue(query.endswith("| project id\n"))
                    return arg_response([{"id": GROUP, "name": "do not retain"}])
                self.assertIn("| project id, type, location", query)
                if body["options"].get("$skipToken"):
                    self.assertEqual(body["options"]["$skipToken"], "opaque-arg-cursor")
                    return arg_response([{"id": SECOND, "type": STORE_TYPE, "location": "westus"}], total=2)
                row = {"id": STORE, "type": STORE_TYPE, "location": "EastUS", "minTlsVersion": "TLS1_2",
                       "allowBlobPublicAccess": False, "secureTransferRequired": True,
                       "publicNetworkAccess": "SecureByPerimeter", "unexpected": "do not retain"}
                return arg_response([row], total=2, token="opaque-arg-cursor", truncated="true")
            assets = lambda value: {"id": value, "type": STORE_TYPE, "location": "eastus"}
            self.assertIn("--query", args)
            if parts.path.endswith("/roleAssignments"):
                return response({"value": [
                    {"scope": GROUP, "principalId": PRINCIPAL, "principalType": "serviceprincipal",
                     "roleDefinitionId": f"{SCOPE}/providers/Microsoft.Authorization/roleDefinitions/{ROLE}",
                     "email": "do not retain"},
                ], "nextLink": None})
            if url == ARM_LIST:
                return response({"value": [assets(STORE.upper()), assets(SECOND)],
                                 "nextLink": ARM_LIST + "&%24skiptoken=opaque-arm-cursor"})
            self.assertTrue(url.endswith("&%24skiptoken=opaque-arm-cursor"))
            return response({"value": [{**assets(ARM_ONLY), "enablePurgeProtection": True}], "nextLink": None})

        self.runner.side_effect = fake_az
        data = collector.collect(TENANT)
        self.assertEqual(data["subscriptions"], [SUB])
        self.assertEqual(data["groups"], [GROUP])
        self.assertEqual({value.lower() for value in data["arm_ids"]}, {v.lower() for v in (STORE, SECOND, ARM_ONLY)})
        resources = {r["id"]: r for r in data["resources"]}
        self.assertEqual(resources[STORE]["source"], "ARG")
        self.assertEqual(resources[STORE]["minTlsVersion"], "1.2")
        self.assertIs(resources[STORE]["allowBlobPublicAccess"], False)
        self.assertIsNone(resources[STORE]["publicNetworkAccess"])
        self.assertEqual(set(resources[ARM_ONLY]), {"id", "type", "location", "source"})
        self.assertEqual(resources[ARM_ONLY]["source"], "ARM")
        self.assertEqual(data["rbac"], [{
            "scope": GROUP, "principalId": PRINCIPAL, "principalType": "ServicePrincipal", "roleDefinitionId": ROLE,
        }])
        self.assertNotIn("do not retain", json.dumps(data))
        statuses = {c["area"]: c["status"] for c in data["coverage"]}
        self.assertEqual(statuses["arg_inventory"], "complete")
        self.assertEqual(statuses["arm_inventory"], "complete")
        self.assertEqual(statuses["inventory_cross_check"], "partial")
        self.assertEqual(statuses["costs"], "complete")
        self.assertEqual(data["costs"], [
            {"subscriptionId": SUB, "group": GROUP, "amount": 18.25, "currency": "EUR"},
            {"subscriptionId": SUB, "group": None, "amount": -1, "currency": "EUR"},
        ])
        self.assertEqual(data["posture"], [
            {"subscriptionId": SUB, "metric": "secure_score_percent", "value": 85},
            {"subscriptionId": SUB, "metric": "defender_alert_high", "value": 2},
            {"subscriptionId": SUB, "metric": "policy_noncompliant", "value": 12},
        ])
        self.assertEqual(len(data["audit"]), self.runner.call_count)
        for sensitive in (TENANT, SUB, PRINCIPAL, ROLE, "opaque-", "https://"):
            self.assertNotIn(sensitive, "\n".join(data["audit"]))

    def test_rejects_foreign_continuation_and_keeps_partial_data(self):
        row = {"id": STORE, "type": STORE_TYPE, "location": "eastus"}
        self.runner.side_effect = [
            response([ACCOUNT]),
            arg_response([row], total=99, truncated="true"),
            arg_response([]),
            response({"value": [row], "nextLink": ARM_LIST.replace(SUB, OTHER) + "&$skiptoken=hidden"}),
            response(error=f"AuthorizationFailed: private text {PRINCIPAL}"),
            response(error="AuthorizationFailed"),
            arg_response([]),
            arg_response([{"kind": "microsoft.policyinsights/policystates", "state": "Unknown", "amount": 1}]),
        ]
        data = collector.collect(TENANT)
        self.assertEqual(self.runner.call_count, 8)
        self.assertEqual(data["arm_ids"], [STORE])
        statuses = {c["area"]: c["status"] for c in data["coverage"]}
        self.assertEqual(statuses["arg_inventory"], "partial")
        self.assertEqual(statuses["arm_inventory"], "partial")
        self.assertEqual(statuses["rbac"], "needs_access")
        self.assertEqual(statuses["defender"], "not_collected")
        self.assertNotIn("private text", json.dumps(data))
        for url in (ARM_LIST.replace("management.azure.com", "outside.invalid"), ARM_LIST + "&x=yes",
                    ARM_LIST.replace("management.azure.com", "management.azure.com@outside.invalid")):
            path = urlsplit(ARM_LIST).path
            self.assertIsNone(collector._continuation(url, path, "2021-04-01"))

    def test_missing_login_uses_fixed_error(self):
        self.runner.side_effect = [
            response([ACCOUNT]),
            *[response(error=f"Please run az login. Context: {TENANT}") for _ in range(4)],
        ]
        with self.assertRaises(collector.CollectionLogin) as context:
            collector.collect(TENANT)
        self.assertIsInstance(context.exception, collector.CollectionError)
        self.assertNotIn(TENANT, str(context.exception))

    def test_pilot_never_queries_other_visible_subscriptions(self):
        def fake_az(args, **_):
            if args[1:3] == ["account", "list"]:
                return response([ACCOUNT, {**ACCOUNT, "id": OTHER}])
            self.assertEqual(argv_value(args, "--subscription"), OTHER)
            route = urlsplit(argv_value(args, "--url")).path
            if route.endswith("/Microsoft.ResourceGraph/resources"):
                self.assertEqual(json.loads(argv_value(args, "--body"))["subscriptions"], [OTHER])
                return arg_response([])
            if route.endswith("/Microsoft.CostManagement/query"):
                return response(error="AuthorizationFailed")
            return response({"value": [], "nextLink": None})

        self.runner.side_effect = fake_az
        result = collector.collect(TENANT, subscription_id=OTHER)
        self.assertEqual(result["subscriptions"], [OTHER])
        self.assertEqual(next(row["status"] for row in result["coverage"] if row["area"] == "scope"), "partial")
        unauthorized = "dddddddd-dddd-dddd-dddd-dddddddddddd"
        self.runner.reset_mock()
        with self.assertRaises(collector.CollectionError):
            collector.collect(TENANT, subscription_id=unauthorized)
        self.runner.assert_called_once()

    def test_metrics_collect_only_full_window_counts(self):
        item = {"id": f"{GROUP}/providers/Microsoft.Web/sites/synthetic", "type": "microsoft.web/sites"}
        self.runner.return_value = response([
            {"name": "Requests", "error": "Success", "unit": "Count", "series": [{"points": [{"total": 0.0}]}]},
            {"name": "Http4xx", "error": "Success", "unit": "Count", "series": []},
            {"name": "Http5xx", "error": "Success", "unit": "Count", "series": [{"points": [{"total": 3.0}]}]},
        ])
        self.assertEqual(collector._app_metrics(collector._Cli([]), item, "2026-10-01T00:00:00Z/2026-10-31T00:00:00Z"), "partial")
        args = self.runner.call_args.args[0]
        self.assertEqual(argv_value(args, "--method"), "get")
        self.assertIn("interval=FULL", argv_value(args, "--url"))
        self.assertEqual(item["requests30d"], 0)
        self.assertEqual(item["http5xx30d"], 3)
        self.assertNotIn("http4xx30d", item)

    def test_app_arm_configuration_uses_names_and_config_not_values(self):
        item = {"id": f"{GROUP}/providers/Microsoft.Web/sites/synthetic", "type": "microsoft.web/sites"}
        self.runner.side_effect = [
            response({"policies": [{"kind": "synthetic/scm", "allow": False}, {"kind": "ftp", "allow": True}],
                      "nextLink": None}),
            response({"settingCount": 0, "nextLink": None}),
            response(["EXAMPLE_API_KEY", "EXAMPLE_WORKER_COUNT"]),
        ]
        audit = []
        self.assertEqual(collector._app_configuration(collector._Cli(audit), item), "complete")
        for call, endpoint in zip(self.runner.call_args_list, (
                "/basicPublishingCredentialsPolicies", "/providers/Microsoft.Insights/diagnosticSettings",
                "/config/slotConfigNames")):
            args = call.args[0]
            self.assertEqual(argv_value(args, "--method"), "get")
            self.assertTrue(urlsplit(argv_value(args, "--url")).path.endswith(endpoint))
        self.assertFalse(item["scmBasicAuthEnabled"])
        self.assertTrue(item["ftpBasicAuthEnabled"])
        self.assertFalse(item["diagnosticsConfigured"])
        self.assertEqual(item["stickySettingCount"], 2)
        self.assertEqual(item["secretLikeStickySettingCount"], 1)
        self.assertNotIn("EXAMPLE_API_KEY", json.dumps([audit, item]))

    def test_cli_requires_confirmation_then_delegates_to_builder(self):
        directory = Path.cwd()
        argv = ["--tenant-id", TENANT, "--output", str(directory)]
        with patch.object(collector, "collect") as collect, contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(collector.main(argv), 0)
            collect.assert_not_called()
        data = {"resources": [{"id": STORE}]}
        with patch.object(collector, "collect", return_value=data) as collect, patch.dict(
            sys.modules, {"build": SimpleNamespace(run=Mock(return_value=("snap", {})))},
        ):
            self.assertEqual(collector.main([*argv, "--confirm-read-only"]), 0)
            collect.assert_called_once_with(TENANT)
            sys.modules["build"].run.assert_called_once_with(directory.absolute(), blob=None, live=data)
        self.runner.assert_not_called()

    def test_cli_hides_builder_exception_details(self):
        argv = ["--tenant-id", TENANT, "--output", str(Path.cwd()), "--confirm-read-only"]
        build = SimpleNamespace(run=Mock(side_effect=EvidenceError(STORE)))
        with (
            patch.object(collector, "collect", return_value={}),
            patch.dict(sys.modules, {"build": build}),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            self.assertNotEqual(collector.main(argv), 0)
        self.assertNotIn(STORE, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
