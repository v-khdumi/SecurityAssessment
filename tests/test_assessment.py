import http.client
import io
import json
import csv
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from threading import Event, Thread
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from app import AssessmentServer, ConnectionSetup
from archive_fixture import FILES as REPORT_FIXTURE
import build
from controls import RULES
from evidence import MAX_ZIP, MIB, EvidenceError, prowler_config, read_archive
from foundry_agents import FoundryError, FoundryReceipt, ModelConnection, assess_evidence, invoke

SUB = "4c97b582-9b26-42cd-97f1-e3ca95eadf90"
MODEL = ModelConnection("https://synthetic.openai.azure.com", "review-test", "synthetic-fixture-key-only")
RESOURCE = f"/subscriptions/{SUB}/resourceGroups/review-demo/providers/Microsoft.Web/sites/synthetic-test"
CONFIG = {
    "schema_version": 1,
    "resources": [
        {"id": RESOURCE, "type": "microsoft.web/sites", "location": "westeurope",
         "httpsOnly": False, "minTlsVersion": "1.2", "description": "alex@example.test"},
    ],
}


def archive(**members):
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as file:
        for name, body in members.items():
            file.writestr(name, body if isinstance(body, str) else json.dumps(body))
    return buffer.getvalue()


class EvidenceTests(unittest.TestCase):
    def test_selects_configuration_members_without_opening_logs(self):
        blob = archive(**{"assessment-v1.json": CONFIG, "auditLogs.json": "not JSON",
                          "signIns.json": "not JSON", "../authorizationPolicy.json": "not JSON"})
        config, skipped = read_archive(blob)
        self.assertEqual(list(config), ["assessment-v1.json"])
        self.assertEqual(skipped, 3)

    def test_invalid_archive_creates_no_artifacts(self):
        with tempfile.TemporaryDirectory() as output:
            with self.assertRaises(EvidenceError):
                build.run(output, archive(**{"authorizationPolicy.json": "invalid JSON"}))
            self.assertEqual(list(Path(output).iterdir()), [])

    def test_projects_data_and_reports_lifted_severity(self):
        blob = archive(**{"assessment-v1.json": CONFIG, "signIns.json": "not JSON",
                          "authorizationPolicy.json": {"displayName": "alex@example.test", "allowInvitesFrom": "none"}})
        with tempfile.TemporaryDirectory() as output, patch.dict("os.environ", {"ASSESSMENT_PSEUDONYM_KEY": "1" * 64}):
            first, summary = build.run(output, blob)
            self.assertEqual({key: summary[key] for key in ("resources", "findings", "high", "skipped", "eligible_files")},
                             {"resources": 1, "findings": 1, "high": 0, "skipped": 1, "eligible_files": 2})
            folder = Path(output, first)
            candidates = folder / "csv" / "resource-groups" / "system-map-candidates.csv"
            group = candidates.read_text("utf-8").splitlines()[1].split(",")[0]
            with patch("build.system_map", return_value={group: ("SYS-001", True)}):
                second, summary = build.run(output, blob)
            self.assertEqual(summary["high"], 1)
            result = Path(output, second, "report.html").read_text("utf-8")
            self.assertIn("APP-HTTPS", result)
            self.assertIn("displayName", result)
            findings_csv = Path(output, second, "csv", "findings", "details.csv").read_text("utf-8")
            self.assertNotIn("APP-TLS,", findings_csv)
            self.assertIn("Resource control coverage", result)
            self.assertNotIn("example.test", result)
            self.assertNotIn("synthetic-test", result)
            self.assertNotIn("signIns.json", result)
            build.delete_snapshot(output, first)
            self.assertFalse(folder.exists())
            self.assertTrue(Path(output, second).exists())

    def test_output_guard_rejects_upn(self):
        with self.assertRaises(EvidenceError):
            build.csv_data(("item",), (("synthetic@tenant.example",),))

    def test_cost_export_pseudonymises_billing_group(self):
        blob = archive(**{"assessment-v1.json": {**CONFIG, "costs": [
            {"subscriptionId": SUB, "group": RESOURCE.split("/providers/")[0], "currency": "EUR", "amount": 12.5},
            {"subscriptionId": SUB, "group": None, "currency": "RON", "amount": 4.5},
        ]}})
        with tempfile.TemporaryDirectory() as output:
            snapshot, _ = build.run(output, blob)
            csv = Path(output, snapshot, "csv", "cost", "totals.csv").read_text("utf-8")
            self.assertIn("EUR,ZIP,12.5", csv)
            self.assertIn("Unallocated,RON,ZIP,4.5", csv)
            self.assertNotIn("review-demo", csv)
            self.assertNotIn(SUB, csv)

    def test_function_findings_require_explicit_enabled_state(self):
        doc = {**CONFIG, "functions": [
            {"id": RESOURCE + "/functions/synthetic-unknown", "trigger": "httpTrigger", "authLevel": "anonymous"},
            {"id": RESOURCE + "/functions/synthetic-timer", "trigger": "timerTrigger", "disabled": False},
        ]}
        with tempfile.TemporaryDirectory() as output:
            _, inconclusive = build.run(output, archive(**{"assessment-v1.json": doc}))
            self.assertEqual(inconclusive["high"], 0)
            doc["functions"][0]["disabled"] = False
            snapshot, confirmed = build.run(output, archive(**{"assessment-v1.json": doc}))
            self.assertEqual(confirmed["high"], 1)
            folder = Path(output, snapshot)
            config = (folder / "csv" / "apps" / "function-config.csv").read_text("utf-8")
            self.assertIn("httpTrigger,anonymous,False", config)
            self.assertNotIn("synthetic-unknown", config)
            detail = (folder / "csv" / "findings" / "details.csv").read_text("utf-8")
            self.assertIn("ZIP — function configuration", detail)

    def test_candidate_system_groups_environments_without_exposing_name(self):
        template = f"/subscriptions/{SUB}/resourceGroups"
        data = {"schema_version": 1, "groups": [template + "/rg-synthetic-aggr-prod", template + "/rg-synthetic-aggr-qa"]}
        with tempfile.TemporaryDirectory() as path:
            snapshot, _ = build.run(path, archive(**{"assessment-v1.json": data}))
            mapping = Path(path, snapshot, "csv", "resource-groups", "system-map-candidates.csv").read_text("utf-8")
            self.assertNotIn("synthetic-aggr", mapping)
            self.assertEqual(len(set(line.split(",")[1] for line in mapping.splitlines()[1:])), 1)

    def test_cis_requirement_catalog_does_not_infer_pass_for_unscanned_checks(self):
        req = {"benchmark": "CIS-Azure", "benchmarkVersion": "6.0", "section": "1", "requirement": "1.2"}
        raw = {"version": "6.1.0", "requirements": [{**req, "exclusion": "entra_permissions"},
                                                     {**req, "requirement": "1.3"}],
               "checks": [{**req, "requirement": "1.3", "status": "pass"}]}
        version, table = prowler_config(raw)
        self.assertEqual(version, "6.1.0")
        self.assertEqual(table, [
            ("CIS-Azure", "6.0", "1", "1.2", "needs_entra_access", "—", "entra_permissions"),
            ("CIS-Azure", "6.0", "1", "1.3", "pass", "—", "—"),
        ])

    def test_native_prowler_catalog_marks_requirements_not_run(self):
        blob = archive(**{"prowler-nis2-azure.json": {"Framework": "NIS2", "Provider": "Azure", "Requirements": [
            {"Id": "1.1.1.a", "Description": "hidden@sample.test",
             "Attributes": [{"Section": "1 TEST (ARTICLE 21(2), POINT (A) OF DIRECTIVE (EU) 2022/2555)"}]},
        ]}, "prowler-cis-azure.json": {"Framework": "CIS", "Provider": "Azure", "Version": "6.0",
                                      "Requirements": [{"Id": "2.1.1", "Checks": ["synthetic_check"]}]}})
        with tempfile.TemporaryDirectory() as output:
            snapshot, summary = build.run(output, blob)
            table = Path(output, snapshot, "csv", "security-posture", "prowler.csv").read_text("utf-8")
            self.assertEqual(summary["eligible_files"], 2)
            self.assertIn("NIS2-2024-2690,2024/2690,1,1.1.1.a,manual_review,a,not_run", table)
            self.assertIn("CIS-Azure,6.0,2,2.1.1,manual_review,—,not_run", table)
            self.assertNotIn("hidden@sample.test", table)

    def test_wrong_native_framework_is_rejected(self):
        blob = archive(**{"prowler-cis-azure.json": {"Framework": "CIS", "Provider": "AWS", "Requirements": []}})
        with tempfile.TemporaryDirectory() as output:
            with self.assertRaises(EvidenceError):
                build.run(output, blob)
            self.assertEqual(list(Path(output).iterdir()), [])

    def test_runtime_threshold_and_plan_alias_join(self):
        plan = RESOURCE.replace("/sites/synthetic-test", "/serverfarms/synthetic-farm")
        doc = {**CONFIG, "resources": [
            {"id": plan, "type": "microsoft.web/serverfarms", "planSku": "P1V3", "planWorkers": 2},
            {**CONFIG["resources"][0], "planId": plan, "runtimeStack": "python", "runtimeEosDate": "2027-05-01"},
            {**CONFIG["resources"][0], "id": RESOURCE + "-future", "planId": plan, "runtimeStack": "node",
             "runtimeEosDate": "2027-05-02"},
        ]}
        tables, _, _ = build.dataset(archive(**{"assessment-v1.json": doc}), None, {}, {},
                                     datetime(2027, 1, 1, tzinfo=timezone.utc), b"x" * 32, {})
        tables_by_id = {table[0]: table[3] for table in tables["Apps"]}
        self.assertEqual({row[-1] for row in tables_by_id["runtimes"]}, {"within_120_days", "supported"})
        self.assertEqual(tables_by_id["plans"][0][1:], ("P1V3", 2, None, 2))
        self.assertNotIn("synthetic-farm", str(tables_by_id))

    def test_no_evidence_is_not_a_positive_result(self):
        with tempfile.TemporaryDirectory() as output:
            snapshot, summary = build.run(output, archive(**{"signIns.json": "not JSON"}))
            report = Path(output, snapshot, "report.html").read_text("utf-8")
            self.assertEqual(summary["resources"], 0)
            self.assertIn("No usable configuration evidence", report)
            self.assertIn("neither confirm nor rule out an incident", report)


class FoundryProtocolTests(unittest.TestCase):
    def test_rejects_missing_unknown_or_free_form_model_decisions(self):
        evidence = [{"id": 1, "control": "APP-HTTPS", "observed": False}]
        for decisions in ([], [[2, "finding", "High", "CHANGE"]],
                          [[1, "finding", "High", "free text"]],
                          [[1, "insufficient", None, None], [1, "no_finding", None, None]]):
            with self.subTest(decisions=decisions), patch("foundry_agents.build_opener") as opener:
                opener.return_value.open.return_value = self.response(decisions)
                with self.assertRaises(FoundryError):
                    invoke(MODEL, "posture", evidence)

    @staticmethod
    def response(decisions, **metadata):
        message = {"status": "completed", "output": [{"type": "message", "role": "assistant", "content": [
            {"type": "output_text", "text": json.dumps({"decisions": decisions})}]}]}
        response = io.BytesIO(json.dumps({**message, **metadata}).encode())
        response.status = 200
        response.headers = {"apim-request-id": "d540eb78-ac1a-4cfb-a5af-dd929c9753b7"}
        return response

    def test_api_key_mode_uses_the_deployment_without_cli(self):
        requests = []

        def fake_open(request, **_):
            payload = json.loads(request.data)
            rows = json.loads(payload["input"][0]["content"])
            requests.append((request, payload))
            code = "CHANGE" if "Agent: Security Posture." in payload["instructions"] else "EVIDENCE"
            return self.response([[row["id"], "finding", "Low", code] for row in rows],
                                 model="gpt-4.1", id="resp_test123456789",
                                 usage={"input_tokens": 203, "output_tokens": 48})

        evidence = {"posture": [{"id": 1, "control": "APP-HTTPS", "observed": False}],
                    "compliance": [{"id": 2, "control": "ENTRA-CA-REPORT", "observed": True}]}
        with patch("foundry_agents.build_opener") as opener:
            opener.return_value.open.side_effect = fake_open
            decisions, _, receipts = assess_evidence(MODEL, evidence)
        self.assertEqual(decisions, {1: ("finding", "Low", "CHANGE"), 2: ("finding", "Low", "EVIDENCE")})
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(receipts), len(requests))
        for receipt in receipts:
            self.assertEqual((receipt.provider_model, receipt.response_id), ("gpt-4.1", "resp_test123456789"))
            self.assertEqual(receipt.request_id, "d540eb78-ac1a-4cfb-a5af-dd929c9753b7")
            self.assertEqual((receipt.input_tokens, receipt.output_tokens, receipt.evidence_patterns), (203, 48, 1))
        for request, payload in requests:
            self.assertEqual(request.full_url, MODEL.endpoint + "/openai/v1/responses")
            self.assertEqual({name.lower(): value for name, value in request.header_items()}["api-key"], MODEL.api_key)
            self.assertNotIn(MODEL.api_key, request.data.decode())
            self.assertEqual(payload["model"], "review-test")
            self.assertFalse(payload["store"])

    def test_incomplete_response_does_not_produce_a_receipt(self):
        evidence = [{"id": 1, "control": "APP-HTTPS", "observed": False}]
        with patch("foundry_agents.build_opener") as opener:
            opener.return_value.open.return_value = self.response([[1, "no_finding", None, None]], status="incomplete")
            with self.assertRaisesRegex(FoundryError, "completed assessment response"):
                invoke(MODEL, "posture", evidence)


class LocalAppTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.server = AssessmentServer(0, Path(directory.name))
        self.server.setup = ConnectionSetup()
        thread = Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.archive = archive(**{"assessment-v1.json": CONFIG})
        self.prefix = self.server.session + "/"
        self.headers = {"Origin": self.server.origin, "Content-Type": "application/zip"}

    def request(self, method, path, body=None, headers=None):
        client = http.client.HTTPConnection(self.server.hostname, timeout=5)
        try:
            client.request(method, path, body, headers or {})
            reply = client.getresponse()
            return reply.status, reply.read()
        finally:
            client.close()

    @staticmethod
    def no_findings(_, batches, __):
        return ({row["id"]: ("no_finding", None, None) for rows in batches.values() for row in rows},
                {"posture": "Foundry assessed supported evidence."}, [])

    def test_ui_rejects_live_collection_requests(self):
        self.server.setup = ConnectionSetup(MODEL)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only", "X-Foundry-Consent": "minimized-configuration",
                   "X-Azure-Consent": "readonly-config",
                   "X-Setup-Revision": "0"}
        with patch("azure_collect.collect") as azure, patch("app.assess_evidence") as ai:
            status, body = self.request("POST", self.prefix + "assess", headers=headers)
            ai.assert_not_called()
            azure.assert_not_called()
        self.assertEqual(status, 400)
        self.assertIn("uploaded ZIP files only", json.loads(body)["error"])
        self.assertEqual(list(self.server.output.iterdir()), [])

    def test_http_consent_and_report_download(self):
        status, _ = self.request("POST", self.prefix + "assess", headers=self.headers)
        self.assertEqual(status, 403)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only"}
        status, _ = self.request("POST", self.prefix + "assess", headers={**headers, "Origin": "http://www.example.test"})
        self.assertEqual(status, 403)
        self.server.setup = ConnectionSetup(foundry=MODEL)
        status, _ = self.request("POST", self.prefix + "assess", headers={**headers, "X-Foundry-Consent": "public-catalog-only"})
        self.assertEqual(status, 403)
        headers.update({"X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0"})
        with patch("app.assess_evidence", side_effect=self.no_findings):
            status, body = self.request("POST", self.prefix + "assess", self.archive, headers)
        self.assertEqual(status, 200, body)
        data = json.loads(body)
        status, _ = self.request("GET", "/" + data["download"])
        self.assertEqual(status, 404)
        status, report = self.request("GET", self.prefix + data["download"])
        self.assertEqual(status, 200)
        self.assertIn(b"Confidential - internal", report)

    def test_readiness_and_invalid_zip_never_invoke_cloud(self):
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only", "X-Foundry-Consent": "minimized-configuration",
                   "X-Setup-Revision": "0"}
        self.server.setup = ConnectionSetup(MODEL)
        with patch("app.assess_evidence") as foundry, patch("azure_collect.collect") as azure:
            status, body = self.request("GET", self.prefix + "readiness")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"foundry_configured": True, "revision": 0, "max_zip_bytes": MAX_ZIP})
            self.assertNotIn(SUB.encode(), body)
            status, _ = self.request("POST", self.prefix + "assess", b"not a zip", headers)
            self.assertEqual(status, 422)
            foundry.assert_not_called()
            azure.assert_not_called()
        self.assertEqual(list(self.server.output.iterdir()), [])

    def test_setup_key_is_write_only_and_cannot_follow_an_endpoint_change(self):
        headers = {"Origin": self.server.origin, "Content-Type": "application/json", "X-Assessment-Setup": "session-only"}
        setup = {"revision": 0, "azure_tenant": SUB, "foundry": {
                 "endpoint": "https://synthetic.openai.azure.com/openai/v1/", "deployment": "review-model-1.2",
                 "api_key": "synthetic-fixture-key-only"}}
        key = setup["foundry"]["api_key"].encode()
        route = self.prefix + "setup"
        with patch("app.assess_evidence") as foundry, patch("azure_collect.collect") as azure:
            code, _ = self.request("POST", route, headers={**headers, "Origin": "http://example.test"})
            self.assertEqual(code, 403)
            self.assertIsNone(self.server.setup.foundry)
            code, body = self.request("POST", route, json.dumps(setup), headers)
            self.assertEqual(code, 200, body)
            self.assertNotIn(key, body)
            code, body = self.request("GET", route)
            self.assertEqual(code, 200)
            self.assertNotIn(key, body)
            self.assertTrue(json.loads(body)["foundry"]["has_key"])
            self.assertEqual(json.loads(body)["foundry"]["deployment"], "review-model-1.2")
            setup["revision"] = 1
            setup["foundry"]["api_key"] = ""
            self.assertEqual(self.request("POST", route, json.dumps(setup), headers)[0], 200)
            setup["revision"] = 2
            setup["foundry"]["endpoint"] = "https://another.openai.azure.com"
            self.assertEqual(self.request("POST", route, json.dumps(setup), headers)[0], 422)
            setup["foundry"]["api_key"] = key.decode()
            setup["foundry"]["endpoint"] = "https://synthetic.openai.azure.com@outside.invalid"
            code, error = self.request("POST", route, json.dumps(setup), headers)
            self.assertEqual(code, 422)
            self.assertNotIn(key, error)
            self.assertEqual(self.server.setup.foundry.endpoint, "https://synthetic.openai.azure.com")
            code, _ = self.request("POST", route, json.dumps({"revision": 2, "foundry": {"mode": "off"}}), headers)
            self.assertEqual(code, 422)
            foundry.assert_not_called()
            azure.assert_not_called()
        self.assertEqual(list(self.server.output.iterdir()), [])

    def test_setup_changes_require_new_online_consent_and_do_not_leak_into_reports(self):
        connection = MODEL
        self.server.setup = ConnectionSetup(foundry=connection, revision=3)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only", "X-Foundry-Consent": "minimized-configuration",
                   "X-Setup-Revision": "2"}
        with patch("app.assess_evidence", side_effect=self.no_findings) as foundry:
            code, _ = self.request("POST", self.prefix + "assess",
                                   headers={**headers, "Content-Length": str(len(self.archive))})
            self.assertEqual(code, 409)
            foundry.assert_not_called()
            code, reply = self.request("POST", self.prefix + "assess", self.archive, {**headers, "X-Setup-Revision": "3"})
            self.assertEqual(code, 200, reply)
            foundry.assert_called_once()
            self.assertIs(foundry.call_args.args[0], connection)
        snapshot = self.server.output / json.loads(reply)["snapshot"]
        report = (snapshot / "report.html").read_text("utf-8")
        self.assertNotIn(connection.api_key, report)
        self.assertNotIn(connection.endpoint, report)
        self.assertNotIn("get-access-token", report)
        self.assertIn("Azure OpenAI Responses", report)

    def test_no_bundled_sample_or_empty_assessment(self):
        route = self.prefix + "sample"
        self.server.setup = ConnectionSetup(MODEL)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only",
                   "X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0", "Content-Length": "0"}
        self.assertEqual(self.request("GET", route)[0], 404)
        with patch("app.assess_evidence") as foundry, patch("azure_collect.collect") as azure:
            self.assertEqual(self.request("POST", route, headers=headers)[0], 403)
            status, body = self.request("POST", self.prefix + "assess", headers=headers)
            self.assertEqual(status, 400)
            self.assertIn("nonempty configuration ZIP", json.loads(body)["error"])
            foundry.assert_not_called()
            azure.assert_not_called()
        self.assertEqual(list(self.server.output.iterdir()), [])

    def test_upload_larger_than_24_mib_and_excessive_upload_rejection(self):
        blob = archive(**{"assessment-v1.json": json.dumps(CONFIG) + " " * (25 * MIB), "ignored.bin": "not opened"})
        self.server.setup = ConnectionSetup(MODEL)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only",
                   "X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0"}
        with patch("app.assess_evidence", side_effect=self.no_findings) as foundry:
            status, body = self.request("POST", self.prefix + "assess",
                                        headers={**headers, "Content-Length": str(MAX_ZIP + 1)})
            self.assertEqual(status, 413)
            self.assertIn("512 MiB", json.loads(body)["error"])
            foundry.assert_not_called()
            status, body = self.request("POST", self.prefix + "assess", blob, headers)
            self.assertEqual(status, 200, body)
            foundry.assert_called_once()
        run = json.loads(body)
        self.assertEqual((run["resources"], run["skipped"], run["eligible_files"]), (1, 1, 1))
        self.assertEqual([entry.name for entry in self.server.output.iterdir()], [run["snapshot"]])
        report = (self.server.output / run["snapshot"] / "report.html").read_text("utf-8")
        self.assertIn("Foundry reported no findings in the submitted configuration", report)

    def test_foundry_alone_produces_ui_findings_from_minimized_zip_evidence(self):
        blob = archive(**{"assessment-v1.json": CONFIG, "authorizationPolicy.json": {
            "allowInvitesFrom": "everyone", "displayName": "do-not-export-this-policy-name",
        }})
        self.server.setup = ConnectionSetup(foundry=MODEL)
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only",
                   "X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0"}
        outgoing = {}

        def fake_open(request, **_):
            payload = json.loads(request.data)
            for row in json.loads(payload["input"][0]["content"]):
                outgoing[row["control"]] = row["observed"]
                self.assertEqual(set(row), {"id", "control", "setting", "observed", "finding_when", "typical_severity"})
            for secret in (RESOURCE, SUB, MODEL.api_key, "do-not-export-this-policy-name"):
                self.assertNotIn(secret, request.data.decode())
            decisions = [[row["id"], "finding", "High", "EVIDENCE"] if row["control"] == "ENTRA-GUEST-INVITES"
                         else [row["id"], "no_finding", None, None] for row in json.loads(payload["input"][0]["content"])]
            return FoundryProtocolTests.response(decisions, id="resp_testlocalassessment", model="gpt-4.1",
                                                 usage={"input_tokens": 120, "output_tokens": 11},
                                                 extra=MODEL.api_key)

        with patch("build.findings", side_effect=AssertionError("Local rule engine must not run")), \
                patch("foundry_agents.build_opener") as opener:
            opener.return_value.open.side_effect = fake_open
            status, body = self.request("POST", self.prefix + "assess", blob, headers)
        self.assertEqual(status, 200, body)
        self.assertIs(outgoing["APP-HTTPS"], False)
        self.assertEqual(outgoing["ENTRA-GUEST-INVITES"], "everyone")
        result = json.loads(body)
        self.assertEqual((result["analysis_mode"], result["findings"], result["high"]), ("Foundry", 1, 1))
        self.assertEqual(result["foundry_requests"], 2)
        with (self.server.output / result["snapshot"] / "csv" / "findings" / "details.csv").open(
                newline="", encoding="utf-8") as file:
            [finding] = list(csv.DictReader(file))
        self.assertEqual(finding["Key"], "ENTRA-GUEST-INVITES")
        self.assertIn("Foundry severity: High", finding["Severity rationale"])
        folder = self.server.output / result["snapshot"]
        report = (folder / "report.html").read_text("utf-8")
        self.assertIn("Executive summary", report)
        self.assertIn("Foundry identified 1 finding (1 high, 0 medium, 0 low)", report)
        self.assertIn("Start with ENTRA-GUEST-INVITES", report)
        self.assertIn("The total also includes Entra policy findings.", report)
        self.assertTrue((folder / "csv" / "summary" / "executive-summary.csv").is_file())
        with (folder / "csv" / "method-and-limits" / "foundry-receipts.csv").open(newline="", encoding="utf-8") as file:
            receipts = list(csv.DictReader(file))
        self.assertEqual({row["Agent"] for row in receipts}, {"Security Posture", "Compliance"})
        self.assertTrue(all(row["Model reported by Azure"] == "gpt-4.1" and row["Input tokens"] == "120" for row in receipts))
        self.assertIn("resp_testlocalassessment", report)
        self.assertNotIn(MODEL.api_key, report)

    def test_repeated_settings_are_sent_once_and_accounted_for_per_resource(self):
        blob = archive(**{"assessment-v1.json": {"schema_version": 1, "resources": [
            {"id": f"{RESOURCE}-{index}", "type": "microsoft.web/sites", "httpsOnly": False} for index in range(600)
        ]}})

        def assess(batches):
            [row] = batches["posture"]
            return {row["id"]: ("finding", "Medium", "CHANGE")}, {}, []

        _, summary, _ = build.dataset(blob, None, {}, {}, datetime.now(timezone.utc), b"x" * 32, {},
                                      review_mode="model", assess=assess)
        self.assertEqual((summary["model_patterns"], summary["model_evidence_rows"], summary["findings"]), (1, 600, 600))
        self.assertIn("affecting 600 of 600", summary["executive"][0][1])

    def test_uploaded_system_has_matching_resource_and_finding_counts(self):
        tables, _, _ = build.dataset(archive(**REPORT_FIXTURE), None, {}, {},
                                     datetime(2026, 11, 19, tzinfo=timezone.utc), b"x" * 32, {})
        [system_risk] = tables["Systems"][:1]
        self.assertEqual(sorted(row[3] for row in system_risk[3]), [3, 4, 5])
        orders = next(row for row in system_risk[3] if row[6] == 1)
        self.assertEqual((orders[3], orders[6:9]), (5, (1, 5, 2)))

    def test_findings_include_control_specific_plans_and_distinguish_context_from_missing_evidence(self):
        blob = archive(**REPORT_FIXTURE)
        with tempfile.TemporaryDirectory() as output:
            snapshot, summary = build.run(output, blob)
            directory = Path(output, snapshot)
            with (directory / "csv" / "findings" / "details.csv").open(newline="", encoding="utf-8") as file:
                findings = {row["Key"]: row for row in csv.DictReader(file)}
            anonymous = findings["APP-FUNC-ANON"]
            self.assertIn("1 enabled anonymous HTTP function(s)", anonymous["Related evidence"])
            self.assertIn("publicNetworkAccess: Enabled (ZIP)", anonymous["Related evidence"])
            self.assertIn("authenticationEnabled", anonymous["Related evidence not observed"])
            self.assertIn("not proof of internet reachability", anonymous["What this does not prove"])
            self.assertIn("staging", anonymous["2. Plan the change"])
            self.assertIn("cannot be turned off", findings["KV-PURGE"]["2. Plan the change"])
            self.assertIn("did not read container settings", findings["STG-ANON"]["What this does not prove"])
            self.assertEqual(anonymous["Microsoft Learn — primary"],
                             "https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook-trigger")
            self.assertTrue(findings["STG-ANON"]["Microsoft Learn — primary"].endswith("/anonymous-read-access-prevent"))
            self.assertTrue(findings["KV-PURGE"]["Microsoft Learn — primary"].endswith("/soft-delete-overview"))
            report = (directory / "report.html").read_text("utf-8")
            self.assertIn(f'href="{anonymous["Microsoft Learn — primary"]}" target="_blank" rel="noopener noreferrer"', report)
            self.assertIn("Evidence and remediation plan", report)
            self.assertIn("Evidence to close", report)
            self.assertNotIn("sample-health", report)
            self.assertEqual((summary["resources"], summary["findings"], summary["high"]), (12, 12, 1))

    def test_entra_guidance_uses_projected_counts_without_exported_links_or_policy_names(self):
        blob = archive(**{"conditionalAccessPolicies.json": {
            "value": [{"displayName": "Synthetic policy label", "state": "enabledForReportingButNotEnforced"}],
            "@odata.nextLink": "https://outside.invalid/synthetic-pagination",
        }})
        with tempfile.TemporaryDirectory() as output:
            snapshot, summary = build.run(output, blob)
            report = (Path(output, snapshot) / "report.html").read_text("utf-8")
            self.assertIn("0 enabled, 1 report-only, 0 disabled", report)
            self.assertIn("totals are incomplete", report)
            self.assertIn("does not show MFA requirements", report)
            self.assertIn('href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only"', report)
            self.assertNotIn("outside.invalid", report)
            self.assertNotIn("Synthetic policy label", report)
            self.assertEqual(summary["findings"], 0)

    def test_domain_tabs_include_reviews_with_scoped_evidence_and_unmatched_cost(self):
        normalized = {"schema_version": 1, "resources": [
            {"id": RESOURCE, "type": "microsoft.web/sites", "publicNetworkAccess": "Enabled", "httpsOnly": False},
            {"id": RESOURCE + "-storage", "type": "microsoft.storage/storageaccounts", "allowBlobPublicAccess": False},
        ], "costs": [{"subscriptionId": SUB, "amount": 43.0, "currency": "EUR"}]}
        tables, _, _ = build.dataset(archive(**{"assessment-v1.json": normalized}), None, {}, {},
                                     datetime(2026, 11, 19, tzinfo=timezone.utc), b"x" * 32, {})
        self.assertTrue(all(any(table[0] == "review-plan" for table in tab) for tab in tables.values()))
        network = {slug: rows for slug, _, _, rows, _ in tables["Network"]}
        self.assertEqual(len(network["review-evidence"]), 1)
        self.assertEqual(network["review-evidence"][0][2:], ("Enabled", "Not observed", "Not observed"))
        self.assertEqual(network["linked-findings"][0][:2], ("Medium", "APP-HTTPS"))
        storage = {slug: rows for slug, _, _, rows, _ in tables["Storage"]}
        self.assertIs(storage["review-evidence"][0][3], False)
        self.assertEqual(storage["linked-findings"], [])
        cost = {slug: rows for slug, _, _, rows, _ in tables["Cost"]}
        self.assertEqual(cost["billing-reconciliation"][0][3:], (43.0, 0, 43.0))

    def test_progress_stream_reports_both_agents_before_they_return(self):
        self.server.setup = ConnectionSetup(foundry=MODEL)
        allow_response = Event()
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only",
                   "X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0", "Accept": "application/x-ndjson"}

        def finish_agent(_, role, rows):
            if not allow_response.wait(3):
                raise FoundryError("The test did not release this agent.")
            if role == "compliance":
                raise FoundryError("Simulated unavailable deployment.")
            decisions = {row["id"]: ("finding", "Medium", "CHANGE") for row in rows}
            receipt = FoundryReceipt("Security Posture", "2026-11-19T13:00:00+00:00", 10, 200,
                                     len(rows), None, None, None, None, None)
            return decisions, receipt

        client = http.client.HTTPConnection(self.server.hostname, timeout=5)
        with patch("foundry_agents.invoke", side_effect=finish_agent):
            try:
                client.request("POST", self.prefix + "assess", archive(**REPORT_FIXTURE), headers)
                response = client.getresponse()
                self.assertTrue(response.getheader("Content-Type").startswith("application/x-ndjson"))
                events = [json.loads(response.readline()) for _ in range(5)]
                self.assertEqual([(event["stage"], event["state"]) for event in events],
                                 [("upload", "done"), ("evidence", "running"), ("evidence", "done"),
                                  ("posture", "running"), ("compliance", "running")])
                allow_response.set()
                remaining = [json.loads(line) for line in response.read().splitlines()]
                self.assertEqual({(event["stage"], event["state"]) for event in remaining[:2]},
                                 {("posture", "done"), ("compliance", "failed")})
                self.assertEqual(remaining[-1]["status"], 422)
            finally:
                allow_response.set()
                client.close()

    def test_real_assessment_requires_key_and_agent_success(self):
        route = self.prefix + "assess"
        headers = {**self.headers, "X-Assessment-Consent": "configuration-only",
                   "X-Foundry-Consent": "minimized-configuration", "X-Setup-Revision": "0"}
        with patch("app.assess_evidence", side_effect=FoundryError("Compliance agent: test failure")) as review:
            status, body = self.request("POST", route, headers={**headers, "Content-Length": str(len(self.archive))})
            self.assertEqual(status, 400)
            self.assertIn("API key in Setup", json.loads(body)["error"])
            review.assert_not_called()
            self.server.setup = ConnectionSetup(foundry=MODEL)
            status, body = self.request("POST", route, self.archive, headers)
            self.assertEqual(status, 422)
            self.assertIn("Compliance agent", json.loads(body)["error"])
            review.assert_called_once()
            self.assertIs(review.call_args.args[0], MODEL)
        self.assertEqual(list(self.server.output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
