"""Loopback-only UI for the local Azure assessment."""

import argparse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import stat
from tempfile import TemporaryFile
from threading import Lock

import build
from evidence import MAX_ZIP, MIB, EvidenceError, read_archive
from foundry_agents import FoundryError, ModelConnection, assess_evidence, configuration, model_endpoint

ASSETS = build.BASE / "web"


@dataclass(frozen=True)
class ConnectionSetup:
    foundry: ModelConnection | None = None
    revision: int = 0

    def public_settings(self):
        fields = {}
        if self.foundry:
            fields.update(endpoint=self.foundry.endpoint, deployment=self.foundry.deployment, has_key=True)
        return {"foundry": fields, "revision": self.revision}

    def update(self, payload):
        if not isinstance(payload, dict) or not isinstance(payload.get("foundry"), dict):
            raise EvidenceError("The setup request must contain Foundry connection settings.")

        def text(body, field):
            value = body.get(field, "")
            if not isinstance(value, str) or len(value) > 512:
                raise EvidenceError("A setup field is invalid or too long.")
            return value.strip()

        values = payload["foundry"]
        if "mode" in values:
            raise EvidenceError("Setup has changed. Reload the workspace to use API-key setup.")
        endpoint = model_endpoint(text(values, "endpoint"))
        api_key = text(values, "api_key")
        if not api_key and self.foundry and endpoint == self.foundry.endpoint:
            api_key = self.foundry.api_key
        foundry = ModelConnection(endpoint, text(values, "deployment"), api_key)
        return ConnectionSetup(foundry, self.revision + 1)


class AssessmentServer(ThreadingHTTPServer):
    def __init__(self, port, output):
        super().__init__(("127.0.0.1", port), Handler)
        self.output = output
        self.hostname = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.hostname}"
        self.session = "/" + secrets.token_urlsafe(24)
        self.lock = Lock()
        try:
            foundry = configuration()
        except FoundryError:
            foundry = None
        self.setup = ConnectionSetup(foundry)

    def get_request(self):
        client, address = super().get_request()
        client.settimeout(45)
        return client, address


class Handler(BaseHTTPRequestHandler):
    streaming = False

    def log_message(self, *_):
        return

    def send(self, code, body, content_type, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if extra:
            for name, value in extra.items():
                self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def payload(self, code, message):
        if self.streaming:
            self.event({"event": "result", "status": code, "payload": message})
            return
        self.send(code, json.dumps(message, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def event(self, data):
        try:
            self.wfile.write((json.dumps(data, ensure_ascii=False) + "\n").encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def progress(self, step, state, detail):
        if self.streaming:
            self.event({"event": "progress", "stage": step, "state": state, "detail": detail})

    def path_local(self):
        session = self.server.session + "/"
        if self.headers.get("Host") != self.server.hostname or not self.path.startswith(session):
            return None
        return self.path[len(session):]

    def do_GET(self):
        path = self.path_local()
        if path == "readiness":
            setup = self.server.setup
            self.payload(200, {
                "foundry_configured": setup.foundry is not None,
                "revision": setup.revision,
                "max_zip_bytes": MAX_ZIP,
            })
            return
        if path == "setup":
            self.payload(200, self.server.setup.public_settings())
            return
        if path in ("", "ui.js", "ui.css", "mandate.txt"):
            asset, kind = {
                "": ("index.html", "text/html"), "ui.js": ("ui.js", "application/javascript"),
                "ui.css": ("ui.css", "text/css"), "mandate.txt": ("mandate.txt", "text/plain"),
            }[path]
            asset_path = (build.BASE if path == "mandate.txt" else ASSETS) / asset
            csp = ("default-src 'none'; script-src 'self'; style-src 'self'; frame-src 'self'; "
                   "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            try:
                body = asset_path.read_bytes()
            except OSError:
                self.payload(500, {"error": "Application assets are unavailable."})
                return
            self.send(200, body, kind + "; charset=utf-8", {"Content-Security-Policy": csp})
            return
        match = re.fullmatch(r"(report|download)/([^/]+)", path or "")
        if match and build.SNAPSHOT.fullmatch(match[2]):
            folder = self.server.output / match[2]
            report = folder / "report.html"
            try:
                info = report.lstat() if build.safe_dir(folder) else None
                if (info and stat.S_ISREG(info.st_mode) and not
                        getattr(info, "st_file_attributes", 0) & 0x400):
                    headers = {"Content-Disposition": 'attachment; filename="Azure Tenant Inventory.html"'} if match[1] == "download" else {}
                    self.send(200, report.read_bytes(), "text/html; charset=utf-8", headers)
                    return
            except OSError:
                pass
        self.payload(404, {"error": "The page or report is unavailable."})

    def do_POST(self):
        path = self.path_local()
        if path not in {"assess", "setup"} or self.headers.get("Origin") != self.server.origin:
            self.payload(403, {"error": "Unauthorized local request."})
            return
        if path == "setup":
            self.save_setup()
            return
        if self.headers.get("X-Assessment-Consent") != "configuration-only":
            self.payload(403, {"error": "Confirm the mandate and data categories before running the assessment."})
            return
        if self.headers.get("X-Foundry-Consent") != "minimized-configuration":
            self.payload(403, {"error": "Approve sending the listed configuration indicators to your Foundry deployment."})
            return
        if self.headers.get("X-Azure-Consent"):
            self.payload(400, {"error": "This app assesses uploaded ZIP files only. Reload the workspace to continue."})
            return
        raw_length = self.headers.get("Content-Length", "")
        if not re.fullmatch(r"[0-9]{1,10}", raw_length) or self.headers.get("Transfer-Encoding"):
            self.payload(400, {"error": "The ZIP upload must have a known file size."})
            return
        length = int(raw_length)
        if length > MAX_ZIP:
            self.payload(413, {"error": f"The ZIP exceeds {MAX_ZIP // MIB} MiB. Re-export a narrower assessment scope and upload that ZIP."})
            return
        if not length or self.headers.get("Content-Type") != "application/zip":
            self.payload(400, {"error": "Select a nonempty configuration ZIP before starting an assessment."})
            return
        if not self.server.lock.acquire(blocking=False):
            self.payload(409, {"error": "An assessment is already running."})
            return
        try:
            setup = self.server.setup
            if self.headers.get("X-Setup-Revision") != str(setup.revision):
                self.payload(409, {"error": "Connection setup changed. Review the current settings and confirm the assessment again."})
                return
            connection = setup.foundry
            with TemporaryFile(dir=build.output_root(self.server.output)) as upload:
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(MIB, remaining))
                    if not chunk:
                        self.payload(400, {"error": "The ZIP transfer was incomplete. Select the file and upload it again."})
                        return
                    upload.write(chunk)
                    remaining -= len(chunk)
                if self.headers.get("Accept") == "application/x-ndjson":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.streaming = True
                    self.close_connection = True
                self.progress("upload", "done", "ZIP received on the assessment host.")
                self.progress("evidence", "running", "Detecting supported configuration by content on the assessment host.")
                prepared_archive = read_archive(upload, recover_members=True)
            self.progress("evidence", "done", "Archive validated. The temporary upload is closed.")
            self.progress("prepare", "running", "Checking the ZIP for supported assessment evidence.")
            if self.headers.get("X-Assessment-Coverage") == "require-all-evidence-entries":
                prepared_archive.require_all_evidence_entries()
            unresolved = sum(prepared_archive.coverage_issues().values())
            entry_label = "entry" if unresolved == 1 else "entries"
            gap_detail = (f" {unresolved} {entry_label} could not be fully imported; see Archive import coverage in the report."
                          if unresolved else "")
            status = {}

            def assess(batches):
                nonlocal status
                count = sum(map(len, batches.values()))
                if not count:
                    reason = "No supported configuration settings to assess."
                    status = {role: f"Not called: {reason}" for role in batches}
                    self.progress("prepare", "done", reason + gap_detail)
                    for role in batches:
                        self.progress(role, "skipped", reason)
                    self.progress("report", "running", "Writing coverage and recovery guidance without Foundry decisions.")
                    return {}, status, []
                if connection is None:
                    raise EvidenceError("Set the Azure OpenAI endpoint, deployment, and API key in Setup to assess the supported settings.")
                self.progress("prepare", "done", f"Prepared {count} configuration patterns for Foundry." + gap_detail)
                decisions, status, receipts = assess_evidence(connection, batches, self.progress)
                self.progress("report", "running", "Writing the Foundry decisions to the report.")
                return decisions, status, receipts

            snapshot, summary = build.run(self.server.output, prepared_archive=prepared_archive, review_mode="model", assess=assess)
            self.progress("report", "done", "Report and CSVs saved on the assessment host.")
            self.payload(200, {"snapshot": snapshot, **summary,
                               "foundry_status": status, "preview": f"report/{snapshot}",
                               "download": f"download/{snapshot}"})
        except (EvidenceError, FoundryError) as exc:
            self.payload(422, {"error": str(exc)})
        except (OSError, TimeoutError):
            self.payload(500, {"error": "A local read or write failed. Check the directory and its permissions."})
        finally:
            self.server.lock.release()

    def save_setup(self):
        if (self.headers.get("X-Assessment-Setup") != "session-only"
                or self.headers.get("Content-Type") != "application/json"):
            self.payload(403, {"error": "Unauthorized setup request."})
            return
        size = self.headers.get("Content-Length", "")
        if not re.fullmatch(r"[0-9]{1,4}", size) or not 1 <= int(size) <= 8192 or self.headers.get("Transfer-Encoding"):
            self.payload(400, {"error": "Invalid setup request size."})
            return
        try:
            payload = json.loads(self.rfile.read(int(size)))
        except (ValueError, RecursionError, OSError):
            self.payload(400, {"error": "Could not read the setup request."})
            return
        if not self.server.lock.acquire(blocking=False):
            self.payload(409, {"error": "An assessment or setup update is already running."})
            return
        try:
            if not isinstance(payload, dict) or payload.get("revision") != self.server.setup.revision:
                self.payload(409, {"error": "Setup changed in another tab. Close Setup and reopen it to continue."})
                return
            self.server.setup = self.server.setup.update(payload)
            self.payload(200, self.server.setup.public_settings())
        except (EvidenceError, FoundryError) as exc:
            self.payload(422, {"error": str(exc)})
        finally:
            self.server.lock.release()


def main():
    parser = argparse.ArgumentParser(description="Azure Tenant Assessment, accessible on loopback only.")
    parser.add_argument("--output", type=Path, required=True, help="Existing, company-approved local directory")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    try:
        output = build.output_root(args.output)
        with AssessmentServer(args.port, output) as server:
            print(f"Open in your local browser (do not share this address): {server.origin}{server.session}/", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    except (EvidenceError, OSError) as exc:
        msg = str(exc) if isinstance(exc, EvidenceError) else "The local server could not start. Check the port."
        parser.exit(1, msg + "\n")


if __name__ == "__main__":
    main()
