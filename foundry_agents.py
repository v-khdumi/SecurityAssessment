"""Two built-in review agents backed by Azure OpenAI."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
import os
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from controls import QUESTIONS

DEPLOYMENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}")
MODEL_ENDPOINT = re.compile(r"https://[a-z0-9][a-z0-9-]{0,62}\.(?:openai\.azure\.com|services\.ai\.azure\.com)")
API_KEY = re.compile(r"[A-Za-z0-9_.~+/=-]{16,512}")
AGENTS = {
    "posture": ("Security Posture", "Assess Azure resource configuration.",
                ("EXCEPTION", "COMPENSATING", "CHANGE")),
    "compliance": ("Compliance", "Assess Entra and Microsoft 365 configuration without concluding that a tenant is compliant.",
                   ("EVIDENCE", "SCOPE", "DPO")),
}
MAX_EVIDENCE_ROWS = 480
BATCH_SIZE = 40


class FoundryError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class ModelConnection:
    endpoint: str
    deployment: str
    api_key: str = field(repr=False)

    def __post_init__(self):
        if not MODEL_ENDPOINT.fullmatch(self.endpoint):
            raise FoundryError("Enter a public Azure OpenAI resource endpoint, not a Foundry project URL.")
        if not DEPLOYMENT.fullmatch(self.deployment):
            raise FoundryError("Enter the deployment name from the portal, not a URL. Use letters, numbers, periods, hyphens, or underscores.")
        if not API_KEY.fullmatch(self.api_key):
            raise FoundryError("Enter a valid Azure OpenAI API key. It is not saved to disk.")


def model_endpoint(value: str) -> str:
    return value.strip().rstrip("/").removesuffix("/openai/v1")


def configuration() -> ModelConnection | None:
    endpoint = model_endpoint(os.getenv("AZURE_OPENAI_ENDPOINT", ""))
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "").strip()
    key = os.getenv("AZURE_OPENAI_API_KEY", "").strip()
    return ModelConnection(endpoint, deployment, key) if (endpoint or deployment or key) else None


@dataclass(frozen=True)
class FoundryReceipt:
    agent: str
    requested_at: str
    duration_ms: int
    http_status: int
    evidence_patterns: int
    provider_model: str | None
    request_id: str | None
    response_id: str | None
    input_tokens: int | None
    output_tokens: int | None


def receipt_field(value, pattern):
    return value if isinstance(value, str) and re.fullmatch(pattern, value) else None


def invoke(connection: ModelConnection, role: str, evidence: list[dict]):
    label, purpose, options = AGENTS[role]
    rubric = {key: QUESTIONS[key] for key in options}
    instructions = (
        f"Agent: {label}. {purpose} For each evidence row, decide whether its observed setting supports the risk "
        "condition in finding_when. A list in finding_when means any of those values. Emit finding only if it does, "
        "no_finding if it does not, or insufficient if the "
        "evidence is indeterminate. Do not infer a breach, reachability, policy effectiveness, or compliance. "
        "If policy_context is present, use only its supplied settings; missing fields are unknown. "
        "For Conditional Access do not infer enforcement across policies or tenant-wide MFA coverage. "
        "For a finding select Low, Medium, or High, using typical_severity as a guide, and one question code. "
        'Return a JSON object with exactly one key "decisions". Its value must be an array of rows '
        '[id, "finding", "Medium", "allowed_question_code"], [id, "no_finding", null, null] '
        'or [id, "insufficient", null, null]. Return each supplied id exactly once, with no prose or tools. '
        f"Allowed question codes: {json.dumps(rubric)}"
    )
    payload = {"model": connection.deployment, "instructions": instructions,
               "input": [{"role": "user", "content": json.dumps(evidence, separators=(",", ":"), ensure_ascii=True)}],
               "store": False}
    url = f"{connection.endpoint}/openai/v1/responses"
    request = Request(url, method="POST", data=json.dumps(payload).encode(),
                      headers={"api-key": connection.api_key, "Content-Type": "application/json"})
    started = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    start = monotonic()
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=45) as response:
            contents = response.read(512_001)
            code = response.status
            request_id = next((value for name in ("apim-request-id", "x-ms-request-id", "x-request-id")
                               if (value := receipt_field(response.headers.get(name),
                                   r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"))), None)
            duration = round((monotonic() - start) * 1000)
        if len(contents) > 512_000:
            raise FoundryError("The Foundry response exceeded the size limit.")
        data = json.loads(contents)
        if code != 200 or data.get("status", "completed") != "completed":
            raise FoundryError("Foundry did not return a completed assessment response.")
        texts = [part["text"] for item in data["output"] if item.get("type") == "message"
                 and item.get("role") == "assistant" for part in item.get("content", [])
                 if part.get("type") == "output_text"]
        raw = json.loads("".join(texts))
        decisions = validate_decisions(raw, {row["id"] for row in evidence}, options)
        usage = data.get("usage")
        input_count, output_count = ((usage.get("input_tokens"), usage.get("output_tokens"))
                                     if isinstance(usage, dict) else (None, None))
        provider_model = receipt_field(data.get("model"), r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
        if provider_model and connection.api_key in provider_model:
            provider_model = None
        response_id = receipt_field(data.get("id"), r"resp_[A-Za-z0-9_-]{8,100}")
        return decisions, FoundryReceipt(
            label, started, duration, code, len(evidence), provider_model, request_id, response_id,
            input_count if type(input_count) is int and input_count >= 0 else None,
            output_count if type(output_count) is int and output_count >= 0 else None,
        )
    except HTTPError as exc:
        exc.close()
        if exc.code in (401, 403):
            raise FoundryError("Azure denied access. Check the API key and whether the resource allows key authentication.") from None
        if exc.code == 404:
            raise FoundryError("Azure did not find the deployment. Check the resource endpoint and deployment name.") from None
        if exc.code == 429:
            raise FoundryError("Azure rate limit or quota reached. Try again later.") from None
        raise FoundryError("The Azure OpenAI request failed. Check that the deployment supports the Responses API.") from None
    except (OSError, URLError, ValueError, TypeError, AttributeError, KeyError, RecursionError):
        raise FoundryError("Azure AI did not return a usable review response.") from None


def validate_decisions(raw, expected, options):
    if not isinstance(raw, dict) or set(raw) != {"decisions"} or not isinstance(raw["decisions"], list):
        raise FoundryError("The model response did not match the assessment format.")
    decisions = {}
    for row in raw["decisions"]:
        if not isinstance(row, list) or len(row) != 4:
            raise FoundryError("The model returned an invalid evidence decision.")
        anchor, verdict, severity, question = row
        if type(anchor) is not int or anchor not in expected or anchor in decisions:
            raise FoundryError("The model returned an unknown or duplicate evidence reference.")
        if verdict == "finding":
            valid = severity in ("Low", "Medium", "High") and question in options
        else:
            valid = verdict in ("no_finding", "insufficient") and severity is None and question is None
        if not valid:
            raise FoundryError("The model returned an invalid verdict, severity, or review question.")
        decisions[anchor] = (verdict, severity, question)
    if decisions.keys() != expected:
        raise FoundryError("The model did not return a decision for every submitted evidence row.")
    return decisions


def assess_evidence(connection: ModelConnection, evidence: dict[str, list[dict]], on_progress=None):
    count = sum(map(len, evidence.values()))
    if not count:
        raise FoundryError("No supported configuration evidence was found. Sign-in, audit, and application logs are not assessed.")
    if count > MAX_EVIDENCE_ROWS:
        raise FoundryError(f"Evidence exceeds the {MAX_EVIDENCE_ROWS}-row assessment limit. Narrow the export or Azure subscription scope.")

    def assess_batches(role, rows):
        result = {}
        receipts = []
        for start in range(0, len(rows), BATCH_SIZE):
            batch = rows[start:start + BATCH_SIZE]
            decisions, receipt = invoke(connection, role, batch)
            result.update(decisions)
            receipts.append(receipt)
        return result, receipts

    result, status, failures, receipts = {}, {}, [], []
    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = {}
        for role, rows in evidence.items():
            if not rows:
                status[role] = "Not called: no supported evidence in this scope."
                if on_progress:
                    on_progress(role, "skipped", status[role])
                continue
            if on_progress:
                on_progress(role, "running", f"Waiting for Foundry to assess {len(rows)} evidence rows.")
            calls[pool.submit(assess_batches, role, rows)] = role
        for call in as_completed(calls):
            role = calls[call]
            try:
                decisions, completed = call.result()
            except FoundryError as exc:
                failures.append(f"{AGENTS[role][0]} agent: {exc}")
                if on_progress:
                    on_progress(role, "failed", str(exc))
                continue
            result.update(decisions)
            receipts.extend(completed)
            reported = sum(decision[0] == "finding" for decision in decisions.values())
            unknown = sum(decision[0] == "insufficient" for decision in decisions.values())
            status[role] = f"Foundry assessed {len(decisions)} evidence rows: {reported} findings, {unknown} insufficient."
            if on_progress:
                on_progress(role, "done", status[role])
        if failures:
            raise FoundryError(" ".join(failures))
    return result, status, sorted(receipts, key=lambda receipt: (receipt.requested_at, receipt.agent))
