from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import re
from urllib.parse import unquote, urlsplit
import json
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- GLOBAL EXCEPTION TRAPS ---
# Force all protocol errors (404 Not Found, 405 Method Not Allowed) to return the exact assignment schema
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    print(f"[TRAPPED HTTP {exc.status_code}] -> {request.method} {request.url.path}")
    return JSONResponse(status_code=200, content={"safe": False, "reason": "INVALID_SCHEMA"})

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    print("[TRAPPED 422 VALIDATION ERROR]")
    return JSONResponse(status_code=200, content={"safe": False, "reason": "INVALID_SCHEMA"})

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    print(f"[TRAPPED 500 FATAL ERROR] -> {str(exc)}")
    return JSONResponse(status_code=200, content={"safe": False, "reason": "INVALID_SCHEMA"})

@app.get("/")
@app.head("/")
async def root_health_check():
    return JSONResponse(content={"status": "live"})

@app.post("/release-gate")
@app.post("/release-gate/")
async def release_gate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
        
    violations = set()
    
    target = payload.get("target", "")
    event = payload.get("event", "")
    ref = payload.get("ref", "")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get("permissions") != expected_perms:
        violations.add("EXCESS_PERMISSION")

    trigger = workflow.get("trigger", "")
    if (event == "pull_request" and trigger != "pull_request") or (trigger == "pull_request_target"):
        violations.add("UNSAFE_PR_TRIGGER")

    if workflow.get("testsPassed") is not True or \
       workflow.get("matrixComplete") is not True or \
       workflow.get("failFast") is not False:
        violations.add("TESTS_INCOMPLETE")

    hex_sha_regex = re.compile(r'^[a-f0-9]{40}$')
    for action in workflow.get("actions", []):
        if action.get("owner") != "actions":
            if not hex_sha_regex.fullmatch(action.get("ref", "")):
                violations.add("MUTABLE_ACTION")

    if image.get("multiStage") is not True:
        violations.add("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.add("ROOT_RUNTIME")

    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.add("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.add("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.add("UNPINNED_IMAGE")

    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.add("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.add("APPROVAL_REQUIRED")

    violations_list = list(violations)
    decision = "promote" if not violations_list else "block"
    
    return JSONResponse(content={"decision": decision, "violations": violations_list})

@app.post("/action-firewall")
@app.post("/action-firewall/")
async def action_firewall(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    if not isinstance(payload, dict):
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
        
    action = payload.get("action")
    if not isinstance(action, dict) or "tool" not in action or "args" not in action:
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(args, dict):
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    allowed_tools = {"search", "lookup_record", "send_email", "render_html"}
    if tool not in allowed_tools:
        return JSONResponse(content={"decision": "block", "reason": "TOOL_NOT_ALLOWED"})

    args_keys = set(args.keys())
    if tool == "search":
        if args_keys != {"query"} or not isinstance(args.get("query"), str):
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
        if not (1 <= len(args["query"]) <= 200):
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
            
    elif tool == "lookup_record":
        if args_keys != {"tenantId", "recordId"} or not isinstance(args.get("tenantId"), str) or not isinstance(args.get("recordId"), str):
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
        if len(args["recordId"]) == 0:
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
            
    elif tool == "send_email":
        if args_keys != {"to", "subject", "body"} or not isinstance(args.get("to"), str) or not isinstance(args.get("subject"), str) or not isinstance(args.get("body"), str):
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
            
    elif tool == "render_html":
        if args_keys != {"html"} or not isinstance(args.get("html"), str):
            return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    if tool == "lookup_record":
        if args["tenantId"] != "tenant-f9lp0ur":
            return JSONResponse(content={"decision": "block", "reason": "TENANT_SCOPE"})

    if tool == "send_email":
        email = args["to"]
        if not email.endswith("@notify-sl77rjl.example") or email.split("@")[-1] != "notify-sl77rjl.example":
            return JSONResponse(content={"decision": "block", "reason": "EGRESS_DENIED"})
        if payload.get("humanApproved") is not True:
            return JSONResponse(content={"decision": "block", "reason": "APPROVAL_REQUIRED"})

    if tool == "render_html":
        html_content = args["html"]
        unsafe_pattern = re.compile(r'(<\s*script|<\s*iframe|\bon[a-zA-Z]+\s*=|javascript\s*:)', re.IGNORECASE)
        if unsafe_pattern.search(html_content):
            return JSONResponse(content={"decision": "block", "reason": "UNSAFE_OUTPUT"})

    return JSONResponse(content={"decision": "allow", "reason": "ALLOW"})

@app.post("/terraform/plan")
@app.post("/terraform/plan/")
async def terraform_plan(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    if type(payload) is not dict:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    req_keys = {"environment", "state", "providerVersion", "destroyApproved", "resource"}
    if not req_keys.issubset(payload.keys()):
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    env = payload["environment"]
    state = payload["state"]
    prov_ver = payload["providerVersion"]
    destroy_app = payload["destroyApproved"]
    res = payload["resource"]

    if type(env) is not str or type(state) is not dict or \
       type(prov_ver) is not str or type(destroy_app) is not bool or \
       type(res) is not dict:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    if "backend" not in state or "locked" not in state:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})
    
    state_backend = state["backend"]
    state_locked = state["locked"]
    if type(state_backend) is not str or type(state_locked) is not bool:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    res_keys = {"address", "type", "action", "labels", "secret", "forceDestroy"}
    if not res_keys.issubset(res.keys()):
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    r_addr = res["address"]
    r_type = res["type"]
    r_action = res["action"]
    r_labels = res["labels"]
    r_secret = res["secret"]
    r_force = res["forceDestroy"]

    if type(r_addr) is not str or type(r_type) is not str or type(r_action) is not str or \
       type(r_labels) is not dict or type(r_force) is not bool:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})
    
    if r_secret is not None and type(r_secret) is not str:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})
        
    if any(type(k) is not str or type(v) is not str for k, v in r_labels.items()):
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    if r_action not in {"create", "update", "delete"}:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    if env != "prod-yj9jdn":
        return JSONResponse(content={"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"})

    valid_backends = {"gcs", "s3", "azurerm", "remote"}
    if state_backend not in valid_backends or state_locked is not True:
        return JSONResponse(content={"decision": "reject", "reason": "STATE_UNSAFE"})

    prov_ver_clean = prov_ver.strip()
    is_exact = re.match(r'^=?\s*\d+\.\d+(\.\d+)?$', prov_ver_clean)
    is_pessimistic = re.match(r'^~>\s*\d+\.\d+(\.\d+)?$', prov_ver_clean)
    
    if not (is_exact or is_pessimistic):
        return JSONResponse(content={"decision": "reject", "reason": "UNPINNED_PROVIDER"})

    req_labels = {"owner": "student-aa0jh", "environment": "production", "cost_center": "cc-h3sz"}
    for k, v in req_labels.items():
        if r_labels.get(k) != v:
            return JSONResponse(content={"decision": "reject", "reason": "MISSING_LABELS"})

    if r_secret is not None:
        if not r_secret.startswith("secret://") or len(r_secret) == len("secret://"):
            return JSONResponse(content={"decision": "reject", "reason": "PLAINTEXT_SECRET"})

    critical_resources = {"storage_bucket", "sql_database", "persistent_disk"}
    if r_action == "delete" and r_type in critical_resources:
        if destroy_app is not True:
            return JSONResponse(content={"decision": "reject", "reason": "DELETE_NOT_APPROVED"})

    if r_type == "storage_bucket" and r_force is True:
        return JSONResponse(content={"decision": "reject", "reason": "FORCE_DESTROY"})

    return JSONResponse(content={"decision": "approve", "reason": "APPROVE"})


# --- OWASP LLM05 Firewall ---
ALLOWED_HOSTS = frozenset({"cdn-ox5ugw7.example", "app-xwwtkl4.example"})
CHANNELS = frozenset({"html", "markdown", "url", "sql", "shell"})
MAX_OUTPUT = 20000

SCRIPT_TAG_RE = re.compile(r"<\s*(?:script|iframe|object|embed)\b", re.I)
EVENT_HANDLER_RE = re.compile(r"[\s\"'/]on[a-z]+\s*=", re.I)
LITERAL_SCHEME_RE = re.compile(r"(?:javascript|data|vbscript)\s*:", re.I)
SAFE_URL_SCHEMES = frozenset({"http", "https"})
HTML_URL_RE = re.compile(r"""(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))""", re.I)
MARKDOWN_URL_RE = re.compile(r"\]\(([^)]*)\)")
SQL_METACHAR_RE = re.compile(r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1""", re.I)
SHELL_METACHAR_RE = re.compile(r"[;&|`<>]|\$\(|\$\{")

_NAMED_ENTITIES = {"lt": "<", "gt": ">", "quot": '"', "apos": "'", "amp": "&"}
ENTITY_RE = re.compile(r"&#x([0-9a-fA-F]+);|&#(\d+);|&(lt|gt|quot|apos|amp);")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")

def _entity_sub(match):
    hex_digits, dec_digits, name = match.group(1), match.group(2), match.group(3)
    try:
        if hex_digits is not None:
            return chr(int(hex_digits, 16))
        if dec_digits is not None:
            return chr(int(dec_digits))
    except (ValueError, OverflowError):
        return match.group(0)
    return _NAMED_ENTITIES[name]

def _unicode_sub(match):
    try:
        return chr(int(match.group(1), 16))
    except (ValueError, OverflowError):
        return match.group(0)

def _decode_once(text):
    decoded = unquote(text)
    decoded = ENTITY_RE.sub(_entity_sub, decoded)
    decoded = UNICODE_ESCAPE_RE.sub(_unicode_sub, decoded)
    return decoded

def _extract_urls(channel, text):
    if channel == "html":
        return [double or single or bare for double, single, bare in HTML_URL_RE.findall(text)]
    if channel == "markdown":
        targets = []
        for raw in MARKDOWN_URL_RE.findall(text):
            target = raw.strip()
            if not target: continue
            target = target.split()[0]
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            targets.append(target)
        return targets
    if channel == "url":
        stripped = text.strip()
        return [stripped] if stripped else []
    return []

def _split(url):
    try:
        return urlsplit(url)
    except ValueError:
        return None

def _bad_scheme(url):
    parts = _split(url)
    if parts is None: return True
    return bool(parts.scheme) and parts.scheme.lower() not in SAFE_URL_SCHEMES

def _external_host(url):
    candidate = "https:" + url if url.startswith("//") else url
    parts = _split(candidate)
    if parts is None: return True
    if not parts.scheme and not parts.netloc: return False
    if not parts.netloc: return False
    host = (parts.hostname or "").lower().rstrip(".")
    if not host: return True
    return host not in ALLOWED_HOSTS

def _check_dangerous_scheme(text, urls):
    if LITERAL_SCHEME_RE.search(text): return "DANGEROUS_SCHEME"
    for url in urls:
        if _bad_scheme(url): return "DANGEROUS_SCHEME"
    return None

def _check_external_exfil(urls):
    for url in urls:
        if _external_host(url): return "EXTERNAL_EXFIL"
    return None

def _channel_reason(channel, text):
    if channel == "sql": return "SQL_METACHAR" if SQL_METACHAR_RE.search(text) else "SAFE"
    if channel == "shell": return "SHELL_METACHAR" if SHELL_METACHAR_RE.search(text) else "SAFE"
    if channel == "html":
        if SCRIPT_TAG_RE.search(text): return "SCRIPT_TAG"
        if EVENT_HANDLER_RE.search(text): return "EVENT_HANDLER"
    
    urls = _extract_urls(channel, text)
    return _check_dangerous_scheme(text, urls) or _check_external_exfil(urls) or "SAFE"

def evaluate(body):
    if type(body) is not dict: return "INVALID_SCHEMA"
    channel = body.get("channel")
    output = body.get("output")
    if type(channel) is not str or channel not in CHANNELS: return "INVALID_SCHEMA"
    if type(output) is not str or len(output) > MAX_OUTPUT: return "INVALID_SCHEMA"
    
    decoded = _decode_once(output)
    if decoded != output and _channel_reason(channel, decoded) != "SAFE":
        return "ENCODED_PAYLOAD"
        
    return _channel_reason(channel, output)

@app.post("/sanitize-output")
@app.post("/sanitize-output/")
async def sanitize_output(request: Request):
    try:
        body_bytes = await request.body()
        payload = json.loads(body_bytes)
        reason = evaluate(payload)
    except Exception:
        reason = "INVALID_SCHEMA"
        
    return JSONResponse(content={"safe": reason == "SAFE", "reason": reason})