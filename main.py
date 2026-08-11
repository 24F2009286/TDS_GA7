from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re
import html
from urllib.parse import urlparse, unquote
from datetime import datetime

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
        
    violations = set() # Set prevents duplicate violation strings
    
    target = payload.get("target", "")
    event = payload.get("event", "")
    ref = payload.get("ref", "")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Least Privilege Permissions
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get("permissions") != expected_perms:
        violations.add("EXCESS_PERMISSION")

    # 2. PR Trigger Safety
    trigger = workflow.get("trigger", "")
    if (event == "pull_request" and trigger != "pull_request") or (trigger == "pull_request_target"):
        violations.add("UNSAFE_PR_TRIGGER")

    # 3. Test & Matrix Completion (Must strictly be True/False)
    if workflow.get("testsPassed") is not True or \
       workflow.get("matrixComplete") is not True or \
       workflow.get("failFast") is not False:
        violations.add("TESTS_INCOMPLETE")

    # 4. Action Pinning
    hex_sha_regex = re.compile(r'^[a-f0-9]{40}$')
    for action in workflow.get("actions", []):
        if action.get("owner") != "actions":
            if not hex_sha_regex.fullmatch(action.get("ref", "")):
                violations.add("MUTABLE_ACTION")

    # 5. Image Stage
    if image.get("multiStage") is not True:
        violations.add("SINGLE_STAGE_IMAGE")

    # 6. Image Root Runtime
    if image.get("runsAsRoot") is not False:
        violations.add("ROOT_RUNTIME")

    # 7. Image Secrets
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.add("SECRET_IN_LAYER")

    # 8. Critical Vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.add("CRITICAL_CVE")

    # 9. Pinned Image
    if image.get("digestPinned") is not True:
        violations.add("UNPINNED_IMAGE")

    # 10. Production Overrides
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.add("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.add("APPROVAL_REQUIRED")

    violations_list = list(violations)
    decision = "promote" if not violations_list else "block"
    
    return JSONResponse(content={"decision": decision, "violations": violations_list})

@app.post("/action-firewall")
async def action_firewall(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    # 1. Top-Level Schema Check
    if not isinstance(payload, dict):
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})
        
    action = payload.get("action")
    if not isinstance(action, dict) or "tool" not in action or "args" not in action:
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    tool = action.get("tool")
    args = action.get("args")
    if not isinstance(args, dict):
        return JSONResponse(content={"decision": "block", "reason": "INVALID_SCHEMA"})

    # 2. Tool Allowlist Check
    allowed_tools = {"search", "lookup_record", "send_email", "render_html"}
    if tool not in allowed_tools:
        return JSONResponse(content={"decision": "block", "reason": "TOOL_NOT_ALLOWED"})

    # 3. Selected Tool's Argument Schema Check
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

    # 4. Tenant Scope Check
    if tool == "lookup_record":
        if args["tenantId"] != "tenant-f9lp0ur":
            return JSONResponse(content={"decision": "block", "reason": "TENANT_SCOPE"})

    # 5. Exact Email Domain Check
    if tool == "send_email":
        email = args["to"]
        if not email.endswith("@notify-sl77rjl.example") or email.split("@")[-1] != "notify-sl77rjl.example":
            return JSONResponse(content={"decision": "block", "reason": "EGRESS_DENIED"})

    # 6. Human Approval Check
    if tool == "send_email":
        if payload.get("humanApproved") is not True:
            return JSONResponse(content={"decision": "block", "reason": "APPROVAL_REQUIRED"})

    # 7. HTML Safety Check
    if tool == "render_html":
        html_content = args["html"]
        # Blocks <script>, <iframe>, inline event handlers (like onload=), and javascript: URLs
        unsafe_pattern = re.compile(r'(<\s*script|<\s*iframe|\bon[a-zA-Z]+\s*=|javascript\s*:)', re.IGNORECASE)
        if unsafe_pattern.search(html_content):
            return JSONResponse(content={"decision": "block", "reason": "UNSAFE_OUTPUT"})

    # If all checks pass
    return JSONResponse(content={"decision": "allow", "reason": "ALLOW"})

@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # --- 1. Schema & Type Check ---
    if type(payload) is not dict:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # Check required top-level keys
    req_keys = {"environment", "state", "providerVersion", "destroyApproved", "resource"}
    if not req_keys.issubset(payload.keys()):
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    env = payload["environment"]
    state = payload["state"]
    prov_ver = payload["providerVersion"]
    destroy_app = payload["destroyApproved"]
    res = payload["resource"]

    # Strict type checks (type() is safer than isinstance() for bools/ints in Python)
    if type(env) is not str or type(state) is not dict or \
       type(prov_ver) is not str or type(destroy_app) is not bool or \
       type(res) is not dict:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # Check state keys
    if "backend" not in state or "locked" not in state:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})
    
    state_backend = state["backend"]
    state_locked = state["locked"]
    if type(state_backend) is not str or type(state_locked) is not bool:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # Check resource keys
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
    
    # Secret must be explicitly None (null in JSON) or string
    if r_secret is not None and type(r_secret) is not str:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})
        
    # Labels must be strictly string:string
    if any(type(k) is not str or type(v) is not str for k, v in r_labels.items()):
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # THE FIX: Action must strictly be one of the enum values
    if r_action not in {"create", "update", "delete"}:
        return JSONResponse(content={"decision": "reject", "reason": "INVALID_PLAN"})

    # --- 2. Environment Match ---
    if env != "prod-yj9jdn":
        return JSONResponse(content={"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"})

    # --- 3. State Safety ---
    valid_backends = {"gcs", "s3", "azurerm", "remote"}
    if state_backend not in valid_backends or state_locked is not True:
        return JSONResponse(content={"decision": "reject", "reason": "STATE_UNSAFE"})

    # --- 4. Provider Version Pinning ---
    prov_ver_clean = prov_ver.strip()
    is_exact = re.match(r'^=?\s*\d+\.\d+(\.\d+)?$', prov_ver_clean)
    is_pessimistic = re.match(r'^~>\s*\d+\.\d+(\.\d+)?$', prov_ver_clean)
    
    if not (is_exact or is_pessimistic):
        return JSONResponse(content={"decision": "reject", "reason": "UNPINNED_PROVIDER"})

    # --- 5. Missing Labels ---
    req_labels = {"owner": "student-aa0jh", "environment": "production", "cost_center": "cc-h3sz"}
    for k, v in req_labels.items():
        if r_labels.get(k) != v:
            return JSONResponse(content={"decision": "reject", "reason": "MISSING_LABELS"})

    # --- 6. Plaintext Secret ---
    if r_secret is not None:
        if not r_secret.startswith("secret://") or len(r_secret) == len("secret://"):
            return JSONResponse(content={"decision": "reject", "reason": "PLAINTEXT_SECRET"})

    # --- 7. Delete Not Approved ---
    critical_resources = {"storage_bucket", "sql_database", "persistent_disk"}
    if r_action == "delete" and r_type in critical_resources:
        if destroy_app is not True:
            return JSONResponse(content={"decision": "reject", "reason": "DELETE_NOT_APPROVED"})

    # --- 8. Force Destroy ---
    if r_type == "storage_bucket" and r_force is True:
        return JSONResponse(content={"decision": "reject", "reason": "FORCE_DESTROY"})

    # --- Pass ---
    return JSONResponse(content={"decision": "approve", "reason": "APPROVE"})


# =====================================================================
#  LLM Output Handling Gate  –  OWASP LLM05
#  POST /sanitize-output
# =====================================================================

ALLOWED_HOSTS = {"cdn-ox5ugw7.example", "app-xwwtkl4.example"}
VALID_CHANNELS = {"html", "markdown", "url", "sql", "shell"}

# ── Decoding helpers ─────────────────────────────────────────────────

def decode_percent_escapes(s: str) -> str:
    """Decode %XX sequences. Unlike urllib.unquote this never throws."""
    return re.sub(
        r'%([0-9A-Fa-f]{2})',
        lambda m: chr(int(m.group(1), 16)),
        s
    )

def decode_html_entities(s: str) -> str:
    """Decode &#NN; &#xNN; and the five named entities. &amp; decoded LAST."""
    s = re.sub(r'&#x([0-9A-Fa-f]+);', lambda m: chr(int(m.group(1), 16)), s, flags=re.IGNORECASE)
    s = re.sub(r'&#(\d+);', lambda m: chr(int(m.group(1))), s)
    s = s.replace('&lt;', '<')
    s = s.replace('&gt;', '>')
    s = s.replace('&quot;', '"')
    s = s.replace('&apos;', "'")
    s = s.replace('&amp;', '&')
    return s

def decode_unicode_escapes(s: str) -> str:
    """Decode \\uXXXX sequences."""
    return re.sub(
        r'\\u([0-9A-Fa-f]{4})',
        lambda m: chr(int(m.group(1), 16)),
        s,
        flags=re.IGNORECASE
    )

def full_decode(s: str) -> str:
    """Single-pass decode: percent → HTML entities → \\uXXXX."""
    r = decode_percent_escapes(s)
    r = decode_html_entities(r)
    r = decode_unicode_escapes(r)
    return r

# ── Detection checks ─────────────────────────────────────────────────

def has_script_tag(text: str) -> bool:
    return bool(re.search(r'<\s*(script|iframe|object|embed)\b', text, re.IGNORECASE))

def has_event_handler(text: str) -> bool:
    return bool(re.search(r'\bon[a-z]+\s*=', text, re.IGNORECASE))

def has_dangerous_scheme_in_text(text: str) -> bool:
    return bool(re.search(r'(javascript|data|vbscript)\s*:', text, re.IGNORECASE))

def is_absolute_url(u: str) -> bool:
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*:', u)) or u.startswith('//')

def safe_parse_url(u: str):
    """Parse a URL string, resolving protocol-relative as https."""
    try:
        if u.startswith('//'):
            return urlparse('https:' + u)
        return urlparse(u)
    except Exception:
        return None

def extract_urls(channel: str, text: str) -> list:
    urls = []
    if channel == 'html':
        for m in re.finditer(r'''(?:src|href)\s*=\s*(["'])([\s\S]*?)\1''', text, re.IGNORECASE):
            urls.append(m.group(2))
    elif channel == 'markdown':
        for m in re.finditer(r'\]\(([^)]*)\)', text):
            url = m.group(1).strip()
            sp = url.find(' ')
            if sp != -1:
                url = url[:sp]
            urls.append(url)
    elif channel == 'url':
        urls.append(text.strip())
    return urls

def check_dangerous_scheme(channel: str, text: str) -> bool:
    if has_dangerous_scheme_in_text(text):
        return True
    for u in extract_urls(channel, text):
        if not is_absolute_url(u):
            continue
        parsed = safe_parse_url(u)
        if parsed and parsed.scheme:
            scheme = parsed.scheme.lower()
            if scheme not in ('http', 'https'):
                return True
    return False

def check_external_exfil(channel: str, text: str) -> bool:
    for u in extract_urls(channel, text):
        if not is_absolute_url(u):
            continue
        parsed = safe_parse_url(u)
        if parsed and parsed.hostname:
            host = parsed.hostname.lower()
            if host not in ALLOWED_HOSTS:
                return True
    return False

def check_sql_metachar(text: str) -> bool:
    if re.search(r"""['";]""", text):
        return True
    if '--' in text:
        return True
    if '/*' in text:
        return True
    if re.search(r'\bunion\b', text, re.IGNORECASE):
        return True
    if re.search(r'\bor\s+1\s*=\s*1', text, re.IGNORECASE):
        return True
    return False

def check_shell_metachar(text: str) -> bool:
    if re.search(r'[;&|`<>]', text):
        return True
    if '$(' in text:
        return True
    if '${' in text:
        return True
    return False

# ── Channel violation dispatcher ─────────────────────────────────────

def get_channel_violation(channel: str, text: str):
    if channel == 'html':
        if has_script_tag(text):                    return 'SCRIPT_TAG'
        if has_event_handler(text):                 return 'EVENT_HANDLER'
        if check_dangerous_scheme(channel, text):   return 'DANGEROUS_SCHEME'
        if check_external_exfil(channel, text):     return 'EXTERNAL_EXFIL'
    elif channel in ('markdown', 'url'):
        if check_dangerous_scheme(channel, text):   return 'DANGEROUS_SCHEME'
        if check_external_exfil(channel, text):     return 'EXTERNAL_EXFIL'
    elif channel == 'sql':
        if check_sql_metachar(text):                return 'SQL_METACHAR'
    elif channel == 'shell':
        if check_shell_metachar(text):              return 'SHELL_METACHAR'
    return None

# ── Endpoint ─────────────────────────────────────────────────────────

@app.post("/sanitize-output")
async def sanitize_output(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"})

    # Rule 1: INVALID_SCHEMA
    if not isinstance(body, dict):
        return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"})
    channel = body.get("channel")
    output = body.get("output")
    if channel not in VALID_CHANNELS:
        return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"})
    if not isinstance(output, str):
        return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"})
    if len(output) > 20000:
        return JSONResponse(content={"safe": False, "reason": "INVALID_SCHEMA"})

    # Rule 2: ENCODED_PAYLOAD
    decoded = full_decode(output)
    if decoded != output:
        if get_channel_violation(channel, decoded):
            return JSONResponse(content={"safe": False, "reason": "ENCODED_PAYLOAD"})

    # Rule 3: Channel rules on original output
    violation = get_channel_violation(channel, output)
    if violation:
        return JSONResponse(content={"safe": False, "reason": violation})

    return JSONResponse(content={"safe": True, "reason": "SAFE"})



# ==========================================
# GATE 5: OSINT Corroboration Engine
# ==========================================
@app.post("/corroborate")
@app.post("/corroborate/")
async def corroborate(request: Request):
    # 1. Safe extraction and JSON parsing
    try:
        body_bytes = await request.body()
        if not body_bytes:
            return JSONResponse(content={"verdict": "invalid", "confidence": "low", "corroboratingSources": []})
        payload = json.loads(body_bytes)
    except Exception:
        return JSONResponse(content={"verdict": "invalid", "confidence": "low", "corroboratingSources": []})

    def invalid_response():
        return JSONResponse(content={"verdict": "invalid", "confidence": "low", "corroboratingSources": []})

    # 2. Strict Schema Validation (Rule 1)
    if type(payload) is not dict:
        return invalid_response()

    claim = payload.get("claim")
    if type(claim) is not dict:
        return invalid_response()
    
    claim_val = claim.get("value")
    if type(claim_val) is not str:
        return invalid_response()

    as_of_str = payload.get("asOf")
    if type(as_of_str) is not str:
        return invalid_response()
    
    try:
        # Standardize Zulu time to offset for strict parsing
        as_of_dt = datetime.fromisoformat(as_of_str.replace("Z", "+00:00"))
    except Exception:
        return invalid_response()

    staleness_days = payload.get("stalenessDays")
    # Booleans are a subclass of int in Python, so strict type exclusion is required
    if not isinstance(staleness_days, (int, float)) or type(staleness_days) is bool:
        return invalid_response()

    sources = payload.get("sources")
    if type(sources) is not list:
        return invalid_response()

    # 3. Source Filtration (Freshness and Validity)
    allowed_types = {"dns", "ct_log", "registry", "archive", "scan"}
    valid_sources = []
    
    for s in sources:
        if type(s) is not dict: continue
        if type(s.get("id")) is not str: continue
        if type(s.get("origin")) is not str: continue
        if type(s.get("value")) is not str: continue
        if type(s.get("observedAt")) is not str: continue
        if s.get("type") not in allowed_types: continue
        
        try:
            obs_dt = datetime.fromisoformat(s["observedAt"].replace("Z", "+00:00"))
        except Exception:
            continue
            
        # Calculate freshness
        delta_days = (as_of_dt - obs_dt).total_seconds() / 86400.0
        if delta_days <= staleness_days:
            valid_sources.append(s)

    # 4. Rule 2: Contradicted
    contradicting = []
    for s in valid_sources:
        if s.get("authoritative") is True and s["value"] != claim_val:
            contradicting.append(s["id"])
            
    if contradicting:
        return JSONResponse(content={
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting)
        })

    # 5. Rule 3: Supported
    origins = {}
    for s in valid_sources:
        if s["value"] == claim_val:
            origin = s["origin"]
            if origin not in origins:
                origins[origin] = []
            origins[origin].append(s)

    reps = []
    for origin, orig_sources in origins.items():
        # Representative is the source with the lexicographically smallest ID
        rep = min(orig_sources, key=lambda x: x["id"])
        reps.append(rep)

    if len(reps) >= 2:
        types = set(r["type"] for r in reps)
        confidence = "high" if len(types) >= 2 else "medium"
        return JSONResponse(content={
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": sorted(r["id"] for r in reps)
        })

    # 6. Rule 4: Unverified
    return JSONResponse(content={
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    })