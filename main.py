from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

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