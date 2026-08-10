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