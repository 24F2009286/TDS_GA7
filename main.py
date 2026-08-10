from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    payload = await request.json()
    violations = []
    
    target = payload.get("target", "")
    event = payload.get("event", "")
    ref = payload.get("ref", "")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Least Privilege Permissions
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get("permissions") != expected_perms:
        violations.append("EXCESS_PERMISSION")

    # 2. PR Trigger Safety
    if event == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # 3. Test & Matrix Completion
    if not workflow.get("testsPassed") or not workflow.get("matrixComplete") or workflow.get("failFast", True):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning (Third-party actions must use 40-char hex SHA)
    hex_sha_regex = re.compile(r'^[a-f0-9]{40}$')
    for action in workflow.get("actions", []):
        if action.get("owner") != "actions":
            if not hex_sha_regex.fullmatch(action.get("ref", "")):
                violations.append("MUTABLE_ACTION")
                break # Only need to append once

    # 5. Image Stage
    if not image.get("multiStage"):
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Image Root Runtime
    if image.get("runsAsRoot"):
        violations.append("ROOT_RUNTIME")

    # 7. Image Secrets
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. Critical Vulnerabilities
    if image.get("criticalVulnerabilities", 1) > 0:
        violations.append("CRITICAL_CVE")

    # 9. Pinned Image
    if not image.get("digestPinned"):
        violations.append("UNPINNED_IMAGE")

    # 10. Production Overrides
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if not workflow.get("environmentApproval"):
            violations.append("APPROVAL_REQUIRED")

    # Compile Final Decision
    decision = "promote" if not violations else "block"
    
    return JSONResponse(content={"decision": decision, "violations": violations})