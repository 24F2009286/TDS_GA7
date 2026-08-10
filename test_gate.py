import requests
import sys

def test_release_gate():
    url = "http://localhost:8000/release-gate"
    
    # Perfect Payload
    safe_payload = {
        "target": "preview",
        "event": "push",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "push",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True, "matrixComplete": True, "failFast": False,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}]
        },
        "image": {
            "multiStage": True, "runsAsRoot": False, "secretMode": "buildkit",
            "criticalVulnerabilities": 0, "digestPinned": True
        }
    }
    
    # Unsafe Payload
    unsafe_payload = safe_payload.copy()
    unsafe_payload["workflow"]["permissions"] = {"contents": "write"}
    
    try:
        r_safe = requests.post(url, json=safe_payload).json()
        assert r_safe["decision"] == "promote", f"Safe payload failed: {r_safe}"
        assert len(r_safe["violations"]) == 0
        
        r_unsafe = requests.post(url, json=unsafe_payload).json()
        assert r_unsafe["decision"] == "block"
        assert "EXCESS_PERMISSION" in r_unsafe["violations"]
        
        print("All policy tests passed successfully.")
        sys.exit(0)
    except Exception as e:
        print(f"Test failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_release_gate()