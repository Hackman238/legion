import subprocess
import json
import sys
import time

def send_request(proc, request):
    try:
        proc.stdin.write((json.dumps(request) + "\n").encode())
        proc.stdin.flush()
        response = proc.stdout.readline()
        print("Raw response:", repr(response.decode()))
        return json.loads(response.decode())
    except BrokenPipeError:
        # Print any stderr output from the subprocess for debugging
        stderr_output = proc.stderr.read().decode()
        print("MCP server process exited unexpectedly. Stderr output:")
        print(stderr_output)
        sys.exit(1)

if __name__ == "__main__":
    # Start the MCP server as a subprocess
    proc = subprocess.Popen(
        [sys.executable, "app/mcpServer.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Give the server a moment to start
    time.sleep(0.5)

    # Check if the process has already exited
    if proc.poll() is not None:
        stderr_output = proc.stderr.read().decode()
        print("MCP server process exited immediately. Stderr output:")
        print(stderr_output)
        sys.exit(1)

    # 1. List available tools
    req1 = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "list_tools"
    }
    resp1 = send_request(proc, req1)
    print("list_tools response:")
    print(json.dumps(resp1, indent=2))

    # 2. Call the 'list_projects' tool
    req2 = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "call_tool",
        "params": {"name": "list_projects", "arguments": {}}
    }
    resp2 = send_request(proc, req2)
    print("\ncall_tool (list_projects) response:")
    print(json.dumps(resp2, indent=2))

    # 3. Call the 'run_discovery' tool (default: localhost)
    req3 = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "call_tool",
        "params": {"name": "run_discovery", "arguments": {}}
    }
    resp3 = send_request(proc, req3)
    print("\ncall_tool (run_discovery, default localhost) FULL RESPONSE:")
    print(json.dumps(resp3, indent=2))

    # 4. Call the 'run_discovery' tool with a custom target
    req4 = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "call_tool",
        "params": {"name": "run_discovery", "arguments": {"target": "192.168.1.1"}}
    }
    resp4 = send_request(proc, req4)
    print("\ncall_tool (run_discovery, target 192.168.1.1) FULL RESPONSE:")
    print(json.dumps(resp4, indent=2))

    # Clean up
    proc.terminate()
    proc.wait()
