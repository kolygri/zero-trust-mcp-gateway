#!/usr/bin/env python3
"""Run the compiled gateway and resource with temporary signed policy and secrets."""
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    # The generated signed example binds these exact endpoints. Fail explicitly
    # on collisions rather than silently exercising someone else's process.
    for port in (8080, 8091):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", port))
    processes = []
    with tempfile.TemporaryDirectory(prefix="zero-trust-gateway-") as tmp:
        demo = Path(tmp) / "demo"
        subprocess.run([str(ROOT / "bin/gateway"), "init-demo", "-dir", str(demo)], check=True)
        env = dict(os.environ)
        for line in (demo / "demo.env").read_text().splitlines():
            assignment = shlex.split(line)[1]
            key, value = assignment.split("=", 1)
            env[key] = value
        try:
            for argv in ([str(ROOT / "bin/mock-resource"), "-listen", "127.0.0.1:8091", "-state", str(demo / "resource.json")], [str(ROOT / "bin/gateway"), "-config", str(demo / "gateway.json")]):
                processes.append(subprocess.Popen(argv, env=env))
            for _ in range(100):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("demo process exited during startup")
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=0.2):
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise RuntimeError("gateway did not become live")
            # Health checks cover the gateway, so wait for the protected resource
            # endpoint to respond (401 is the correct anonymous response).
            for _ in range(100):
                try:
                    urllib.request.urlopen("http://127.0.0.1:8091/operations", timeout=0.2)
                except urllib.error.HTTPError as error:
                    if error.code == 401:
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise RuntimeError("resource did not become live")
            subprocess.run([os.environ.get("PYTHON", "python3"), str(ROOT / "scripts/demo.py")], env=env, check=True)
            ground_truth = json.loads((demo / "resource.json").read_text())
            if ground_truth["publications"] != 1:
                raise RuntimeError("resource-side oracle observed duplicate or missing effect")
            print("PASS: independent resource state contains exactly one publication")
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
