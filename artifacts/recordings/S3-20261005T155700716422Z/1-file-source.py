"""File-only control: load the fake file and report success; no network request."""
from datetime import datetime, timezone
import json
from pathlib import Path
import socket

def main():
    try:
        path = Path("/run/demo-secrets/credentials-demo.json")
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        if payload.get("purpose") != "demo-only":
            raise ValueError("Expected demo-only credential file")
        print(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "container_hostname": socket.gethostname(),
            "event": "demo_file_read",
            "path": str(path),
            "mode": "file_only",
        }), flush=True)
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"event": "demo_error", "error": str(error)}), flush=True)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
