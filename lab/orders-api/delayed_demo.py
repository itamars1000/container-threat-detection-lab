"""Delayed control: read fake credentials, wait 75 seconds, then GET lab-sink."""
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import time
from urllib.request import urlopen

DELAY_SECONDS = 75

def emit(event, **fields):
    print(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "container_hostname": socket.gethostname(),
        "event": event, **fields,
    }), flush=True)

def main():
    try:
        path = Path("/run/demo-secrets/credentials-demo.json")
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
        if payload.get("purpose") != "demo-only":
            raise ValueError("Expected demo-only credential file")
        emit("demo_file_read", path=str(path))
        emit("demo_wait_start", seconds=DELAY_SECONDS)
        time.sleep(DELAY_SECONDS)
        emit("http_request_start", destination="lab-sink", port=8080)
        with urlopen("http://lab-sink:8080/health", timeout=3) as response:
            reply = json.load(response)
            status = response.status
        if status != 200 or reply.get("service") != "lab-sink" or reply.get("status") != "ok":
            raise ValueError("Unexpected target response")
        emit("http_response", destination="lab-sink", status_code=status,
             response_service=reply["service"])
        return 0
    except (OSError, ValueError) as error:
        emit("demo_error", error=str(error))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
