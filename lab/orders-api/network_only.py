"""Network-only control: GET lab-sink health without opening the demo file."""
from datetime import datetime, timezone
import json
import socket
from urllib.request import urlopen

def main():
    try:
        with urlopen("http://lab-sink:8080/health", timeout=3) as response:
            payload = json.load(response)
            status = response.status
        if status != 200 or payload.get("service") != "lab-sink" or payload.get("status") != "ok":
            raise ValueError("Unexpected target response")
        print(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "container_hostname": socket.gethostname(),
            "event": "http_response",
            "destination": "lab-sink",
            "status_code": status,
            "response_service": payload["service"],
            "mode": "network_only",
        }), flush=True)
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"event": "demo_error", "error": str(error)}), flush=True)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
