"""Controlled file-read then HTTP-request exercise; never sends credentials."""
import argparse
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

CREDENTIALS = Path("/run/demo-secrets/credentials-demo.json")


def emit(event, **fields):
    print(json.dumps({
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "container_hostname": socket.gethostname(),
        "event": event,
        **fields,
    }), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("allowed-api", "lab-sink"), default="allowed-api")
    args = parser.parse_args()

    try:
        with CREDENTIALS.open("r", encoding="utf-8") as handle:
            credentials = json.load(handle)
        if credentials.get("purpose") != "demo-only":
            raise ValueError("Expected demo-only credential file")
        emit("demo_file_read", path=str(CREDENTIALS))

        url = f"http://{args.target}:8080/health"
        emit("http_request_start", destination=args.target, port=8080)
        with urlopen(url, timeout=3) as response:
            payload = json.load(response)
            status_code = response.status
        if payload.get("service") != args.target or payload.get("status") != "ok":
            raise ValueError("Unexpected target response")
        emit("http_response", destination=args.target, status_code=status_code,
             response_service=payload["service"])
    except (OSError, ValueError) as error:
        emit("demo_error", error=str(error))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
