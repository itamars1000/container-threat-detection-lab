"""Capture current lab container identities and validate the demo-file mounts."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {"orders-api", "allowed-api", "lab-sink"}
SECRET_PATH = "/run/demo-secrets/credentials-demo.json"


def docker(*args):
    return subprocess.check_output(["sudo", "docker", *args], cwd=ROOT, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/environment.json")
    args = parser.parse_args()

    ids = docker("compose", "-f", "lab/compose.yaml", "ps", "-q").split()
    if not ids:
        raise SystemExit("No running lab containers found")
    raw = json.loads(docker("inspect", *ids))
    containers = []
    credential_mounts = []
    source_path = str((ROOT / "lab/demo-secrets/credentials-demo.json").resolve())

    for item in raw:
        service = item["Config"]["Labels"].get("com.docker.compose.service")
        mounts = [{"source": m["Source"], "destination": m["Destination"],
                   "read_only": not m["RW"]} for m in item["Mounts"]]
        for mount in mounts:
            if mount["source"] == source_path or mount["destination"] == SECRET_PATH:
                credential_mounts.append({"service": service, **mount})
        containers.append({
            "service": service,
            "container_id": item["Id"],
            "hostname": item["Config"]["Hostname"],
            "image_id": item["Image"],
            "running": item["State"]["Running"],
            "health": item["State"].get("Health", {}).get("Status", "none"),
            "networks": {name: {"ipv4": net["IPAddress"]}
                         for name, net in item["NetworkSettings"]["Networks"].items()},
            "mounts": mounts,
        })

    checks = {
        "expected_services_present": (
            len(containers) == len(SERVICES)
            and {c["service"] for c in containers} == SERVICES
        ),
        "all_running_healthy": all(c["running"] and c["health"] == "healthy" for c in containers),
        "credential_mount_only_orders_api": (
            len(credential_mounts) == 1
            and credential_mounts[0]["service"] == "orders-api"
            and credential_mounts[0]["source"] == source_path
            and credential_mounts[0]["destination"] == SECRET_PATH
        ),
        "credential_mount_read_only": (
            len(credential_mounts) == 1 and credential_mounts[0]["read_only"]
        ),
    }
    snapshot = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "kernel": platform.release(),
        "containers": sorted(containers, key=lambda c: c["service"]),
        "checks": checks,
        "valid": all(checks.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(snapshot, indent=2))
    return 0 if snapshot["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
