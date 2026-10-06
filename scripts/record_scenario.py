"""Record a controlled scenario with separate ground truth and bounded collection checks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone
import yaml

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "artifacts/falco-project"


def utc():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def docker(*args):
    return subprocess.check_output(["sudo", "docker", *args], cwd=ROOT, text=True)


def sensor():
    ids = docker("compose", "-f", "falco/compose.yaml", "ps", "-q").split()
    if len(ids) != 1:
        raise RuntimeError("Falco must be running: start it before recording.")
    item = json.loads(docker("inspect", ids[0]))[0]
    if not item["State"]["Running"]:
        raise RuntimeError("Falco is not running.")
    return {"container_id": item["Id"], "started_at": item["State"]["StartedAt"]}


def latest_metric():
    path = CAPTURES / "metrics.jsonl"
    if not path.exists():
        return None
    # Read only the tail; metrics files can grow during prolonged monitoring.
    with path.open("rb") as stream:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - 131072))
        lines = stream.read().splitlines()
    for line in reversed(lines):
        try:
            value = json.loads(line)
            if "falco.start_ts" in value.get("output_fields", {}):
                return value
        except json.JSONDecodeError:
            pass
    return None


def next_metric(previous_time):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        item = latest_metric()
        if item and item["output_fields"]["evt.time"] > previous_time:
            return item
        time.sleep(0.25)
    raise RuntimeError("No fresh metrics sample within 15 seconds; capture is incomplete.")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("B1", "S1", "B2", "B3", "S2", "M1"))
    args = parser.parse_args(argv)
    case = json.loads((ROOT / "scenarios" / (args.scenario + ".json")).read_text())
    target = case["target"]
    delayed_connection = case.get("action") == "delayed_connection"
    cross_container = case.get("action") == "cross_container"
    file_only = case.get("action") == "file_only" or cross_container
    action_input = None
    if case.get("action") == "maintenance":
        command = ["python", "-", "maintenance-demo"]
        action_input = (ROOT / "lab/orders-api/maintenance_demo.py").read_text()
    elif delayed_connection:
        command = ["python", "-"]
        action_input = (ROOT / "lab/orders-api/delayed_demo.py").read_text()
    elif file_only:
        # Execute reviewed source via stdin in the existing read-only container.
        # No image rebuild or identity/policy change is needed.
        command = ["python", "-"]
        action_input = (ROOT / "lab/orders-api/file_only.py").read_text()
    else:
        if target not in {"allowed-api", "lab-sink"}:
            raise SystemExit("Unsupported controlled target")
        command = ["python", "demo.py"]
        if target != "allowed-api":
            command += ["--target", target]
    expected_command = " ".join(command)
    before_sensor = sensor()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "artifacts/recordings" / (args.scenario + "-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    save(out / "ground-truth.json", case)
    manifest = {"schema_version": 1, "recording_id": out.name,
                "created_at": utc(), "status": "incomplete",
                "sensor_before": before_sensor, "limitations": [
                    "One short low-load recording; not a stress or accuracy benchmark.",
                    "File-open and connect events do not prove exfiltration.",
                    "Ground truth is stored separately from detector input.",
                    "Run this exercise alone; overlapping manual demos can contaminate attribution."]}
    save(out / "manifest.json", manifest)
    try:
        snapshot_run = subprocess.run(
            ["python3", "scripts/snapshot_environment.py", "--output", str(out / "environment.json")],
            cwd=ROOT, text=True, capture_output=True, timeout=30)
        (out / "snapshot.stderr.txt").write_text(snapshot_run.stderr, encoding="utf-8")
        if snapshot_run.returncode:
            raise RuntimeError("Environment checks failed; see environment.json/snapshot.stderr.txt.")
        env = json.loads((out / "environment.json").read_text())
        policy = yaml.safe_load((ROOT / "config/policy.baseline.yaml").read_text())
        services = {c["service"]: c for c in env["containers"]}
        for monitored in policy["monitored_containers"]:
            if services[monitored["service"]]["container_id"] != monitored["container_full_id"]:
                raise RuntimeError("Monitored identity changed; refresh policy AND rules.")
        for dest in policy["expected_destinations"]:
            service = "orders-api" if dest["service"] == "orders-api-self" else dest["service"]
            current = services[service]
            if current["container_id"] != dest["container_full_id"]:
                raise RuntimeError("Destination identity changed; review policy.")
            if dest["ip"] != "127.0.0.1":
                ip = current["networks"][policy["environment_binding"]["network"]]["ipv4"]
                if ip != dest["ip"]:
                    raise RuntimeError("Destination IP changed; review policy.")
        for source, name in [(ROOT / "config/policy.baseline.yaml", "policy.yaml"),
                             (ROOT / "falco/rules.yaml", "rules.yaml")]:
            (out / name).write_bytes(source.read_bytes())
        manifest["policy_version"] = policy["policy_version"]
        manifest["rules_sha256"] = sha(out / "rules.yaml")
        manifest["policy_sha256"] = sha(out / "policy.yaml")
        prior = latest_metric()
        before = next_metric(prior["output_fields"]["evt.time"] if prior else 0)
        fields = before["output_fields"]
        if fields.get("falco.sha256_rules_file.lab_rules_yaml") != manifest["rules_sha256"]:
            raise RuntimeError("Loaded Falco rules differ from saved rules; restart sensor.")
        events_path = CAPTURES / "events.jsonl"
        stat = events_path.stat()
        start_offset = stat.st_size
        manifest["action_started_at"] = utc()
        if delayed_connection:
            print("S2: reading the demo file, waiting 75 seconds, then connecting. Keep Falco running.",
                  file=sys.stderr, flush=True)
        result = subprocess.run(
            ["sudo", "docker", "compose", "-f", "lab/compose.yaml", "exec", "-T",
             "orders-api", *command],
            cwd=ROOT, capture_output=True, text=True, input=action_input, timeout=110 if delayed_connection else 20)
        second_result = None
        if cross_container:
            network_source = (ROOT / "lab/orders-api/network_only.py").read_text()
            second_result = subprocess.run(
                ["sudo", "docker", "compose", "-f", "lab/compose.yaml", "exec", "-T",
                 case["network_service"], "python", "-"],
                cwd=ROOT, capture_output=True, text=True, input=network_source, timeout=20)
            (out / "network.stdout.jsonl").write_text(second_result.stdout, encoding="utf-8")
            (out / "network.stderr.txt").write_text(second_result.stderr, encoding="utf-8")
            (out / "network-action-source.py").write_text(network_source, encoding="utf-8")
            manifest["network_action_source_sha256"] = sha(out / "network-action-source.py")
        manifest["action_finished_at"] = utc()
        # This log is supporting evidence; Falco timestamps remain the correlation clock.
        if target is not None:
            target_log = docker("compose", "-f", "lab/compose.yaml", "logs",
                                "--since", manifest["action_started_at"], "--tail", "50", target)
            (out / "target.log").write_text(target_log, encoding="utf-8")
        if action_input is not None:
            (out / "action-source.py").write_text(action_input, encoding="utf-8")
            manifest["action_source_sha256"] = sha(out / "action-source.py")
        (out / "demo.stdout.jsonl").write_text(result.stdout, encoding="utf-8")
        (out / "demo.stderr.txt").write_text(result.stderr, encoding="utf-8")
        # First obtain a metrics sample that is known to be later than action completion.
        current = latest_metric()
        if current is None:
            raise RuntimeError("Metrics disappeared during recording.")
        after = next_metric(current["output_fields"]["evt.time"])
        time.sleep(1)  # Allow the file-output writer to finish; still a bounded window.
        after_sensor = sensor()
        now_stat = events_path.stat()
        if now_stat.st_ino != stat.st_ino or now_stat.st_size < start_offset:
            raise RuntimeError("Event file rotated or truncated during recording.")
        with events_path.open("rb") as stream:
            stream.seek(start_offset)
            raw = stream.read(now_stat.st_size - start_offset)
        (out / "events.jsonl").write_bytes(raw)
        save(out / "metrics-before.json", before)
        save(out / "metrics-after.json", after)
        parsed = [json.loads(line) for line in raw.splitlines() if line.strip()]
        app = [e for e in parsed if e.get("output_fields", {}).get("proc.cmdline") == expected_command
               and e["output_fields"].get("container.full_id") == services["orders-api"]["container_id"]]
        opens = [e for e in app if e["rule"] == "Lab sensitive file opened for reading"
                 and e["output_fields"].get("evt.res") == "SUCCESS"]
        app_connects = [e for e in app
                        if e["rule"] == "Lab monitored outbound TCP connect attempt"]
        connects = [] if file_only else [
            e for e in app_connects
            if e["output_fields"].get("fd.sip") ==
               services[target]["networks"][policy["environment_binding"]["network"]]["ipv4"]
            and e["output_fields"].get("fd.sport") == 8080]
        bf, af = before["output_fields"], after["output_fields"]
        demo = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        checks = {
            "scenario_succeeded": result.returncode == 0 and (
                any(d.get("event") == "demo_file_read" and d.get("mode") == "file_only"
                    for d in demo) if file_only else any(
                    d.get("event") == "http_response" and d.get("status_code") == 200
                    and d.get("response_service") == target for d in demo)),
            "sensor_unchanged": before_sensor == after_sensor,
            "same_sensor_start_and_reload": all(bf.get(k) is not None and bf[k] == af.get(k)
                for k in ("falco.start_ts", "falco.reload_ts")),
            "rules_unchanged": sha(ROOT / "falco/rules.yaml") == manifest["rules_sha256"]
                == af.get("falco.sha256_rules_file.lab_rules_yaml"),
            "policy_unchanged": sha(ROOT / "config/policy.baseline.yaml") == manifest["policy_sha256"],
            "kernel_events_processed": af["scap.n_evts"] > bf["scap.n_evts"],
            "no_kernel_drops_in_window": af["scap.n_drops"] == bf["scap.n_drops"],
            "no_output_queue_drops_in_window": af["falco.outputs_queue_num_drops"] == bf["falco.outputs_queue_num_drops"],
            "file_signal_received": bool(opens),
        }
        if file_only:
            checks["no_network_signal_from_control_process_observed"] = not app_connects
        else:
            checks["scenario_target_connect_received"] = bool(connects)
            pair_deltas = [
                n["output_fields"]["evt.rawtime"] - f["output_fields"]["evt.rawtime"]
                for f in opens for n in connects
                if n["output_fields"]["proc.pid"] == f["output_fields"]["proc.pid"]]
            window_ns = policy["correlation"]["lookback_seconds"] * 1_000_000_000
            if delayed_connection:
                checks["same_process_pair_outside_window_received"] = any(
                    delta > window_ns for delta in pair_deltas)
                checks["no_same_process_pair_inside_window_observed"] = not any(
                    0 < delta <= window_ns for delta in pair_deltas)
                manifest["same_process_pair_deltas_ns"] = pair_deltas
            else:
                checks["ordered_same_process_pair_received"] = any(
                    0 < delta <= window_ns for delta in pair_deltas)
        if cross_container:
            network_demo = [json.loads(line) for line in second_result.stdout.splitlines() if line.strip()]
            network_id = services[case["network_service"]]["container_id"]
            control_events = [e for e in parsed
                              if e["output_fields"].get("container.full_id") == network_id
                              and e["output_fields"].get("proc.cmdline") == "python -"]
            other_connects = [e for e in control_events
                              if e["rule"] == "Lab monitored outbound TCP connect attempt"
                              and e["output_fields"].get("fd.sip") ==
                                  services[target]["networks"][policy["environment_binding"]["network"]]["ipv4"]
                              and e["output_fields"].get("fd.sport") == 8080]
            checks["network_action_succeeded"] = second_result.returncode == 0 and any(
                d.get("event") == "http_response" and d.get("response_service") == target
                and d.get("status_code") == 200 for d in network_demo)
            checks["other_container_connect_received"] = bool(other_connects)
            checks["signals_from_different_containers"] = bool(opens and other_connects) and all(
                f["output_fields"]["container.full_id"] != n["output_fields"]["container.full_id"]
                for f in opens for n in other_connects)
            checks["ordered_cross_container_signals_received"] = any(
                0 < n["output_fields"]["evt.rawtime"] - f["output_fields"]["evt.rawtime"] <= 60_000_000_000
                for f in opens for n in other_connects)
            checks["no_sensitive_file_signal_from_network_control_observed"] = not any(
                e["rule"] == "Lab sensitive file opened for reading" for e in control_events)
        save(out / "collection-checks.json", {"checks": checks, "valid": all(checks.values()),
                                             "matched_rule_events": len(parsed)})
        manifest.update({"sensor_after": after_sensor,
                         "sensor_run_id": str(bf["falco.start_ts"]),
                         "host_boot_ts": bf.get("falco.host_boot_ts"),
                         "sensor_hostname": bf.get("evt.hostname"),
                         "event_byte_range": [start_offset, now_stat.st_size],
                         "completed_at": utc(),
                         "status": "complete" if all(checks.values()) else "invalid",
                         "events_sha256": sha(out / "events.jsonl")})
        save(out / "manifest.json", manifest)
        print(json.dumps({"recording": str(out), "status": manifest["status"],
                          "collection_checks": checks, "expected_incidents": case["expected_incident_count"],
                          "actual_detector_result": "not_implemented"}, indent=2))
        return 0 if all(checks.values()) else 1
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        manifest.update({"status": "incomplete", "error": str(error), "finished_at": utc()})
        save(out / "manifest.json", manifest)
        print(json.dumps({"recording": str(out), "status": "incomplete", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
