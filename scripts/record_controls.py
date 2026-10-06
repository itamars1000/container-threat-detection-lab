"""Record connection-only, different-process, or reverse-order controls."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import time
import yaml
from record_scenario import ROOT, CAPTURES, sensor, latest_metric, next_metric, save, sha, utc, docker

SOURCES = {"file": ROOT / "lab/orders-api/file_only.py",
           "network": ROOT / "lab/orders-api/network_only.py"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=("B4", "S3", "B5"))
    args = parser.parse_args(argv)
    case = json.loads((ROOT / "scenarios" / (args.scenario + ".json")).read_text())
    before_sensor = sensor()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = ROOT / "artifacts/recordings" / (args.scenario + "-" + stamp)
    out.mkdir(parents=True, exist_ok=False)
    save(out / "ground-truth.json", case)
    manifest = {"schema_version": 1, "recording_id": out.name, "created_at": utc(),
                "status": "incomplete", "sensor_before": before_sensor,
                "limitations": ["Short low-load capture; no detector is implemented.",
                                "Run alone; concurrent manual actions can contaminate attribution.",
                                "Use Falco times for correlation; application clocks may differ."]}
    save(out / "manifest.json", manifest)
    try:
        result = subprocess.run(
            ["python3", "scripts/snapshot_environment.py", "--output", str(out / "environment.json")],
            cwd=ROOT, text=True, capture_output=True, timeout=30)
        (out / "snapshot.stderr.txt").write_text(result.stderr, encoding="utf-8")
        if result.returncode:
            raise RuntimeError("Lab environment validation failed")
        env = json.loads((out / "environment.json").read_text())
        services = {c["service"]: c for c in env["containers"]}
        policy = yaml.safe_load((ROOT / "config/policy.baseline.yaml").read_text())
        for item in policy["monitored_containers"]:
            if item["container_full_id"] != services[item["service"]]["container_id"]:
                raise RuntimeError("Policy monitored identity is stale")
        network = policy["environment_binding"]["network"]
        for dest in policy["expected_destinations"]:
            svc = "orders-api" if dest["service"] == "orders-api-self" else dest["service"]
            if dest["container_full_id"] != services[svc]["container_id"]:
                raise RuntimeError("Policy destination identity is stale")
            if dest["ip"] != "127.0.0.1" and dest["ip"] != services[svc]["networks"][network]["ipv4"]:
                raise RuntimeError("Policy destination IP is stale")
        target_ip = services["lab-sink"]["networks"][network]["ipv4"]
        if (target_ip, 8080, "tcp") in {
                (d["ip"], d["port"], d["protocol"]) for d in policy["expected_destinations"]}:
            raise RuntimeError("lab-sink is expected under current policy; review scenario ground truth")
        for src, name in [(ROOT / "config/policy.baseline.yaml", "policy.yaml"),
                          (ROOT / "falco/rules.yaml", "rules.yaml")]:
            (out / name).write_bytes(src.read_bytes())
        manifest.update({"policy_version": policy["policy_version"],
                         "policy_sha256": sha(out / "policy.yaml"),
                         "rules_sha256": sha(out / "rules.yaml"),
                         "recorder_sha256": sha(Path(__file__))})
        prior = latest_metric()
        before = next_metric(prior["output_fields"]["evt.time"] if prior else 0)
        bf = before["output_fields"]
        if bf.get("falco.sha256_rules_file.lab_rules_yaml") != manifest["rules_sha256"]:
            raise RuntimeError("Loaded rules differ; restart Falco")
        path = CAPTURES / "events.jsonl"
        stat = path.stat()
        manifest["action_started_at"] = utc()
        action_checks = []
        sources = {}
        for index, action in enumerate(case["steps"], 1):
            source = SOURCES[action].read_text()
            source_name = str(index) + "-" + action + "-source.py"
            (out / source_name).write_text(source, encoding="utf-8")
            sources[source_name] = sha(out / source_name)
            response = subprocess.run(
                ["sudo", "docker", "compose", "-f", "lab/compose.yaml", "exec", "-T",
                 "orders-api", "python", "-"],
                cwd=ROOT, text=True, capture_output=True, input=source, timeout=20)
            prefix = str(index) + "-" + action
            (out / (prefix + ".stdout.jsonl")).write_text(response.stdout, encoding="utf-8")
            (out / (prefix + ".stderr.txt")).write_text(response.stderr, encoding="utf-8")
            messages = [json.loads(line) for line in response.stdout.splitlines() if line.strip()]
            action_checks.append(response.returncode == 0 and any(
                (m.get("event") == "demo_file_read" and m.get("mode") == "file_only")
                if action == "file" else
                (m.get("event") == "http_response" and m.get("response_service") == "lab-sink"
                 and m.get("status_code") == 200) for m in messages))
            if not action_checks[-1]:
                raise RuntimeError("Action failed: " + action)
        manifest["action_finished_at"] = utc()
        manifest["action_sources_sha256"] = sources
        (out / "target.log").write_text(docker(
            "compose", "-f", "lab/compose.yaml", "logs", "--since",
            manifest["action_started_at"], "--tail", "50", "lab-sink"), encoding="utf-8")
        current = latest_metric()
        if current is None:
            raise RuntimeError("Metrics missing after action")
        after = next_metric(current["output_fields"]["evt.time"])
        time.sleep(1)
        end = path.stat()
        if end.st_ino != stat.st_ino or end.st_size < stat.st_size:
            raise RuntimeError("Event file rotated/truncated")
        with path.open("rb") as stream:
            stream.seek(stat.st_size)
            raw = stream.read(end.st_size - stat.st_size)
        (out / "events.jsonl").write_bytes(raw)
        save(out / "metrics-before.json", before)
        save(out / "metrics-after.json", after)
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        control = [e["output_fields"] for e in events
                   if e["output_fields"].get("proc.cmdline") == "python -"
                   and e["output_fields"].get("container.full_id") == services["orders-api"]["container_id"]]
        opens = [f for f in control if f.get("evt.type") in ("open", "openat", "openat2")
                 and f.get("fd.name") == "/run/demo-secrets/credentials-demo.json"
                 and f.get("evt.res") == "SUCCESS"]
        connects = [f for f in control if f.get("evt.type") == "connect"
                    and f.get("fd.sip") == target_ip and f.get("fd.sport") == 8080
                    and f.get("fd.l4proto") == "tcp"]
        af = after["output_fields"]
        checks = {
            "scenario_succeeded": all(action_checks),
            "sensor_unchanged": before_sensor == sensor(),
            "same_sensor_start_and_reload": all(bf.get(k) is not None and bf[k] == af.get(k)
                for k in ("falco.start_ts", "falco.reload_ts")),
            "rules_unchanged": manifest["rules_sha256"] == sha(ROOT / "falco/rules.yaml")
                == af.get("falco.sha256_rules_file.lab_rules_yaml"),
            "policy_unchanged": manifest["policy_sha256"] == sha(ROOT / "config/policy.baseline.yaml"),
            "kernel_events_processed": af["scap.n_evts"] > bf["scap.n_evts"],
            "no_kernel_drops_in_window": af["scap.n_drops"] == bf["scap.n_drops"],
            "no_output_queue_drops_in_window": af["falco.outputs_queue_num_drops"] == bf["falco.outputs_queue_num_drops"],
            "scenario_target_connect_received": bool(connects),
            "single_control_connect_received": len(connects) == 1,
        }
        if args.scenario == "B4":
            checks["no_sensitive_file_open_in_capture"] = not any(
                e["output_fields"].get("fd.name") == "/run/demo-secrets/credentials-demo.json"
                for e in events)
        else:
            checks["single_control_file_open_received"] = len(opens) == 1
            checks["different_processes_same_container"] = bool(opens and connects) and all(
                f["proc.pid"] != n["proc.pid"] for f in opens for n in connects)
            deltas = [n["evt.rawtime"] - f["evt.rawtime"] for f in opens for n in connects]
            window = policy["correlation"]["lookback_seconds"] * 1_000_000_000
            checks["scenario_order_verified"] = bool(deltas) and all(
                0 < d <= window if args.scenario == "S3" else -window <= d < 0 for d in deltas)
            manifest["network_minus_file_ns"] = deltas
        save(out / "collection-checks.json", {"checks": checks, "valid": all(checks.values()),
                                             "matched_rule_events": len(events)})
        manifest.update({"status": "complete" if all(checks.values()) else "invalid",
                         "completed_at": utc(), "sensor_run_id": str(bf["falco.start_ts"]),
                         "host_boot_ts": bf.get("falco.host_boot_ts"),
                         "sensor_hostname": bf.get("evt.hostname"),
                         "event_byte_range": [stat.st_size, end.st_size],
                         "events_sha256": sha(out / "events.jsonl")})
        save(out / "manifest.json", manifest)
        print(json.dumps({"recording": str(out), "status": manifest["status"],
                          "collection_checks": checks,
                          "expected_incidents": case["expected_incident_count"],
                          "actual_detector_result": "not_implemented"}, indent=2), flush=True)
        return 0 if all(checks.values()) else 1
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        manifest.update({"status": "incomplete", "error": str(error)})
        save(out / "manifest.json", manifest)
        print(json.dumps({"recording": str(out), "status": "incomplete", "error": str(error)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
