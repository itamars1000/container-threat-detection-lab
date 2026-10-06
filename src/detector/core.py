"""Evidence correlation without using scenario labels or application logs."""
from collections import defaultdict, deque
import hashlib
import ipaddress
import json
import re

FILE_RULE = "Lab sensitive file opened for reading"
NETWORK_RULE = "Lab monitored outbound TCP connect attempt"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(name + " must be an integer >= " + str(minimum))
    return value


def full_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("container.full_id must be a full 64-character ID")
    return value


def endpoint(item):
    ip = str(ipaddress.ip_address(item["ip"]))
    port = integer(item["port"], "port", 1)
    if port > 65535 or item["protocol"] != "tcp":
        raise ValueError("Expected a TCP endpoint with port 1..65535")
    return (ip, port, "tcp")


def validate_policy(policy):
    if policy.get("schema_version") != 1 or not policy.get("policy_version"):
        raise ValueError("Unsupported/missing policy version")
    correlation = policy["correlation"]
    window = integer(correlation["lookback_seconds"], "lookback_seconds", 1)
    required = ["require_positive_time_delta", "require_same_sensor_run",
                "require_same_host", "require_same_container_full_id"]
    if any(correlation.get(k) is not True for k in required) or correlation.get("require_same_pid") is not False:
        raise ValueError("Unsupported correlation contract")
    monitored = {full_id(c["container_full_id"]) for c in policy["monitored_containers"]}
    paths = policy["sensitive_files"]
    if not monitored or not paths or any(not isinstance(p, str) or not p.startswith("/") for p in paths):
        raise ValueError("Empty/invalid monitored scope or sensitive paths")
    expected = {endpoint(d) for d in policy["expected_destinations"]}
    exceptions = policy.get("exceptions", [])
    for item in exceptions:
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError("Exception needs an ID")
        full_id(item["container_full_id"])
        integer(item["uid"], "exception uid")
        if any(not isinstance(item.get(k), str) or not item[k]
               for k in ["file_command", "network_command", "file_path"]):
            raise ValueError("Exception must specify file/network commands and path")
        endpoint(item["destination"])
    if len({e["id"] for e in exceptions}) != len(exceptions):
        raise ValueError("Duplicate exception IDs")
    return monitored, set(paths), expected, window * 1_000_000_000, exceptions


def normalize(raw, line, context):
    if not isinstance(raw, dict) or not isinstance(raw.get("output_fields"), dict):
        raise ValueError("Expected a Falco event with output_fields")
    rule = raw.get("rule")
    if rule not in {FILE_RULE, NETWORK_RULE}:
        return None
    f = raw["output_fields"]
    if raw.get("source") != "syscall":
        raise ValueError("Wrong event source")
    if raw.get("hostname") != context["sensor_hostname"]:
        raise ValueError("Event belongs to a different sensor host")
    container = full_id(f.get("container.full_id"))
    event_ns = integer(f.get("evt.rawtime"), "evt.rawtime", 1)
    result = f.get("evt.res")
    if not isinstance(result, str) or not result:
        raise ValueError("Missing syscall result")
    event = {"kind": "file" if rule == FILE_RULE else "network", "time_ns": event_ns,
             "container_full_id": container, "sensor_run_id": context["sensor_run_id"],
             "host": context["sensor_hostname"], "host_boot_ts": context["host_boot_ts"],
             "rule": rule, "result": result, "raw_result": f.get("evt.rawres"),
             "source_line": line, "process": {"pid": f.get("proc.pid"),
                 "name": f.get("proc.name"), "command": f.get("proc.cmdline"),
                 "parent": f.get("proc.pname"), "uid": f.get("user.uid")}}
    if event["kind"] == "file":
        if f.get("evt.type") not in {"open", "openat", "openat2"} or result != "SUCCESS":
            raise ValueError("File candidate is not a successful open")
        if not isinstance(f.get("fd.name"), str) or not f["fd.name"]:
            raise ValueError("Missing file path")
        event["path"] = f["fd.name"]
    else:
        if f.get("evt.type") != "connect":
            raise ValueError("Network candidate is not connect")
        event["destination"] = {"ip": f.get("fd.sip"), "port": f.get("fd.sport"),
                                "protocol": f.get("fd.l4proto")}
        endpoint(event["destination"])
        event["client"] = {"ip": f.get("fd.cip"), "port": f.get("fd.cport")}
    event["event_id"] = digest({"context": context, "raw": raw})
    return event


def exception_for(file, network, exceptions):
    for item in exceptions:
        if (file["container_full_id"] == item["container_full_id"]
            and network["container_full_id"] == item["container_full_id"]
            and file["path"] == item["file_path"]
            and file["process"]["uid"] == network["process"]["uid"] == item["uid"]
            and file["process"]["command"] == item["file_command"]
            and network["process"]["command"] == item["network_command"]
            and endpoint(network["destination"]) == endpoint(item["destination"])):
            return item["id"]
    return None


def replay(lines, policy, context):
    monitored, paths, expected, window, exceptions = validate_policy(policy)
    for field in ["sensor_run_id", "sensor_hostname", "host_boot_ts"]:
        if context.get(field) in (None, ""):
            raise ValueError("Missing recording context: " + field)
    events, errors, seen = [], [], set()
    ignored, duplicates = 0, 0
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = normalize(json.loads(line), line_number, context)
            if event is None:
                ignored += 1
                continue
            if event["event_id"] in seen:
                duplicates += 1
                continue
            seen.add(event["event_id"])
            if event["container_full_id"] not in monitored:
                ignored += 1
                continue
            events.append(event)
        except (ValueError, KeyError, TypeError) as error:
            errors.append({"source_line": line_number, "error": str(error)})
    events.sort(key=lambda e: (e["time_ns"], e["event_id"]))
    files = defaultdict(deque)
    incidents, decisions, excluded = [], [], []
    for event in events:
        key = (event["sensor_run_id"], event["host_boot_ts"], event["host"], event["container_full_id"])
        recent = files[key]
        while recent and event["time_ns"] - recent[0]["time_ns"] > window:
            recent.popleft()
        if event["kind"] == "file":
            if event["path"] in paths:
                recent.append(event)
            continue
        if endpoint(event["destination"]) in expected:
            decisions.append({"event_id": event["event_id"], "decision": "expected_destination"})
            continue
        eligible = [f for f in recent if 0 < event["time_ns"] - f["time_ns"] <= window]
        active = []
        for file in eligible:
            exception_id = exception_for(file, event, exceptions)
            if exception_id:
                excluded.append({"file_event_id": file["event_id"], "network_event_id": event["event_id"],
                                 "exception_id": exception_id})
            else:
                active.append(file)
        if active:
            incidents.append({"incident_id": digest({"network": event["event_id"],
                              "files": sorted(f["event_id"] for f in active),
                              "policy": policy["policy_version"]}),
                              "container_full_id": event["container_full_id"],
                              "sensor_run_id": event["sensor_run_id"], "host": event["host"],
                              "network_event_id": event["event_id"],
                              "file_event_ids": [f["event_id"] for f in active],
                              "deltas_ns": [event["time_ns"] - f["time_ns"] for f in active],
                              "destination": event["destination"],
                              "connection_result": event["result"],
                              "severity": "investigate",
                              "reason": "Sensitive-file open followed by an unexpected TCP connect attempt in the same container and sensor run within the policy window."})
            decision = "investigate"
        else:
            decision = "all_pairs_excepted" if eligible else "no_preceding_file_in_window"
        decisions.append({"event_id": event["event_id"], "decision": decision})
    return {"schema_version": 1, "detector_version": "replay-1",
            "policy_version": policy["policy_version"],
            "status": "data_errors_present" if errors else "complete",
            "context": context, "incident_count": len(incidents), "incidents": incidents,
            "events": events, "network_decisions": decisions, "excepted_pairs": excluded,
            "data_errors": errors, "counts": {"normalized_events": len(events),
                 "duplicate_events": duplicates, "ignored_events": ignored, "data_errors": len(errors)},
            "limitations": ["Correlation is not proof of causality, unauthorized activity or exfiltration.",
                            "Successful open does not prove bytes were read; connect can be EINPROGRESS or fail.",
                            "Expected endpoints apply to all monitored processes; no HTTP path is inferred.",
                            "Only the completed input recording is evaluated; missing sensor activity cannot be reconstructed."]}


def load_recording(folder):
    manifest = json.loads((folder / "manifest.json").read_text())
    checks = json.loads((folder / "collection-checks.json").read_text())
    if manifest.get("status") != "complete" or checks.get("valid") is not True:
        raise ValueError("Recording did not pass collection checks")
    if not checks.get("checks") or any(v is not True for v in checks["checks"].values()):
        raise ValueError("Recording has failed or missing collection checks")
    for file, key in [("events.jsonl", "events_sha256"), ("policy.yaml", "policy_sha256"),
                      ("rules.yaml", "rules_sha256")]:
        if hashlib.sha256((folder / file).read_bytes()).hexdigest() != manifest.get(key):
            raise ValueError("Recording hash mismatch: " + file)
    before = json.loads((folder / "metrics-before.json").read_text())["output_fields"]
    after = json.loads((folder / "metrics-after.json").read_text())["output_fields"]
    for k in ["falco.start_ts", "falco.reload_ts", "falco.host_boot_ts"]:
        if before.get(k) is None or before[k] != after.get(k):
            raise ValueError("Sensor run/host changed in metrics")
    if str(before["falco.start_ts"]) != manifest.get("sensor_run_id"):
        raise ValueError("Manifest sensor run does not match metrics")
    if before["falco.host_boot_ts"] != manifest.get("host_boot_ts"):
        raise ValueError("Manifest host context does not match metrics")
    context = {k: manifest[k] for k in ["sensor_run_id", "sensor_hostname", "host_boot_ts"]}
    return manifest, context


def markdown(report):
    out = ["# Replay detection report", "",
           "Status: " + report["status"], "Policy: " + report["policy_version"],
           "Incidents for investigation: " + str(report["incident_count"]), "",
           "No incidents is not a claim of safety.", ""]
    evidence = {e["event_id"]: e for e in report["events"]}
    for index, incident in enumerate(report["incidents"], 1):
        out += ["## Incident " + str(index), "", incident["reason"], "",
                "Container: " + incident["container_full_id"],
                "Destination: " + str(incident["destination"]),
                "Connect result: " + incident["connection_result"], "",
                "| Evidence | Source line | Time (ns) | PID | Command |",
                "|---|---|---|---|---|"]
        for identifier in [*incident["file_event_ids"], incident["network_event_id"]]:
            event = evidence[identifier]
            command = str(event["process"]["command"]).replace("|", "\\|").replace("\n", " ")
            out.append("| " + event["kind"] + " | " + str(event["source_line"]) + " | "
                       + str(event["time_ns"]) + " | " + str(event["process"]["pid"]) + " | " + command + " |")
        out += ["", "File-to-network gaps (ns): " + str(incident["deltas_ns"]), ""]
    out += ["## Excepted evidence pairs", ""]
    for pair in report["excepted_pairs"]:
        file = evidence[pair["file_event_id"]]
        network = evidence[pair["network_event_id"]]
        out.append("Exception " + pair["exception_id"] + ": file source line "
                   + str(file["source_line"]) + ", network source line "
                   + str(network["source_line"]) + ". Evidence retained.")
    if not report["excepted_pairs"]:
        out.append("None.")
    out += ["", "## Data errors", "", json.dumps(report["data_errors"]), "",
            "## Limits", "", *["- " + text for text in report["limitations"]], ""]
    return "\n".join(out)
