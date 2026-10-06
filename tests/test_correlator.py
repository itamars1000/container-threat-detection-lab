"""Synthetic boundary tests; these are not live Falco recordings."""
import copy
import json
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from detector.core import replay, FILE_RULE, NETWORK_RULE, validate_policy

A, B = "a" * 64, "b" * 64
CONTEXT = {"sensor_run_id": "run-1", "sensor_hostname": "sensor-1", "host_boot_ts": 100}
POLICY = {"schema_version": 1, "policy_version": "test-1",
          "monitored_containers": [{"container_full_id": A}, {"container_full_id": B}],
          "sensitive_files": ["/demo.json"],
          "expected_destinations": [{"ip": "127.0.0.1", "port": 8080, "protocol": "tcp"}],
          "correlation": {"lookback_seconds": 60, "require_positive_time_delta": True,
              "require_same_sensor_run": True, "require_same_host": True,
              "require_same_container_full_id": True, "require_same_pid": False},
          "exceptions": []}


def event(kind, ns, container=A, pid=1, command="app", port=8080, ip="10.0.0.9"):
    fields = {"container.full_id": container, "evt.rawtime": ns,
              "evt.res": "SUCCESS" if kind == "file" else "EINPROGRESS",
              "proc.pid": pid, "proc.cmdline": command, "user.uid": 10001,
              "evt.type": "openat" if kind == "file" else "connect"}
    if kind == "file":
        fields["fd.name"] = "/demo.json"
    else:
        fields.update({"fd.sip": ip, "fd.sport": port, "fd.l4proto": "tcp"})
    return {"source": "syscall", "hostname": "sensor-1",
            "rule": FILE_RULE if kind == "file" else NETWORK_RULE, "output_fields": fields}


def run(events, policy=None, context=None):
    return replay([json.dumps(e) if not isinstance(e, str) else e for e in events],
                  policy or POLICY, context or CONTEXT)


class CorrelatorTests(unittest.TestCase):
    def test_unexpected_pair_and_different_pids(self):
        r = run([event("file", 1, pid=1), event("network", 2, pid=2)])
        self.assertEqual(r["incident_count"], 1)

    def test_expected_endpoint(self):
        self.assertEqual(run([event("file", 1), event("network", 2, ip="127.0.0.1")])["incident_count"], 0)

    def test_endpoint_is_full_tuple(self):
        self.assertEqual(run([event("file", 1), event("network", 2, ip="127.0.0.1", port=9090)])["incident_count"], 1)

    def test_file_only(self):
        self.assertEqual(run([event("file", 1)])["incident_count"], 0)

    def test_network_only(self):
        self.assertEqual(run([event("network", 2)])["incident_count"], 0)

    def test_different_containers(self):
        self.assertEqual(run([event("file", 1), event("network", 2, container=B)])["incident_count"], 0)

    def test_reverse_order(self):
        self.assertEqual(run([event("network", 1), event("file", 2)])["incident_count"], 0)

    def test_equal_timestamp(self):
        self.assertEqual(run([event("file", 10), event("network", 10)])["incident_count"], 0)

    def test_window_inclusive_at_60_seconds(self):
        self.assertEqual(run([event("file", 1), event("network", 60_000_000_001)])["incident_count"], 1)

    def test_one_ns_outside_window(self):
        self.assertEqual(run([event("file", 1), event("network", 60_000_000_002)])["incident_count"], 0)

    def test_out_of_order_arrival(self):
        pair = [event("file", 1), event("network", 10)]
        a, b = run(pair), run(list(reversed(pair)))
        self.assertEqual(a["incidents"], b["incidents"])

    def test_exact_duplicates(self):
        pair = [event("file", 1), event("network", 10)]
        r = run(pair + pair)
        self.assertEqual(r["incident_count"], 1)
        self.assertEqual(r["counts"]["duplicate_events"], 2)

    def test_multiple_file_opens_one_network(self):
        r = run([event("file", 1), event("file", 2), event("network", 3)])
        self.assertEqual(r["incident_count"], 1)
        self.assertEqual(len(r["incidents"][0]["file_event_ids"]), 2)

    def test_real_network_events_are_separate(self):
        self.assertEqual(run([event("file", 1), event("network", 2), event("network", 3)])["incident_count"], 2)

    def test_sliding_window_uses_newer_file(self):
        r = run([event("file", 1), event("file", 50_000_000_001), event("network", 70_000_000_001)])
        self.assertEqual(len(r["incidents"][0]["file_event_ids"]), 1)

    def test_missing_container_is_error(self):
        e = event("network", 2)
        del e["output_fields"]["container.full_id"]
        r = run([event("file", 1), e])
        self.assertEqual(r["status"], "data_errors_present")
        self.assertEqual(r["incident_count"], 0)

    def test_missing_time_is_error(self):
        e = event("file", 1)
        del e["output_fields"]["evt.rawtime"]
        self.assertEqual(len(run([e])["data_errors"]), 1)

    def test_float_time_rejected(self):
        self.assertEqual(len(run([event("file", 1.5)])["data_errors"]), 1)

    def test_bad_json_is_error(self):
        self.assertEqual(len(run(["not json"])["data_errors"]), 1)

    def test_other_sensor_host_is_error(self):
        e = event("network", 2); e["hostname"] = "other"
        self.assertEqual(run([event("file", 1), e])["incident_count"], 0)
        self.assertEqual(len(run([e])["data_errors"]), 1)

    def test_separate_runs_do_not_share_state(self):
        run([event("file", 1)])
        context = dict(CONTEXT, sensor_run_id="run-2")
        self.assertEqual(run([event("network", 2)], context=context)["incident_count"], 0)

    def test_missing_process_not_assumed_safe(self):
        e = event("network", 2); del e["output_fields"]["proc.cmdline"]
        self.assertEqual(run([event("file", 1), e])["incident_count"], 1)

    def test_failed_connect_is_retained(self):
        e = event("network", 2); e["output_fields"]["evt.res"] = "ECONNREFUSED"
        r = run([event("file", 1), e])
        self.assertEqual(r["incidents"][0]["connection_result"], "ECONNREFUSED")

    def test_unknown_destination_is_data_error(self):
        e = event("network", 2); e["output_fields"]["fd.sip"] = None
        self.assertEqual(len(run([e])["data_errors"]), 1)

    def test_exception_applies_only_to_matching_pair(self):
        p = copy.deepcopy(POLICY)
        p["exceptions"] = [{"id": "maintenance", "container_full_id": A, "uid": 10001,
                           "file_path": "/demo.json", "file_command": "maintenance",
                           "network_command": "app",
                           "destination": {"ip": "10.0.0.9", "port": 8080, "protocol": "tcp"}}]
        r = run([event("file", 1, command="maintenance"), event("file", 2, command="other"),
                 event("network", 3)], policy=p)
        self.assertEqual(r["incident_count"], 1)
        self.assertEqual(len(r["excepted_pairs"]), 1)
        self.assertEqual(len(r["incidents"][0]["file_event_ids"]), 1)

    def test_all_pairs_excepted(self):
        p = copy.deepcopy(POLICY)
        p["exceptions"] = [{"id": "maintenance", "container_full_id": A, "uid": 10001,
                           "file_path": "/demo.json", "file_command": "app", "network_command": "app",
                           "destination": {"ip": "10.0.0.9", "port": 8080, "protocol": "tcp"}}]
        r = run([event("file", 1), event("network", 2)], policy=p)
        self.assertEqual(r["incident_count"], 0)
        self.assertEqual(r["network_decisions"][0]["decision"], "all_pairs_excepted")

    def test_repeat_replay_is_identical(self):
        pair = [event("file", 1), event("network", 2)]
        self.assertEqual(run(pair), run(pair))


if __name__ == "__main__":
    unittest.main()
