"""Synthetic checks of the precise maintenance exception and its limits."""
import copy
import unittest
from test_correlator import POLICY, CONTEXT, A, B, event, run

COMMAND = "python - maintenance-demo"


def policy():
    result = copy.deepcopy(POLICY)
    result["policy_version"] = "maintenance-test"
    result["exceptions"] = [{"id": "maintenance", "container_full_id": A, "uid": 10001,
                             "file_path": "/demo.json", "file_command": COMMAND,
                             "network_command": COMMAND,
                             "destination": {"ip": "10.0.0.9", "port": 8080, "protocol": "tcp"}}]
    return result


def pair():
    return [event("file", 1, command=COMMAND), event("network", 2, command=COMMAND)]


class MaintenanceTests(unittest.TestCase):
    def test_exact_pair_is_preserved_and_excepted(self):
        result = run(pair(), policy=policy())
        self.assertEqual(result["incident_count"], 0)
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(len(result["excepted_pairs"]), 1)

    def test_file_command_change_does_not_match(self):
        events = pair(); events[0]["output_fields"]["proc.cmdline"] = "other"
        self.assertEqual(run(events, policy=policy())["incident_count"], 1)

    def test_network_command_change_does_not_match(self):
        events = pair(); events[1]["output_fields"]["proc.cmdline"] = "other"
        self.assertEqual(run(events, policy=policy())["incident_count"], 1)

    def test_uid_change_does_not_match(self):
        events = pair(); events[1]["output_fields"]["user.uid"] = 0
        self.assertEqual(run(events, policy=policy())["incident_count"], 1)

    def test_port_change_does_not_match(self):
        events = pair(); events[1]["output_fields"]["fd.sport"] = 9090
        self.assertEqual(run(events, policy=policy())["incident_count"], 1)

    def test_container_change_does_not_match(self):
        events = pair()
        for e in events:
            e["output_fields"]["container.full_id"] = B
        self.assertEqual(run(events, policy=policy())["incident_count"], 1)

    def test_nonexcepted_file_not_hidden(self):
        events = [event("file", 1, command=COMMAND), event("file", 2, command="other"),
                  event("network", 3, command=COMMAND)]
        result = run(events, policy=policy())
        self.assertEqual(result["incident_count"], 1)
        self.assertEqual(len(result["excepted_pairs"]), 1)

    def test_identical_imitation_cannot_be_distinguished(self):
        # There is no authentication evidence in these fields.
        self.assertEqual(run(pair(), policy=policy())["incident_count"], 0)


if __name__ == "__main__":
    unittest.main()
