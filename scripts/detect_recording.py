"""Replay a completed recording without reading ground-truth or application logs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import yaml
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from detector.core import load_recording, replay, markdown

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recording", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--policy", type=Path, help="Explicit alternate replay policy; recorded inputs remain validated")
    args = parser.parse_args()
    folder = args.recording.resolve()
    try:
        manifest, context = load_recording(folder)
        policy = yaml.safe_load((folder / "policy.yaml").read_text())
        if policy["policy_version"] != manifest["policy_version"]:
            raise ValueError("Policy version mismatch")
        recorded_policy_version = policy["policy_version"]
        evaluated_policy_hash = manifest["policy_sha256"]
        if args.policy:
            policy_bytes = args.policy.read_bytes()
            policy = yaml.safe_load(policy_bytes)
            evaluated_policy_hash = hashlib.sha256(policy_bytes).hexdigest()
        report = replay((folder / "events.jsonl").read_text().splitlines(), policy, context)
        report["recording_id"] = manifest["recording_id"]
        report["input_hashes"] = {k: manifest[k] for k in ["events_sha256", "policy_sha256", "rules_sha256"]}
        report["recorded_policy_version"] = recorded_policy_version
        report["evaluated_policy_sha256"] = evaluated_policy_hash
        report["policy_source"] = "explicit_override" if args.policy else "recorded_snapshot"
        out = args.output or ROOT / "artifacts/reports" / folder.name
        if args.policy and not args.output:
            out = out / ("policy-" + evaluated_policy_hash[:12])
        out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (out / "report.md").write_text(markdown(report), encoding="utf-8")
        print(json.dumps({"status": report["status"], "incidents": report["incident_count"],
                          "data_errors": len(report["data_errors"]), "report": str(out / "report.json")}))
        return 0 if report["status"] == "complete" else 2
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
        print(json.dumps({"status": "invalid_input", "error": str(error)}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
