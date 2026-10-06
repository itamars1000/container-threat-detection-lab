"""Replay selected saved lab recordings and verify the demonstrated outcomes."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
# These expectations belong to the demo; the detector receives only evidence/policy.
STEPS = [
    ("normal", "B1-20261005T153005030054Z", False, 0, 0,
     "File followed by an expected destination."),
    ("suspicious", "S1-20261005T153624863042Z", False, 1, 0,
     "File followed by an unexpected destination inside the window."),
    ("different-processes", "S3-20261005T155700716422Z", False, 1, 0,
     "Different PIDs in the same container still form a candidate sequence."),
    ("different-containers", "B3-20261005T154644374785Z", False, 0, 0,
     "Nearby signals from different containers are not joined."),
    ("outside-window", "S2-20261005T155043527398Z", False, 0, 0,
     "Known coverage miss: the 75-second delay exceeds the 60-second window."),
    ("maintenance-before", "M1-20261006T060525477191Z", False, 1, 0,
     "Exercise-authorized maintenance creates a false alert under the saved baseline."),
    ("maintenance-after", "M1-20261006T060525477191Z", True, 0, 1,
     "The exact pair is excepted; its evidence is retained in the report."),
    ("suspicious-after", "S1-20261005T153624863042Z", True, 1, 0,
     "The maintenance exception does not hide this suspicious scenario."),
    ("different-processes-after", "S3-20261005T155700716422Z", True, 1, 0,
     "The maintenance exception also preserves the different-PID detection."),
]

def main():
    output_root = ROOT / "artifacts/reports/demo"
    output_root.mkdir(parents=True, exist_ok=True)
    summary_path = output_root / "summary.json"
    results = []
    # Write an incomplete result first so a failed run cannot leave a stale success.
    summary_path.write_text(json.dumps({"status": "running", "results": []}) + "\n")
    try:
        for name, recording, alternate, expected, expected_excepted, explanation in STEPS:
            output = output_root / name
            command = [sys.executable, str(ROOT / "scripts/detect_recording.py"),
                       str(ROOT / "artifacts/recordings" / recording), "--output", str(output)]
            if alternate:
                command += ["--policy", str(ROOT / "config/policy.maintenance.yaml")]
            process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            if process.returncode != 0:
                raise RuntimeError(f"{name}: replay failed: {process.stdout} {process.stderr}")
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            actual_excepted = len(report.get("excepted_pairs", []))
            if (report["status"] != "complete" or report["data_errors"]
                    or report["incident_count"] != expected
                    or actual_excepted != expected_excepted):
                raise RuntimeError(f"{name}: unexpected replay result")
            result = {"step": name, "recording": recording,
                      "policy_version": report["policy_version"],
                      "incidents": report["incident_count"], "excepted_pairs": actual_excepted,
                      "explanation": explanation, "report": str(output / "report.md")}
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        summary_path.write_text(json.dumps({"status": "failed", "results": results,
                                          "error": str(error)}, indent=2) + "\n")
        print(json.dumps({"status": "failed", "error": str(error)}), file=sys.stderr)
        return 2
    summary_path.write_text(json.dumps({"status": "complete", "steps_passed": len(results),
                                     "scope": "Offline controlled recordings; not general accuracy.",
                                     "results": results}, indent=2) + "\n")
    print(json.dumps({"status": "complete", "steps_passed": len(results),
                      "summary": str(summary_path)}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
