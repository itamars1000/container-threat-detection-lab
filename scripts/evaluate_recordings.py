"""Compare completed-recording detector reports to separate scenario ground truth."""
import json
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]

def main():
    rows = []
    for folder in sorted((ROOT / "artifacts/recordings").iterdir()):
        if not folder.is_dir() or not (folder / "ground-truth.json").exists():
            continue
        manifest = json.loads((folder / "manifest.json").read_text())
        if manifest.get("status") != "complete":
            continue
        process = subprocess.run(
            [sys.executable, str(ROOT / "scripts/detect_recording.py"), str(folder)],
            text=True, capture_output=True)
        truth = json.loads((folder / "ground-truth.json").read_text())
        if process.returncode:
            rows.append({"recording": folder.name, "scenario": truth["scenario_id"],
                         "status": "detector_error", "output": process.stdout + process.stderr,
                         "pass": False})
            continue
        report = json.loads((ROOT / "artifacts/reports" / folder.name / "report.json").read_text())
        rows.append({"recording": folder.name, "scenario": truth["scenario_id"],
                     "policy_version": report["policy_version"],
                     "expected": truth["expected_incident_count"],
                     "actual": report["incident_count"], "data_errors": len(report["data_errors"]),
                     "pass": report["incident_count"] == truth["expected_incident_count"]
                        and not report["data_errors"],
                     "known_detection_limitation": truth.get("known_detection_limitation")})
    out = ROOT / "artifacts/reports"
    out.mkdir(parents=True, exist_ok=True)
    result = {"scope": "Agreement with predefined scenario expectations; not general security accuracy.",
              "recording_count": len(rows), "all_passed": bool(rows) and all(r["pass"] for r in rows),
              "results": rows}
    (out / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["all_passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
