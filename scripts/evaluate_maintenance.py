"""Replay the same recordings before/after an exact maintenance exception."""
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
        if json.loads((folder / "manifest.json").read_text()).get("status") != "complete":
            continue
        truth = json.loads((folder / "ground-truth.json").read_text())
        outcomes = {}
        for mode in ["before", "after"]:
            out = ROOT / "artifacts/reports/maintenance-comparison" / folder.name / mode
            command = [sys.executable, str(ROOT / "scripts/detect_recording.py"), str(folder),
                       "--output", str(out)]
            if mode == "after":
                command += ["--policy", str(ROOT / "config/policy.maintenance.yaml")]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            report = json.loads((out / "report.json").read_text())
            outcomes[mode] = {"incidents": report["incident_count"],
                              "excepted_pairs": len(report["excepted_pairs"]),
                              "data_errors": len(report["data_errors"]),
                              "policy_version": report["policy_version"]}
        expected_before = truth["expected_incident_count"]
        expected_after = truth.get("expected_tuned_incident_count", expected_before)
        rows.append({"recording": folder.name, "scenario": truth["scenario_id"],
                     "legitimate_by_exercise_definition": truth.get("legitimate_activity", False),
                     "expected_before": expected_before, "expected_after": expected_after,
                     **outcomes,
                     "pass": outcomes["before"]["incidents"] == expected_before
                         and outcomes["after"]["incidents"] == expected_after
                         and not outcomes["before"]["data_errors"] and not outcomes["after"]["data_errors"]})
    result = {"scope": "Nine controlled lab cases; not general security accuracy. Before uses each saved policy, after uses maintenance-1.",
              "all_passed": bool(rows) and all(r["pass"] for r in rows), "results": rows,
              "limitation": "An actor who imitates the exact UID/commands/container/file/endpoint can match the exception; these fields do not authenticate authorization."}
    labels = {"B1": False, "B2": False, "B3": False, "B4": False, "B5": False,
              "M1": False, "S1": True, "S2": True, "S3": True}
    counts = {}
    for mode in ["before", "after"]:
        counts[mode] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
        for row in rows:
            positive = labels[row["scenario"]]
            actual = row[mode]["incidents"] > 0
            key = "TP" if actual and positive else "FP" if actual else "FN" if positive else "TN"
            counts[mode][key] += 1
    result["controlled_scenario_counts"] = counts
    result["counting_note"] = "Exercise-defined scenario labels, not real attacks or population accuracy. S2 remains a known coverage miss."
    path = ROOT / "artifacts/reports/maintenance-comparison.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
