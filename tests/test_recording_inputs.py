"""Integration checks against a copy of a real recording, never modifying the source."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from detector.core import load_recording

RECORDING = ROOT / "artifacts/recordings/B1-20261005T153005030054Z"


class RecordingTests(unittest.TestCase):
    def copy(self, tmp):
        folder = Path(tmp) / "recording"
        shutil.copytree(RECORDING, folder)
        return folder

    def test_modified_events_rejected(self):
        with TemporaryDirectory() as tmp:
            folder = self.copy(tmp)
            with (folder / "events.jsonl").open("a") as stream:
                stream.write("{}\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_recording(folder)

    def test_changed_sensor_run_rejected(self):
        with TemporaryDirectory() as tmp:
            folder = self.copy(tmp)
            metric = json.loads((folder / "metrics-after.json").read_text())
            metric["output_fields"]["falco.start_ts"] += 1
            (folder / "metrics-after.json").write_text(json.dumps(metric))
            with self.assertRaisesRegex(ValueError, "changed"):
                load_recording(folder)

    def test_cli_does_not_read_ground_truth_or_demo_logs(self):
        with TemporaryDirectory() as tmp:
            folder = self.copy(tmp)
            (folder / "ground-truth.json").write_text("INVALID JSON - DO NOT READ")
            (folder / "demo.stdout.jsonl").write_text("INVALID JSON - DO NOT READ")
            (folder / "manifest.json").write_text((folder / "manifest.json").read_text())
            output = Path(tmp) / "report"
            result = subprocess.run([sys.executable, str(ROOT / "scripts/detect_recording.py"),
                                     str(folder), "--output", str(output)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads((output / "report.json").read_text())["incident_count"], 0)


if __name__ == "__main__":
    unittest.main()
