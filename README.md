# Container Threat Detection Lab

A learning project in container runtime detection: collect file and network signals with Falco, correlate recorded evidence in Python, and evaluate the result against controlled scenarios.

**Status:** The implemented learning scope is complete: nine controlled recordings, 38 passing tests, an evidence-based case study and a verified nine-step offline demo. This is a learning lab; its results do not establish production readiness or general detection accuracy.

## Detection hypothesis

A successful read-capable open of the demo sensitive file, followed by an unexpected TCP connection attempt from the same monitored container within **0 < delta <= 60 seconds**, creates an incident for investigation.

The correlator checks full container identity and sensor-run/host context. It does not require the same PID. File-open and connection signals do not prove that file contents were transmitted or that the activity was unauthorized.

~~~text
Docker lab -> Falco syscall signals -> JSONL recording + capture context
                                               |
                                     Python replay + YAML policy
                                               |
                                      JSON / Markdown evidence report
~~~

The Docker lab has orders-api (fake credential file), allowed-api (expected HTTP destination), and lab-sink (controlled unexpected destination). The two Falco rules collect candidate file/network signals; the Python correlator makes the policy-based decision.

## Quick start: offline demo

This path needs **no Docker, Falco, administrator privileges or cloud account**. It uses the immutable recordings included in the repository. Python 3.10 or newer is required; the recorded lab used Python 3.12. Use Linux/WSL for the commands below.

~~~bash
git clone <repository-url> container-threat-detection-lab
cd container-threat-detection-lab
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/demo.py
~~~

On Ubuntu, install python3-venv first if the venv module is unavailable. Replace <repository-url> with this repository's clone URL.

Expected last result: status "complete" and steps_passed 9. The demo writes artifacts/reports/demo/summary.json and per-step report.json/report.md files. Reports are regenerated locally and excluded from Git.

For a single suspicious recording:

~~~bash
python scripts/detect_recording.py artifacts/recordings/S3-20261005T155700716422Z
~~~

The detector validates recorded inputs and their hashes before replay. It does not use ground-truth labels or application logs to make its decision.

## Tests and evaluation

~~~bash
python -m unittest discover -s tests -v
python scripts/evaluate_recordings.py
python scripts/evaluate_maintenance.py
~~~

The 38 tests cover time boundaries, ordering, duplicate events, container/run identity, different PIDs, malformed inputs, recording validation, and exact-pair exceptions.

| Case | Controlled action | Before incidents | After incidents |
|---|---|---:|---:|
| B1 | File then expected destination | 0 | 0 |
| B2 | File only | 0 | 0 |
| B3 | File and network from different containers | 0 | 0 |
| B4 | Network only | 0 | 0 |
| B5 | Network before file | 0 | 0 |
| S1 | File then unexpected destination, same process | 1 | 1 |
| S2 | Same sequence after about 75 seconds | 0 | 0 |
| S3 | Same sequence, different processes in one container | 1 | 1 |
| M1 | Exercise-authorized maintenance | 1 | 0 |

Before uses each recording's saved policy (baseline-2 or baseline-3); after uses maintenance-1 on the same evidence.

The maintenance exception requires the exact container, UID, file, file/network commands and destination tuple. It preserves the excepted pair in the report and does not make lab-sink an expected destination generally. S1/S3 remain detected.

S2 is a **known coverage miss**: zero incidents agrees with the 60-second policy but misses a scenario labeled suspicious by the exercise. In this nine-case exercise, false positives decreased from 1 to 0; two suspicious cases remained detected and one remained missed. These are controlled examples, not a real-world benchmark.

## Live collection: environment-specific lab

The recorded environment was Ubuntu 24.04 in WSL2, a local Docker Engine, and Falco 0.45.0 using modern eBPF. Images are pinned by digest. Docker Desktop was not the daemon used for the recorded lab. Other host/kernel combinations have not been validated.

The included rules and policies contain **original lab container IDs and IP addresses**. They work for replaying the included evidence. Starting new containers does not automatically update those bindings.

To explore live collection:
1. Install a supported Linux Docker Engine and Docker Compose; follow the [official Ubuntu installation guide](https://docs.docker.com/engine/install/ubuntu/).
2. Start the application lab and capture its new identities:

~~~bash
sudo docker compose -f lab/compose.yaml up -d --build
sudo docker compose -f lab/compose.yaml ps
sudo -v
python scripts/snapshot_environment.py --output artifacts/environment.live.json
~~~

3. Before starting the sensor, update the active policy and Falco rules to the current orders-api/allowed-api identities. Policy uses full IDs; the Falco monitored list uses short IDs. Update allowed-api's expected IP, environment metadata and the maintenance exception's container/sink IP if used. A live-binding change to policy.maintenance.yaml also changes the bundled offline comparison: restore the recorded version before replaying old evidence. Never edit the saved policy/rules/events inside a completed recording.
4. Validate the current rules, start Falco and verify actual signal collection as described in the [lab guide](docs/lab-guide.he.md). Only then record fresh scenarios. This manual rebinding path is separate from the verified offline quick start.

Falco's lab configuration uses a privileged container and host mounts including the Docker socket. A read-only socket mount does not make the Docker API read-only. Run this sensor only in an isolated learning environment you control.

To stop lab services:

~~~bash
sudo docker compose -f falco/compose.yaml down
sudo docker compose -f lab/compose.yaml down
~~~

## Repository contents and evidence

- src/detector: normalization, replay correlation and evidence report generation.
- scripts: capture, offline replay, demo and evaluation commands.
- tests: synthetic checks and integration checks using included recordings.
- lab / falco / config: application lab, sensor rules and versioned policies.
- scenarios: controlled actions and expected outcomes.
- artifacts/recordings: the nine original complete recordings, including fake actions, capture metrics, policy/rules snapshots and separate ground truth.
- artifacts/falco-preflight and artifacts/falco-project: selected historical evidence examples, not continuous sensor logs.
- docs: the consolidated learning documentation.

Recordings contain private Docker-network addresses, container IDs, kernel/host context, and the original lab username/path (for example /home/itamar/projects). They are lab metadata, not credentials. The credential JSON contains only DEMO_ONLY_NOT_A_REAL_SECRET. Recorded bytes are preserved because the input hash checks depend on them.

Continuous captures, regenerated reports, Python caches and local work archives are excluded by .gitignore. Historical archive references in the learning journal describe local development; the archive is not distributed.

## Learning documentation

- [Case study and two-minute presentation (Hebrew)](CASE_STUDY.he.md)
- [Practical lab guide (Hebrew)](docs/lab-guide.he.md)
- [Original approved work plan (Hebrew)](docs/work-plan.he.md)
- [Threat model (Hebrew)](docs/threat-model.md)
- [Original recorded environment (Hebrew)](docs/environment.md)
- [Learning progress and historical journal (Hebrew)](docs/learning-progress.he.md)

## Limits

This is offline replay, not live automated response or blocking. A file open does not prove bytes were read; a connect does not prove exfiltration. The demo sends GET /health, not credentials. UID/command matching does not authenticate authorization: an actor imitating the exception can match it.

Different processes in one container can be correlated even when their actions are unrelated. Timing gaps between earlier application and sensor logs remain undiagnosed; correlation uses Falco event timestamps within one sensor run. No kernel/output drops were reported in the measured low-load recording windows, which does not establish high-load reliability.

Kubernetes, cloud deployment, customer workflows and production operation have not been tested.
