# vibe-security-score

*(English | [한국어](README.ko.md))*

A CLI tool that automatically scores the security of AI-generated ("vibe coded") Flask
auth apps.

It takes a single **submission directory** containing the generated code,
`requirements.txt`, and the participant's prompt as `prompt.md`, runs static and dynamic
checks, and produces a human-readable report (✔/✘ with deduction reasons) plus
machine-readable JSON.

```
submission/
├── app.py              # (or main.py / run.py / …) the generated Flask app
├── requirements.txt    # the app's dependencies
├── prompt.md           # the participant's prompt
└── templates/ …        # any other generated files
```

## Requirements

The grader is a **Windows** program. It assumes a fully provisioned host — all of the
following present and running:

- **Windows** with **Python 3.11**.
- **Docker Desktop** running. The functional gate runs each submission inside a standard
  Linux `python:3.11-slim` container and calls it over HTTP from the Windows host.
- **`osv-scanner` and a local OSV database.** The CVE check runs them in offline mode for
  reproducible results. See [Offline CVE database](#offline-cve-database) for setup.

## How it works

The scorer runs four modules, each returning a sub-score (0–100) and a list of findings:

| Module | Type | Checks |
| --- | --- | --- |
| `secure_coding` | static | hardcoded secrets, `debug=True`, CSRF, password hashing, raw SQL, XSS, session-cookie flags, security headers |
| `dependencies` | static | CVEs (OSV, offline) and typosquatting against a local popular-package snapshot |
| `prompt_quality` | static | security-concept coverage and density of the prompt |
| `functional` | dynamic | starts the app and exercises `POST /register` / `POST /login` over HTTP |

The functional module starts each submission in a standard `python:3.11-slim` container
controlled by the scorer (participants do not provide a Dockerfile). The scorer mounts
the code, installs `requirements.txt`, launches the app, and calls it over HTTP. The
container keeps its network so the app can use its database and serve requests.

The HTTP contract is fixed (`POST /register`, `POST /login`) but I/O is handled
leniently: field names are read from the source where possible and otherwise a superset
of common aliases is sent; the body is tried as JSON then as form data; any 2xx/3xx is a
success.

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Grade a submission — human-readable report to stdout
# (the prompt is read from <submission>/prompt.md)
python run.py --code path/to/submission

# Also write the machine-readable JSON to a file
python run.py --code path/to/submission --json result.json
```

Run against the bundled samples:

```bash
python run.py --code samples/insecure_app
python run.py --code samples/secure_app
```

## Scoring model

- **Final score** = Σ(module sub-score × weight). Weights live in `config.py`.
- The functional module is a **gate**: if the app fails to start or a core flow
  (register/login) fails, the final score is capped at `FUNCTIONAL_GATE_CAP`. This stops
  an empty or broken submission from scoring full marks for having "zero vulnerabilities".
- The report lists every check ✔/✘ with its deduction reason and sub-score, then the
  weighted sum, final score, grade, and PASS/FAIL. The deduction reasons are the point —
  they tell the participant what to fix.

All weights, thresholds, and deduction values are in `config.py`; the module logic does
not hardcode them.

## Tests

```bash
python -m pytest -q
```

These are regression tests for the grader itself, not for grading submissions. The
functional gate is covered with mocked Docker/HTTP.

## Offline CVE database

The CVE check runs `osv-scanner` in offline mode for reproducibility.

1. Install `osv-scanner` and put it on `PATH`.
2. Download an OSV database snapshot into the directory named by `OSV_OFFLINE_DB_DIR` in
   `config.py` (default `data/osv_db/`). Pin the snapshot for reproducible results.

## Notes

- The app container publishes its port to the Windows host (`-p 5000:5000`). A read-only
  shim (`docker_shim/sitecustomize.py`) is mounted and put on `PYTHONPATH` so it auto-loads
  and rebinds Flask's `app.run()` to `0.0.0.0:5000` inside the container — otherwise an app
  that hardcodes `127.0.0.1` would be unreachable through the published port. The container
  keeps its network for the app's DB / outbound needs.
- A submission whose `requirements.txt` cannot be installed, or whose code raises on import
  (missing functions / fake APIs → ImportError/AttributeError), fails to start and so fails
  the functional gate — caught at startup rather than by a separate analyzer.
