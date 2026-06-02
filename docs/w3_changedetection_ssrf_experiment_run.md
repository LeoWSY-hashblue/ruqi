# W3 changedetection.io SSRF-4 Experiment Run

## Target

- Target repo: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- Experiment: SSRF-4 browser fetch redirect/canary check
- Experiment status: Blocked
- Target service: not started
- Verifier: not run
- Dynamic evidence: none
- Final interpretation: not confirmed
- Blocking reason: Docker image pull/build network failures.
- Runner bugfix commit retained for future runs:
  - `c943798 fix: support docker callback host for SSRF experiments`

## Local Startup Method

- Intended startup: Docker Compose from a temporary compose file under the current fork:
  `run_artifacts/changedetection/docker-compose.yml`
- The compose file builds changedetection.io from the reviewed target checkout and binds:
  `127.0.0.1:5000:5000`
- The compose file enables browser fetcher support with:
  - `PLAYWRIGHT_DRIVER_URL=ws://browser-sockpuppet-chrome:3000`
  - `browser-sockpuppet-chrome` service using `dgtlmoon/sockpuppetbrowser:latest`

## API Key Source

- API key was not obtained.
- Planned source: fresh datastore `settings.application.api_access_token`, or UI Settings > API if datastore access was not sufficient.
- No API key was printed, written to docs, or committed.

## Commands Run

Docker Desktop was started locally, then Docker Compose startup was attempted twice:

```powershell
docker compose -f run_artifacts\changedetection\docker-compose.yml up -d --build
docker compose -f run_artifacts\changedetection\docker-compose.yml up -d --build
```

The intended dry-run and real verifier commands were not executed because the target service never started.
The real command would have used an API key redaction in records:

```powershell
.venv\Scripts\python.exe vulnhuntr\scripts\run_changedetection_ssrf_experiment.py --target-base-url http://127.0.0.1:5000 --mode browser-redirect --api-key <redacted> --dry-run
.venv\Scripts\python.exe vulnhuntr\scripts\run_changedetection_ssrf_experiment.py --target-base-url http://127.0.0.1:5000 --mode browser-redirect --api-key <redacted> --timeout 10 --callback-bind-host 0.0.0.0 --callback-public-host host.docker.internal
```

## Startup Result

- Attempt 1: failed during Docker image pull for `dgtlmoon/sockpuppetbrowser:latest` with Docker Hub referrers EOF.
- Attempt 2: `dgtlmoon/sockpuppetbrowser:latest` pull completed, but changedetection.io local image build failed fetching Docker Hub auth token for `python:3.11-slim-bookworm`.
- The reviewed target service did not start.
- No watch was created.
- No verifier callback server was started for a real experiment.
- No redirect/canary request was attempted.
- Blocking reason: Docker image pull/build network failures, not verifier or runner logic failure.

## Verifier Result

- Result: not run.
- Verifier: not run.
- `/redirect/<token>` hit: not applicable.
- `/canary/<token>` hit: not applicable.
- Dynamic evidence: none.

## Cleanup Status

- `docker compose down --remove-orphans` was run for the temporary compose file.
- Cleanup: docker compose down completed.
- `docker ps` was empty after cleanup.
- Target repository status was clean after cleanup.
- Temporary `run_artifacts/` files were removed and are not part of the run record commit.

## Final Interpretation

This run does not confirm or disprove SSRF-4. The experiment was blocked before
changedetection.io could be started locally with browser fetcher support. The
current status remains: not confirmed. A future run needs Docker Hub access or
preloaded base images for `python:3.11-slim-bookworm` and the browser service.
