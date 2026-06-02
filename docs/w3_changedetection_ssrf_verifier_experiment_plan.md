# W3 changedetection.io SSRF Verifier Experiment Plan

## Target

- Target repo: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- Verifier implementation: `vulnhuntr.ssrf_verifier.verify_ssrf`
- Status: plan only. Do not run changedetection.io yet.
- Phase 1 scope: implement and review `browser-redirect` only.
- Deferred scope: `notification-redirect` remains blocked until UI route/session/CSRF
  behavior and an accepted Apprise HTTP scheme are confirmed.

## Current Candidates

| Candidate | Description | Current priority | Reason |
| --- | --- | --- | --- |
| SSRF-4 | Browser fetch redirect/subresource guard parity | P1 | Initial URL guard exists, but browser redirect/subresource parity is not proven. |
| SSRF-5 | Notification HTTP redirect guard parity | P1 | Initial notification URL guard exists, but redirect-hop guard is not shown. |

## Preconditions

Before running any real target experiment, confirm:

- Exact startup path:
  - local Python command, Docker command, or compose service for changedetection.io.
  - expected listening URL, for example `http://127.0.0.1:<port>`.
- Authentication:
  - whether UI auth is enabled.
  - whether API key access is enabled.
  - how to pass API key to watch/notification endpoints.
  - API key source:
    - UI: Settings > API.
    - Fresh datastore: `settings.application.api_access_token` in the persisted
      datastore, pending confirmation in the exact runtime.
- Browser fetcher:
  - whether `html_webdriver` is available in the local runtime.
  - whether Playwright/Puppeteer/Selenium service is required.
  - how to create a watch using browser fetcher without relying on UI clicks.
  - Docker Compose browser service requirements:
    - set `PLAYWRIGHT_DRIVER_URL=ws://browser-sockpuppet-chrome:3000`.
    - enable the `browser-sockpuppet-chrome` service.
- Notification path:
  - exact API route and payload for notification URL configuration.
  - whether test notification can be triggered through API or only UI endpoint.
  - whether CSRF/session auth is required for UI test notification.
- Cleanup:
  - how to delete any watch created for the experiment.
  - how to remove notification URL settings after the experiment.

Do not run the experiment until these are confirmed.

## Experiment A: Browser Fetch Redirect

Goal: test whether browser fetchers follow a public-looking redirect to a verifier
canary endpoint without equivalent redirect-hop SSRF validation.

Setup:

1. Start the SSRF verifier callback server.
2. Generate a per-test token.
3. Create:
   - callback URL: `/callback/<token>`
   - canary URL: `/canary/<token>`
   - redirect URL: `/redirect/<token>?to=<canary_url>`
4. Create a changedetection.io watch whose URL is the verifier redirect URL.
5. Configure that watch to use browser fetcher, such as `html_webdriver`.
6. Trigger one fetch of the watch.

Expected evidence:

| Result | Evidence |
| --- | --- |
| `confirmed` | Callback server receives `/canary/<token>`, proving browser fetch followed redirect to verifier-controlled canary. |
| `suspected` | Only `/redirect/<token>` is observed, or no callback is observed while PoC succeeds. |
| `false_positive` | Watch creation/fetch fails, target rejects the URL, or browser fetcher is unavailable. |

Subresource variant:

- Instead of an HTTP redirect, the public verifier page can return HTML that
  references `/canary/<token>` through image/script/iframe/meta-refresh/JS
  navigation.
- This variant should only use verifier-controlled callback/canary endpoints.

## Experiment B: Notification Redirect

Goal: test whether changedetection.io notification HTTP handlers follow redirects
to a verifier canary endpoint without equivalent redirect-hop SSRF validation.

Status: deferred. The UI send-test route is known, but session/CSRF handling and
the exact Apprise HTTP scheme/payload for a deterministic local experiment are
not yet confirmed. The runner must continue to exit with a clear not implemented
message for `notification-redirect`.

Setup:

1. Start the SSRF verifier callback server.
2. Generate a per-test token.
3. Create a verifier redirect URL pointing to the verifier canary URL.
4. Configure changedetection.io notification URL to an accepted HTTP method
   scheme that targets the verifier redirect URL.
5. Trigger a test notification or a controlled watch notification.

Expected evidence:

| Result | Evidence |
| --- | --- |
| `confirmed` | Callback server receives `/canary/<token>`, proving notification request followed redirect to verifier-controlled canary. |
| `suspected` | Only `/redirect/<token>` is observed, or no callback is observed while PoC succeeds. |
| `false_positive` | Notification URL is rejected, auth fails, or notification trigger fails. |

## Safety Boundaries

- Do not access real metadata endpoints.
- Do not use real private/internal service targets.
- Do not send traffic to third-party callback collectors.
- Redirects must target only verifier-controlled callback/canary endpoints.
- Use random per-test tokens and ignore stale callback logs.
- Do not send destructive requests.
- Do not set `ALLOW_IANA_RESTRICTED_ADDRESSES=true` for default-policy bypass
  tests unless the experiment explicitly records that it is testing an opt-in
  unsafe configuration.
- Do not run this experiment outside an isolated local or Docker test network.

## PoC Callable Shapes

The SSRF verifier contract is:

```python
def poc(target_base_url: str, callback_url: str, redirect_url: str) -> int:
    ...
```

### Browser Redirect PoC Pseudocode

```python
def browser_redirect_poc(target_base_url, callback_url, redirect_url):
    # 1. create watch with url=redirect_url
    # 2. configure fetch_backend=html_webdriver
    # 3. trigger watch fetch
    # 4. return 0 if API accepted and fetch trigger was attempted
    # 5. return non-zero on auth/API/validation failure
    return 1  # placeholder until API details are confirmed
```

### Notification Redirect PoC Pseudocode

```python
def notification_redirect_poc(target_base_url, callback_url, redirect_url):
    # 1. convert redirect_url to accepted changedetection notification scheme
    # 2. configure notification URL through API or UI endpoint
    # 3. trigger test notification
    # 4. return 0 if notification trigger was attempted
    # 5. return non-zero on auth/API/validation failure
    return 1  # placeholder until API details are confirmed
```

## Blocking Unknowns

- Exact startup command for local changedetection.io at the reviewed commit.
- Whether auth is enabled by default in the intended runtime.
- Whether API key access is enabled and how to provision it.
- Exact watch create/update/trigger endpoints and payloads.
- Exact field name for selecting browser fetcher through API.
- Whether a separate browser service is required for `html_webdriver`.
- Exact notification API route and payload.
- Whether notification test trigger requires CSRF/session auth.
- Cleanup endpoints for watches and notification settings.

## Review Gate

Do not run this experiment until:

1. The skeleton runner is reviewed.
2. Exact changedetection.io API/UI details are confirmed.
3. The target can run in an isolated local or Docker test environment.
4. The PoC uses only verifier-controlled callback/canary URLs.
