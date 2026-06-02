# W3 SSRF Verifier Design

## Goal

Design a minimal deterministic verifier for SSRF candidates that proves whether a
target service performs a server-side request to verifier-controlled URLs.

The verifier must not access real cloud metadata endpoints, private production
services, or destructive targets. It should use only verifier-controlled callback
and canary endpoints.

## Verification Model

| Verdict | Condition |
| --- | --- |
| `confirmed` | Callback server receives a request containing the per-test canary token, or a redirect-target callback receives the token and proves redirect-follow SSRF. |
| `suspected` | PoC succeeds but no callback is received, or the result only proves normal external fetch without a guard bypass. |
| `false_positive` | PoC execution fails, target rejects the URL, or candidate type is unsupported. |

## API Sketch

SSRF verification can either extend the existing verifier entrypoint or live as a
typed helper called from `verify()`.

```python
def verify_ssrf(candidate, target_base_url, poc, callback_server) -> VerifyResult:
    ...
```

Expected inputs:

| Input | Purpose |
| --- | --- |
| `candidate` | Static candidate metadata: file, line, sink type, rule id, suspected path. |
| `target_base_url` | Base URL for the target service under test. |
| `poc` | Deterministic PoC plan that submits a verifier-controlled URL to the target. |
| `callback_server` | Local verifier HTTP server with tokenized callback and redirect endpoints. |

Expected output:

```python
VerifyResult(
    verdict="confirmed" | "suspected" | "false_positive",
    evidence={
        "token": token,
        "callback_hits": [...],
        "poc_status": ...,
        "redirect_hit": True | False,
    },
)
```

Existing `verify()` can dispatch by candidate type:

```python
def verify(candidate, target, poc=None, **kwargs):
    if candidate.sink_type == "ssrf":
        return verify_ssrf(candidate, target.base_url, poc, kwargs["callback_server"])
    ...
```

## Callback Server Design

The callback server should be a local HTTP server started by the verifier test
harness. It records every request in memory and exposes deterministic endpoints.

Required behavior:

- Generate a random per-test token.
- Record method, path, query, headers, remote address, timestamp, and body hash.
- Support a direct callback endpoint:
  - `/callback/<token>`
- Support a redirect endpoint:
  - `/redirect/<token>?to=<url>`
- Support a canary endpoint:
  - `/canary/<token>`
- Provide a wait/poll API for tests:
  - `wait_for_hit(token, timeout)`
  - `hits_for(token)`

Example redirect flow:

1. PoC submits `http://callback/redirect/<token>?to=http://canary/canary/<token>`.
2. Target fetches the redirect URL.
3. Callback server records the `/redirect/<token>` request.
4. Callback server returns `302 Location: http://canary/canary/<token>`.
5. Canary server records `/canary/<token>`.
6. If `/canary/<token>` is hit, verifier returns `confirmed`.

For local-only tests, callback and canary can be the same HTTP server on different
paths. For container-network tests, use verifier-controlled service names or
ports inside an isolated Docker network.

## PoC Contract

The PoC should be deterministic and side-effect bounded.

```python
class SSRFPoC:
    name: str
    mode: Literal["direct", "redirect", "subresource"]

    def run(self, target_base_url: str, callback_url: str, token: str) -> PoCResult:
        ...
```

`PoCResult` should include:

- request status and response body summary,
- whether the target accepted the submitted URL,
- target object id if created,
- cleanup actions attempted,
- errors or exceptions.

The verifier must not infer confirmation from target HTTP success alone. Only
callback evidence can confirm SSRF.

## changedetection.io Experiment Mapping

### SSRF-4 Browser Redirect/Subresource

Purpose: determine whether browser fetchers guard only the initial watch URL or
also block redirect/subresource/browser-side navigation to verifier-controlled
private canaries.

Candidate PoC shape:

1. Configure changedetection.io with browser backend enabled, such as
   `html_webdriver`.
2. Create a watch with a public-looking verifier URL:
   - redirect case: `/redirect/<token>?to=http://canary/canary/<token>`
   - subresource case: HTML page containing image/script/iframe/meta-refresh or
     JavaScript navigation to `/canary/<token>`.
3. Trigger one watch fetch.
4. Inspect callback logs.

Verdict:

- `confirmed`: canary endpoint receives `<token>` after the target fetches the
  public-looking URL with default guard settings.
- `suspected`: target accepts/fetches public URL but canary is not hit.
- `false_positive`: target rejects URL, browser backend unavailable, or PoC fails.

### SSRF-5 Notification Redirect

Purpose: determine whether custom notification HTTP handlers follow redirects to
verifier-controlled canaries without per-hop SSRF validation.

Candidate PoC shape:

1. Configure a notification URL using an accepted method scheme, for example:
   `get://callback/redirect/<token>?to=http://canary/canary/<token>`.
2. Trigger a test notification or controlled watch notification.
3. Inspect callback logs.

Verdict:

- `confirmed`: redirect target canary receives `<token>` with default guard
  settings.
- `suspected`: initial callback is hit but redirect target is not hit.
- `false_positive`: notification URL is rejected or notification send fails.

## Safety Boundaries

- Do not request real cloud metadata endpoints, including `169.254.169.254`.
- Do not request real private network services.
- Redirect targets must be verifier-controlled callback/canary endpoints only.
- Use isolated Docker networks for target experiments.
- Use random tokens to prevent stale callback logs from influencing verdicts.
- Do not send destructive HTTP methods unless the candidate specifically
  requires method coverage and the endpoint is verifier-controlled.
- Do not use internet-facing third-party callback services for final evidence.
- Treat environment flags such as `ALLOW_IANA_RESTRICTED_ADDRESSES=true` as
  explicit bypass configuration; verifier should record them and avoid claiming
  a default-policy bypass when they are enabled.

## Test Plan

### Unit Tests

- Mock callback logs and assert verdict mapping:
  - direct callback hit -> `confirmed`
  - redirect target hit -> `confirmed`
  - PoC success with no hit -> `suspected`
  - PoC failure -> `false_positive`
- Verify token isolation:
  - stale token hits do not confirm a new test.
- Verify redirect URL construction is restricted to verifier-controlled hosts.
- Verify callback hit evidence is included in `VerifyResult.evidence`.

### E2E Fixture

Build a small local fixture app that exposes:

- a route that fetches a user-supplied URL and follows redirects,
- a route that fetches a user-supplied URL but blocks redirects,
- a route that rejects unsupported URL schemes.

Expected fixture tests:

- follow-redirect fixture -> `confirmed` when canary is hit,
- block-redirect fixture -> `suspected` when initial callback is hit but canary
  is not,
- reject fixture -> `false_positive`,
- no callback -> `suspected` or `false_positive` depending on PoC success.

### changedetection.io Target Experiment

The real changedetection.io experiment is deliberately deferred.

Prerequisites before running:

- Implement SSRF verifier callback server and tests.
- Confirm target runs in an isolated Docker network.
- Confirm no real metadata/private endpoints are used.
- Confirm auth/API setup and cleanup path for watches/notifications.
- Run only after static review approves a specific SSRF-4 or SSRF-5 PoC.

## Open Design Questions

- Should callback/canary be one server with multiple paths or two services to
  better model external-to-internal redirect behavior?
- Should verifier support browser-subresource evidence separately from redirect
  evidence?
- Should notification verification enumerate method schemes or require a
  candidate-specific PoC to choose the scheme?
- How should verifier report environment guard bypass flags, such as
  `ALLOW_IANA_RESTRICTED_ADDRESSES=true`, without overclaiming?
