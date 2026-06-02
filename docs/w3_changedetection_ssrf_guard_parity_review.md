# W3 changedetection.io SSRF Guard Parity Review

## Target Commit

- Target repo: `https://github.com/dgtlmoon/changedetection.io`
- Target path: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- LLM: Not run in this review
- Verifier: Not run
- Target service: Not run

## Reviewed Code Paths

- `changedetectionio/processors/base.py`
- `changedetectionio/content_fetchers/requests.py`
- `changedetectionio/content_fetchers/playwright.py`
- `changedetectionio/content_fetchers/puppeteer.py`
- `changedetectionio/content_fetchers/webdriver_selenium.py`
- `changedetectionio/browser_steps/browser_steps.py`
- `changedetectionio/notification/handler.py`
- `changedetectionio/notification/apprise_plugin/custom_handlers.py`
- `changedetectionio/tests/unit/test_notification_iana_restricted.py`
- `docker-compose.yml`

## Browser Fetch Redirect/Subresource Parity

### Requests Fetcher Baseline

The plain requests fetcher has both an initial target guard and explicit redirect-hop validation:

```text
changedetectionio/content_fetchers/requests.py:86
allow_iana_restricted = strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false'))

changedetectionio/content_fetchers/requests.py:93
if is_url_private_or_parser_confused(url):
    raise Exception(...)

changedetectionio/content_fetchers/requests.py:98
r = session.request(..., url=url, allow_redirects=False)

changedetectionio/content_fetchers/requests.py:113
location = r.headers.get('Location', '')
redirect_url = urljoin(current_url, location)
if is_url_private_or_parser_confused(redirect_url):
    raise Exception(...)
r = session.request('GET', redirect_url, ..., allow_redirects=False)
```

This is the strongest observed parity target: private-host/parser checks run before the first request and before every followed redirect.

### Shared Initial Guard

All normal fetchers appear to enter `difference_detection_processor.call_browser()`, which calls `validate_iana_url()` before fetcher selection:

```text
changedetectionio/processors/base.py:100
async def validate_iana_url(self):
    if strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false')):
        return
    if await loop.run_in_executor(None, is_url_private_or_parser_confused, self.watch.link):
        raise Exception(...)

changedetectionio/processors/base.py:130
await self.validate_iana_url()
```

This means the initial stored watch URL is guarded for requests, Playwright, Puppeteer, Selenium, and plugin fetchers that are invoked through `call_browser()`.

### Browser Fetchers

The browser fetchers then navigate directly to the URL:

```text
changedetectionio/content_fetchers/playwright.py:285
context = await browser.new_context(
    accept_downloads=False,
    bypass_csp=True,
    extra_http_headers=request_headers,
    ignore_https_errors=True,
    proxy=self.proxy,
    service_workers=os.getenv('PLAYWRIGHT_SERVICE_WORKERS', 'allow'),
)

changedetectionio/content_fetchers/playwright.py:305
response = await browsersteps_interface.action_goto_url(value=url)

changedetectionio/browser_steps/browser_steps.py:134
async def action_goto_url(self, selector=None, value=None):
    response = await self.page.goto(value, timeout=0, wait_until='load')
    return response

changedetectionio/content_fetchers/puppeteer.py:411
response = await self.page.goto(url, timeout=0)

changedetectionio/content_fetchers/webdriver_selenium.py:130
driver.get(url)
```

Static grep did not find request interception hooks such as `context.route(...)`, `page.route(...)`, request abort/continue handlers, or per-request private-host checks in the reviewed browser fetchers. Playwright only attaches a console handler; Puppeteer attaches frame/load handlers for stopping long loads, not URL policy enforcement. Selenium calls `driver.get(url)` directly.

Browser navigation normally follows HTTP redirects and loads subresources for the loaded document. The reviewed code does not disable JavaScript, block resource loading, or re-check redirect, iframe, image/script, meta refresh, service worker, or JavaScript navigation URLs against `is_url_private_or_parser_confused()`. Playwright explicitly sets `bypass_csp=True` and leaves `service_workers` controlled by `PLAYWRIGHT_SERVICE_WORKERS`, defaulting to `allow`.

### Browser Assessment

The initial browser URL is guarded, so a direct private URL such as `http://127.0.0.1/` should be blocked before `page.goto()`. Guard parity is incomplete after that first URL:

- Requests fetcher: guarded initial URL plus guarded redirects.
- Browser fetchers: guarded initial URL only; no observed per-navigation or per-request guard.
- Browser subresources and browser-side redirects are plausible SSRF vectors if a normal user can make the service fetch an attacker-controlled public page with browser backend enabled.

Current priority: `P1`.

This is not downgraded to P2 because the absence of browser per-request checks is concrete and the browser path is active. It is not upgraded to P0 yet because runtime network reachability and deployment auth/backend-control assumptions still need a controlled verifier experiment.

## Notification Redirect/Scheme Parity

### Scheme Registration

The project registers custom handlers for HTTP-like Apprise methods:

```text
changedetectionio/notification/apprise_plugin/custom_handlers.py:65
SUPPORTED_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head"}

changedetectionio/notification/apprise_plugin/custom_handlers.py:68
def notify_supported_methods(func):
    for method in SUPPORTED_HTTP_METHODS:
        _register_http_handler(method, func)
        _register_http_handler(f"{method}s", func)
    return func

changedetectionio/notification/apprise_plugin/custom_handlers.py:121
plugins.N_MGR.add(plugin=CustomHTTPHandler, schemas=schema, ...)

changedetectionio/notification/apprise_plugin/custom_handlers.py:174
@notify_supported_methods
def apprise_http_custom_handler(...):
```

This covers the explicit `get/gets/post/posts/put/puts/delete/deletes/patch/patchs/head/heads` custom schemes used by changedetection.io's Apprise integration.

### Custom Handler Guard

The custom handler checks the resolved HTTP(S) URL before making the request:

```text
changedetectionio/notification/apprise_plugin/custom_handlers.py:199
url = re.sub(rf"^{schema}", "https" if schema.endswith("s") else "http", parsed_url.get("url"))

changedetectionio/notification/apprise_plugin/custom_handlers.py:204
if not os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', '').lower() in ('true', '1', 'yes'):
    if is_url_private_or_parser_confused(url):
        raise ValueError(...)

changedetectionio/notification/apprise_plugin/custom_handlers.py:212
response = requests.request(method=method, url=url, auth=auth, headers=headers, params=params, data=...)
```

Unit tests cover private IP and loopback blocking by default, and the explicit `ALLOW_IANA_RESTRICTED_ADDRESSES=true` bypass.

### Redirect Gap

Unlike the requests fetcher, the notification custom handler does not pass `allow_redirects=False` and does not manually inspect `Location` headers. `requests.request()` therefore uses Requests' default redirect behavior. The reviewed code does not re-check the final redirected URL with `is_url_private_or_parser_confused()`.

The most plausible remaining SSRF path is:

1. User supplies an accepted notification URL such as `get://public.example/redirect`.
2. Custom handler checks the initial public URL and allows it.
3. The public endpoint redirects to a private address or metadata IP.
4. Requests follows the redirect without a changedetection.io per-hop guard.

### Other Schemes

The reviewed source only shows custom registration for the method-like schemes above and a custom Discord override. It does not prove every possible Apprise built-in scheme is safe, but the clearest HTTP SSRF surface in this codebase is the custom HTTP method handler. Non-HTTP schemes may still cause server-side network actions, but they are outside the focused SSRF parity path and need separate scheme-by-scheme triage before verifier work.

### Environment Control

`ALLOW_IANA_RESTRICTED_ADDRESSES` defaults to false in code paths that use `strtobool(os.getenv(..., 'false'))`, and the notification handler treats unset as blocked. The only observed enablement is via environment variable or tests. Static review did not find a UI/API route that lets a normal user set this environment variable at runtime.

Current priority: `P1`.

This is not downgraded to P2 because the redirect-hop gap is concrete in the custom handler. It is not upgraded to P0 until a verifier demonstrates that Requests follows the redirect in the deployed notification path and that a normal reachable role can trigger the notification request.

## P0 Upgrade Criteria

Upgrade to P0 only if a controlled experiment or additional static proof shows all of the following:

1. A normal reachable user role can create or update the relevant URL input.
2. The input reaches the browser or notification server-side request path in a default or realistic deployment.
3. The initial guard allows a public-looking URL.
4. A redirect, subresource, browser navigation, or accepted notification scheme reaches an internal/private canary endpoint without `ALLOW_IANA_RESTRICTED_ADDRESSES=true`.
5. The behavior is reproducible in an isolated Docker network with observable canary evidence.

## Current Assessment

| Recon ID | Path | Guard parity | Current priority | Reason |
| --- | --- | --- | --- | --- |
| SSRF-4 | Watch URL -> browser fetcher -> `page.goto()` / `driver.get()` | Initial URL guard present; no observed browser redirect/subresource/request interception guard | P1 | Active path and concrete browser parity gap, but runtime reachability and role/backend-control assumptions need verification. |
| SSRF-5 | Notification URL -> custom HTTP handler -> `requests.request()` | Initial URL guard present; no observed redirect-hop guard | P1 | Active server-side request path and concrete redirect parity gap, but needs verifier proof and privilege confirmation. |

No current evidence supports P2 downgrade: both gaps remain plausible. No current evidence supports P0 upgrade without runtime canary proof.

## Proposed Verifier Experiment

Because both items remain P1, the next step is a non-destructive Docker verifier experiment.

### Browser Fetch Experiment

- Run changedetection.io in an isolated Docker network with browser backend enabled.
- Run a controlled public-facing test server in the same test network.
- Public test URL returns:
  - HTTP 302 redirect to `http://127.0.0.1:<canary>/browser-redirect`, or
  - HTML with image/script/iframe/meta-refresh/JS navigation pointing at `http://127.0.0.1:<canary>/browser-subresource`.
- The canary server records callbacks only; no destructive traffic.
- Create a watch using browser backend (`html_webdriver`) and trigger one fetch.
- Expected safe behavior: no canary hit for private/internal targets unless `ALLOW_IANA_RESTRICTED_ADDRESSES=true`.
- Verifier-ready signal: canary hit with default guard settings.

### Notification Experiment

- Run changedetection.io in an isolated Docker network.
- Configure a notification URL using an accepted custom HTTP scheme, such as `get://<public-test-server>/redirect`.
- Public test server returns HTTP 302 to an internal/private canary URL.
- Trigger a test notification or controlled watch notification.
- Expected safe behavior: no canary hit for private/internal redirect targets.
- Verifier-ready signal: canary hit through notification redirect with default guard settings.
