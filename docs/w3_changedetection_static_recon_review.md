# W3 changedetection.io Static Recon Review

## Target Commit

- Target repo: `https://github.com/dgtlmoon/changedetection.io`
- Target path: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- LLM: Not run in this review
- Verifier: Not run
- Target service: Not run

## Inputs Reviewed

- `docs/w3_changedetection_recon_context.md`
- `docs/w3_changedetection_llm_recon.md`
- `changedetectionio/processors/base.py`
- `changedetectionio/content_fetchers/requests.py`
- `changedetectionio/content_fetchers/playwright.py`
- `changedetectionio/browser_steps/browser_steps.py`
- `changedetectionio/forms.py`
- `changedetectionio/blueprint/ui/edit.py`
- `changedetectionio/api/Watch.py`
- `changedetectionio/api/Notifications.py`
- `changedetectionio/blueprint/ui/notification.py`
- `changedetectionio/notification/handler.py`
- `changedetectionio/notification/apprise_plugin/custom_handlers.py`
- `changedetectionio/tests/unit/test_notification_iana_restricted.py`

## SSRF-4 Browser Fetch Finding

### Data Flow

Stored watch URLs reach the worker fetch path through the normal watch processing flow:

```text
changedetectionio/worker.py:157
watch = datastore.data['watching'].get(uuid)
processor = watch.get('processor', 'text_json_diff')
processor_module = get_processor_module(processor)
update_handler = processor_module.perform_site_check(datastore=datastore, watch_uuid=uuid)
await update_handler.call_browser()
```

`difference_detection_processor.call_browser()` resolves the stored URL from `self.watch.link`, rejects `file:` unless explicitly allowed, then calls `validate_iana_url()` before choosing requests/browser/plugin fetchers:

```text
changedetectionio/processors/base.py:100
async def validate_iana_url(self):
    if strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false')):
        return
    loop = asyncio.get_running_loop()
    if await loop.run_in_executor(None, is_url_private_or_parser_confused, self.watch.link):
        raise Exception(...)

changedetectionio/processors/base.py:121
url = self.watch.link
if re.search(r'^file:', url.strip(), re.IGNORECASE):
    if not strtobool(os.getenv('ALLOW_FILE_URI', 'false')):
        raise Exception(...)
await self.validate_iana_url()
prefer_fetch_backend = self.watch.get('fetch_backend', 'system')
if not prefer_fetch_backend or prefer_fetch_backend == 'system':
    prefer_fetch_backend = self.datastore.data['settings']['application'].get('fetch_backend')
```

Browser fetchers are selected when `fetch_backend` resolves to `html_webdriver`, including per-watch settings, global settings, browser steps, or `extra_browser_*` mappings:

```text
changedetectionio/processors/base.py:146
if prefer_fetch_backend.startswith('extra_browser_'):
    ...
    prefer_fetch_backend = 'html_webdriver'
    custom_browser_connection_url = connection[0].get('browser_connection_url')

changedetectionio/processors/base.py:162
if hasattr(content_fetchers, prefer_fetch_backend):
    if prefer_fetch_backend == 'html_webdriver' and self.watch.has_browser_steps:
        from changedetectionio.content_fetchers.playwright import fetcher as playwright_fetcher
        fetcher_obj = playwright_fetcher
    else:
        fetcher_obj = getattr(content_fetchers, prefer_fetch_backend)
```

The Playwright backend then navigates to the URL with `page.goto()`:

```text
changedetectionio/content_fetchers/playwright.py:300
browsersteps_interface = steppable_browser_interface(start_url=url)
browsersteps_interface.page = self.page
response = await browsersteps_interface.action_goto_url(value=url)

changedetectionio/browser_steps/browser_steps.py:134
async def action_goto_url(self, selector=None, value=None):
    response = await self.page.goto(value, timeout=0, wait_until='load')
    return response
```

### Guard Assessment

The browser fetch path is not unguarded: it shares the processor-level `validate_iana_url()` preflight guard before fetcher selection and before `page.goto()`. That guard uses `is_url_private_or_parser_confused()` and is intended to cover requests, browser fetchers, and plugins.

This is not fully equivalent to the requests fetcher. The requests backend additionally disables automatic redirects and checks every redirect hop before manually following it:

```text
changedetectionio/content_fetchers/requests.py:98
r = session.request(..., url=url, allow_redirects=False)

changedetectionio/content_fetchers/requests.py:115
if not allow_iana_restricted:
    if is_url_private_or_parser_confused(redirect_url):
        raise Exception(...)
```

No equivalent browser-navigation redirect, iframe, subresource, meta-refresh, JavaScript redirect, or browser-step destination guard was found in the reviewed Playwright excerpts. The processor-level check covers the initial URL, but browser behavior after initial navigation needs separate static or runtime confirmation.

### User Control

`fetch_backend` is user/config controlled in multiple places:

```text
changedetectionio/forms.py:792
fetch_backend = RadioField(..., choices=content_fetchers.available_fetchers(), ...)

changedetectionio/blueprint/ui/edit.py:164
for p in datastore.extra_browsers:
    form.fetch_backend.choices.append(p)
form.fetch_backend.choices.append(("system", ...))

changedetectionio/forms.py:1049
fetch_backend = RadioField(..., default="html_requests", choices=content_fetchers.available_fetchers(), ...)
```

The path is active and can plausibly be selected by an authenticated UI/API user or administrator, depending on deployment auth and settings. However, the initial browser fetch URL has a private-host guard before browser navigation.

### SSRF-4 Conclusion

SSRF-4 is a `P1` static-review candidate, not a verifier-ready P0. The direct claim that browser fetch lacks an SSRF guard is not supported: `validate_iana_url()` guards the initial stored URL before all fetchers. The remaining concern is incomplete parity with `requests.py` redirect-hop handling for browser navigations and browser-controlled secondary requests.

## SSRF-5 Notification Finding

### Data Flow

Notification URLs can be supplied through API, watch/tag settings, or UI test notification paths:

```text
changedetectionio/api/Notifications.py:21
def post(self):
    json_data = request.get_json()
    notification_urls = json_data.get("notification_urls", [])
    validate_notification_urls(notification_urls)
    for url in notification_urls:
        clean_url = url.strip()
        added_url = self.datastore.add_notification_url(clean_url)

changedetectionio/blueprint/ui/notification.py:41
notification_urls = request.form.get('notification_urls','').strip().splitlines()
...
n_object = NotificationContextData({
    'watch_url': request.form.get('window_url', "https://changedetection.io"),
    'notification_urls': notification_urls
})
```

Validation uses Apprise parsing and Jinja rendering:

```text
changedetectionio/api/Notifications.py:97
def validate_notification_urls(notification_urls):
    from changedetectionio.forms import ValidateAppRiseServers
    validator = ValidateAppRiseServers()
    ...
    validator(dummy_form, field)

changedetectionio/forms.py:497
class ValidateAppRiseServers(object):
    def __call__(self, form, field):
        apobj = apprise.Apprise(asset=apprise_asset)
        for server_url in field.data:
            url = jinja_render(template_str=server_url.strip(), **generic_notification_context_data).strip()
            if url.startswith("#"):
                continue
            if not apobj.add(url):
                raise ValidationError(...)
```

At send time, notification URLs are rendered again, added to Apprise, and sent server-side:

```text
changedetectionio/notification/handler.py:416
for url in n_object['notification_urls']:
    ...
    url = jinja_render(template_str=url, **notification_parameters)
    ...
    if not url.startswith('null://'):
        apobj.add(url)
...
apobj.notify(...)
```

The custom HTTP notification handler performs the server-side HTTP request:

```text
changedetectionio/notification/apprise_plugin/custom_handlers.py:186
url: str = meta.get("url")
schema: str = meta.get("schema")
method: str = re.sub(r"s$", "", schema).upper()
...
url = re.sub(rf"^{schema}", "https" if schema.endswith("s") else "http", parsed_url.get("url"))
if not os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', '').lower() in ('true', '1', 'yes'):
    if is_url_private_or_parser_confused(url):
        raise ValueError(...)
response = requests.request(method=method, url=url, ...)
```

### Guard Assessment

For the reviewed custom HTTP handler path, private/loopback/reserved addresses and parser-differential payloads are blocked by default through `is_url_private_or_parser_confused(url)`. The test suite explicitly covers private IP and loopback blocking and the `ALLOW_IANA_RESTRICTED_ADDRESSES=true` bypass:

```text
changedetectionio/tests/unit/test_notification_iana_restricted.py:24
def test_private_ip_blocked_by_default(...)

changedetectionio/tests/unit/test_notification_iana_restricted.py:44
def test_loopback_blocked_by_default(...)

changedetectionio/tests/unit/test_notification_iana_restricted.py:62
def test_private_ip_allowed_when_env_var_set(...)
```

The reviewed custom handler does not pass `allow_redirects=False`, so requests' default redirect behavior may follow redirects. The reviewed code does not show a per-hop redirect guard for notification HTTP redirects comparable to `content_fetchers/requests.py`.

The remaining open issue is coverage, not an immediate exploitable finding: confirm whether all HTTP-capable Apprise schemes accepted by `ValidateAppRiseServers()` are routed through `apprise_http_custom_handler` or have equivalent private-host and redirect protections.

### User Control

Notification URLs are user-controlled through authenticated API/UI paths, but effective privileges depend on deployment auth and whether the user can edit global, watch, or tag notification settings. The UI test endpoint is protected by `@login_optionally_required`; whether anonymous users can invoke it depends on runtime auth configuration.

### SSRF-5 Conclusion

SSRF-5 is a `P1` static-review candidate, not a verifier-ready P0. There is clear server-side request behavior to user-supplied notification URLs, but the reviewed custom HTTP path has a private-host/parser guard by default. The main residual concerns are redirect-hop handling and Apprise scheme coverage.

## Static Conclusion Table

| Recon ID | Active entrypoint | User controlled URL | SSRF guard present? | Verifier feasible? | Priority | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| SSRF-4 browser fetch | Yes: worker fetch path with `html_webdriver` / Playwright backend | Yes: stored watch URL and selectable `fetch_backend` | Yes for initial URL via `validate_iana_url()`; no proven browser redirect/subresource parity | Yes, but only after static proof of redirect/subresource bypass hypothesis | P1 | Active path reaches `page.goto()`, but initial URL is guarded before fetcher selection. Needs focused static/runtime check for browser-only redirect behavior. |
| SSRF-5 notification URL | Yes: API/UI notification paths and notification send pipeline | Yes: `notification_urls` | Yes for reviewed custom HTTP handler; redirect-hop guard not shown; scheme coverage needs confirmation | Yes, but only after identifying an unguarded accepted scheme or redirect path | P1 | Server-side notification requests exist, but custom HTTP handler blocks private/parser-confused targets by default. |

## Recommended Next Step

No candidate currently qualifies for immediate verifier execution as P0.

For SSRF-4, continue static review before verifier:

1. Inspect `validate_iana_url()` callers and processor subclasses to confirm every browser fetch path enters `difference_detection_processor.call_browser()`.
2. Inspect Playwright/Puppeteer/Selenium behavior for redirects, JavaScript navigations, iframe/subresource fetches, and browser steps.
3. If a browser-only navigation bypass is statically plausible, build a Docker verifier experiment with:
   - a public-looking redirect canary service,
   - a private/internal canary endpoint,
   - one watch configured with `html_webdriver`,
   - expected result: private canary must not be reached unless `ALLOW_IANA_RESTRICTED_ADDRESSES=true`.

For SSRF-5, continue static review before verifier:

1. Enumerate accepted Apprise HTTP-capable schemes after `ValidateAppRiseServers()`.
2. Confirm each accepted HTTP-capable scheme uses `apprise_http_custom_handler` or an equivalent guard.
3. Check redirect behavior from the custom handler and any Apprise fallback HTTP client.
4. If an unguarded scheme or redirect-hop bypass is found, build a Docker verifier experiment with a notification URL pointing to a redirecting canary and a private/internal canary endpoint.
