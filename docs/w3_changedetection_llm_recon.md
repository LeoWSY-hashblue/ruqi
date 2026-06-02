Status: LLM reconnaissance output only; static review is required before verifier execution.

## Bounded static recon summary

Static context shows several user-supplied URL-like inputs reaching fetch, browser navigation, notification, or file-serving paths. All items below are candidate paths for human review only.

---

## Entrypoints

| Entrypoint | File | Line | Input sources | Classification | Evidence |
|---|---:|---:|---|---|---|
| `/api/v1/watch` `POST` / `CreateWatch.post` | `changedetectionio/api/Watch.py` | 465 | JSON `url`, extras/tags implied | recon candidate | Reads `request.get_json()`, strips `json_data['url']`, checks `is_safe_valid_url(url)`, stores via `datastore.add_watch(url=url, extras=extras, tag=tags)`. |
| `/api/v1/watch/<uuid>` `PUT` / `Watch.put` | `changedetectionio/api/Watch.py` | 172 | JSON `url`; other watch settings not fully shown | recon candidate | If `url` is in `request.json`, validates with `is_safe_valid_url(new_url.strip())`; update path can affect stored watch URL. |
| `/form/add/quickwatch` `POST` | `changedetectionio/blueprint/ui/views.py` | 11 | Form `url`, `tags`, extras implied | recon candidate | Builds `quickWatchForm(request.form)`, validates, reads `request.form.get('url').strip()`, stores with `datastore.add_watch(url=url, ...)`. |
| `/edit/<uuid>` `GET/POST` | `changedetectionio/blueprint/ui/edit.py` | unknown | Watch settings form fields | needs static check | Routing map says edit path updates watch settings and form class depends on processor, but selected excerpts do not include handler body or field allowlist. |
| Worker queue / `worker_handler` | `changedetectionio/worker.py` | 157 | Stored watch URL and watch settings | recon candidate | Loads watch by UUID, resolves processor module, creates update handler, calls `await update_handler.call_browser()`. |
| Fetch processor / `call_browser` | `changedetectionio/processors/base.py` | 121 | `self.watch.link`, `fetch_backend`, request settings implied | recon candidate | Uses stored `self.watch.link`; file URI gate shown; calls `await self.validate_iana_url()`; selects `self.watch.get('fetch_backend', 'system')`; constructs fetcher. |
| Requests fetch backend | `changedetectionio/content_fetchers/requests.py` | 86, 98, 115 | Stored watch URL, redirects, headers/body/proxies implied | recon candidate | Checks `is_url_private_or_parser_confused(url)` unless env override; calls `session.request(... url=url, headers=request_headers, proxies=proxies, ...)`; checks redirect URL before following. |
| Browser fetch backend | `changedetectionio/content_fetchers/playwright.py` / `browser_steps.py` | 300 / 134 | Stored watch URL | needs static check | Passes URL to `steppable_browser_interface(start_url=url)` then `page.goto(value, ...)`; excerpt relies on earlier `validate_iana_url()` but does not show implementation. |
| `/notification/send-test/<watch_uuid>` `POST` | `changedetectionio/blueprint/ui/notification.py` | 12 | Form `notification_urls`, `window_url` | recon candidate | Reads `request.form.get('notification_urls','').strip().splitlines()` and builds `NotificationContextData` including `watch_url` from form `window_url`. |
| `/api/v1/notifications` `POST` | `changedetectionio/api/Notifications.py` | 21 | JSON `notification_urls` | recon candidate | Reads JSON `notification_urls`, calls `validate_notification_urls(notification_urls)`, strips and stores each URL. |
| Static/snapshot asset serving | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | 769, 794, 808, 451 | Watch UUID / static group path / fixed filenames | needs static check | Uses `send_from_directory()` with directories derived from `datastore_path`, `filename`, or `watch.data_dir`; final filenames shown appear fixed or variable names, but route/path constraints are not fully shown. |

---

## User-controlled sources

| Source | Entrypoint | Constraints visible in context |
|---|---|---|
| JSON `url` | `/api/v1/watch` `POST` | Requires `@auth.check_token`; checked by `is_safe_valid_url(url)`. |
| JSON `url` | `/api/v1/watch/<uuid>` `PUT` | Requires `@auth.check_token`; checked by `is_safe_valid_url(new_url.strip())`. |
| Form `url` | `/form/add/quickwatch` | `@login_optionally_required`; `quickWatchForm` uses `validateURL()` → `is_safe_valid_url`. |
| Stored watch URL / `self.watch.link` | Worker fetch path | Subject to initial validation and runtime checks; browser-backend private-host coverage needs static check. |
| Watch `fetch_backend` | Worker fetch path | Read from watch data via `self.watch.get('fetch_backend', 'system')`; mutability and allowed values not shown. |
| Request headers/body/proxies | Requests fetch backend | Used by `session.request(...)`; source and validation not shown in excerpts. |
| Form `notification_urls` | `/notification/send-test/<watch_uuid>` | Split from posted lines; downstream validation/sending path not fully shown. |
| JSON `notification_urls` | `/api/v1/notifications` | Calls `validate_notification_urls`; implementation not shown. |
| Form `window_url` | `/notification/send-test/<watch_uuid>` | Used as `watch_url` in `NotificationContextData`; validation not shown. |
| Static asset path component `filename` | Flask static/snapshot routes | Directory joins shown; route converters and source of `filename` not shown. |

---

## Sink families

| Family | Files | Notes |
|---|---|---|
| SSRF | `changedetectionio/content_fetchers/requests.py`, `changedetectionio/content_fetchers/playwright.py`, `changedetectionio/browser_steps/browser_steps.py`, `changedetectionio/notification/apprise_plugin/custom_handlers.py` | Network sinks include `session.request(...)`, `page.goto(...)`, and notification `requests.request(...)`. Requests backend has private-host/parser guard and redirect guard unless environment allows restricted addresses. Browser path depends on `validate_iana_url()` coverage not shown. Notification custom handler has a private-host/parser guard, but coverage across all Apprise schemes needs static check. |
| Path Traversal | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | `send_from_directory()` calls use directories derived from datastore/watch paths and final filenames such as screenshots, favicons, or `elements.deflate`. Needs route/source review for `filename`, `watch.data_dir`, and history/snapshot filename constraints. |
| Other | `changedetectionio/validate_url.py`, `changedetectionio/forms.py` | `jinja_render()` is invoked on URL-like user strings in URL validation and notification validation contexts. Needs static review of template rendering sandbox, context exposure, and intended template capabilities. |
| RCE | `changedetectionio/validate_url.py`, `changedetectionio/forms.py` | Only a needs-static-check angle from user-controlled template rendering is visible. No execution sink is shown in the provided excerpts. |
| SQLi | N/A | No SQL sink or query construction is present in the provided context. |

---

## Suspected paths for review

| Path ID | Source | Sink | Call chain | Classification | Why | Missing context |
|---|---|---|---|---|---|---|
| SSRF-1 | API JSON `url` from `CreateWatch.post` | Requests backend `session.request(url=url, ...)` | `api/Watch.py:CreateWatch.post` → `datastore.add_watch` → `worker.py:worker_handler` → `processors/base.py:call_browser` → `content_fetchers/requests.py` | recon candidate | User URL is validated and stored, then later fetched. Requests backend shows runtime private-host guard and redirect guard, so review should focus on bypasses, env overrides, and all fetch modes. | `datastore.add_watch`, full watch model, `validate_iana_url()`, fetcher selection, environment defaults. |
| SSRF-2 | API JSON `url` from `Watch.put` | Requests or browser fetch backend | `api/Watch.py:Watch.put` → stored watch update → worker path → fetcher | recon candidate | Update path can modify stored URL after validation; same downstream network sinks apply. | Full `Watch.put` body, allowed update fields, queueing behavior, `validate_iana_url()`. |
| SSRF-3 | UI form `url` from quick watch | Requests or browser fetch backend | `views.py:form_quick_watch_add` → `forms.py:quickWatchForm` / `validateURL` → `datastore.add_watch` → worker path → fetcher | recon candidate | UI quick-add stores a validated user URL that later reaches network fetchers. Auth exposure is uncertain because decorator is `@login_optionally_required`. | Auth configuration behavior, `login_optionally_required`, full extras handling, fetch backend selection. |
| SSRF-4 | Stored watch URL | Playwright `page.goto(value, ...)` | `worker.py` → `processors/base.py:call_browser` → `content_fetchers/playwright.py` → `browser_steps.py:action_goto_url` | needs static check | Browser backend navigates directly to `value=url`; excerpt does not show whether private-host/parser checks are equivalent to requests backend for all browser backends. | `difference_detection_processor.validate_iana_url()`, browser fetcher subclasses, redirect/navigation interception behavior. |
| SSRF-5 | JSON/API or form `notification_urls` | Notification custom handler `requests.request(method=method, url=url, ...)` | `api/Notifications.py` or `notification.py` → validation/send path → `custom_handlers.py` | recon candidate | Notification URLs are user supplied and may dispatch HTTP requests. Custom handler has a private-host/parser guard, but Apprise scheme coverage and validation path are not fully shown. | `validate_notification_urls`, notification send function, Apprise plugin registration, all HTTP-capable schemes. |
| SSRF-6 | Form `window_url` in notification test | Notification template context / possible rendered notification URL | `notification.py:ajax_callback_send_notification_test` → `NotificationContextData` → notification rendering/sending | needs static check | `window_url` enters notification context as `watch_url`; if notification URL templates can include this value, it may influence downstream HTTP targets depending on rendering rules. | Notification rendering code, template variables allowed in notification URL, validation after rendering. |
| SSRF-7 | User-controlled proxy selection or custom browser endpoint | Network fetch behavior | Watch edit/API update → watch settings → fetcher construction | needs static check | Routing notes mention proxy and processor config updates; requests sink accepts `proxies=proxies`. Source allowlist and destination constraints are not shown. | Full update/edit handlers, proxy config model, fetcher constructor, browser endpoint config. |
| PT-1 | Static route path component `filename` | `send_from_directory(os.path.join(datastore_path, filename), screenshot_filename)` | Flask static/snapshot route → `flask_app.py:769` | needs static check | Directory is built from `datastore_path` plus `filename`; final file argument appears constrained by variable name, but source/route converter for `filename` is not shown. | Route definitions around lines 769/794/808, converters, auth checks, UUID/path validation. |
| PT-2 | Watch data directory / favicon filename | `send_from_directory(watch.data_dir, favicon_filename)` | Flask/API watch asset route → `flask_app.py:794` / `api/Watch.py:451` | needs static check | Serving from `watch.data_dir` may be safe if data directory is derived only from a validated watch UUID and filename is fixed/allowlisted. Need source check. | `watch.data_dir` construction, `favicon_filename` source, route permissions. |
| PT-3 | Static group directory | `send_from_directory(watch_directory, "elements.deflate")` | Flask static route → `flask_app.py:808` | needs static check | Final filename is fixed, but `watch_directory` includes `filename`; review path anchoring and route constraints. | Route definition, `filename` converter, datastore path normalization. |
| OTHER-1 | User URL containing `{{` or `{%` | `jinja_render(test_url)` | `validate_url.py:is_safe_valid_url` | needs static check | URL validation renders user-provided strings containing Jinja delimiters before final validation. Need review whether rendering is sandboxed and what context/functions are exposed. | `jinja_render` implementation, template environment configuration, context variables, exception behavior. |
| OTHER-2 | Notification server URL templates | `jinja_render(template_str=server_url.strip(), **generic_notification_context_data)` | `forms.py:ValidateAppRiseServers` | needs static check | Notification URL validation renders user-provided notification server strings. Need review rendering context and whether output is revalidated before network use. | `jinja_render`, `generic_notification_context_data`, notification send path, validation-after-rendering behavior. |
| SQLI-1 | N/A | N/A | N/A | likely irrelevant | No SQL query construction or database sink appears in the selected excerpts. | Full datastore implementation only if SQL-backed paths exist outside selected context. |

---

## Semgrep blind spots to consider

| Pattern | Reason Semgrep may miss it | Files to review |
|---|---|---|
| Stored SSRF through worker queue | Source and sink are separated by datastore persistence and async worker dispatch. | `changedetectionio/api/Watch.py`, `changedetectionio/blueprint/ui/views.py`, `changedetectionio/worker.py`, `changedetectionio/processors/base.py`, `changedetectionio/content_fetchers/*` |
| Browser-backed SSRF | Sink is `page.goto()` rather than `requests.get/post`, and guard is in a separate processor method. | `changedetectionio/processors/base.py`, `changedetectionio/content_fetchers/playwright.py`, `changedetectionio/browser_steps/browser_steps.py` |
| Notification dispatch SSRF | Apprise scheme dispatch and custom handler indirection may hide HTTP sinks from simple route-to-requests rules. | `changedetectionio/api/Notifications.py`, `changedetectionio/blueprint/ui/notification.py`, `changedetectionio/notification/apprise_plugin/custom_handlers.py` |
| Template rendering of user-controlled URL strings | Security relevance depends on Jinja environment and context, not a direct network/file sink. | `changedetectionio/validate_url.py`, `changedetectionio/forms.py`, Jinja helper implementation |
| Path traversal through directory component | `send_from_directory()` can look safe if the filename argument is fixed, while the directory argument may include route-derived data. | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` |
| Configuration-gated security checks | Environment flags such as `ALLOW_IANA_RESTRICTED_ADDRESSES` and `ALLOW_FILE_URI` change behavior and may not be modeled. | `changedetectionio/validate_url.py`, `changedetectionio/content_fetchers/requests.py`, `changedetectionio/processors/base.py`, notification handlers |

---

## Required static checks before verifier work

1. Review `difference_detection_processor.validate_iana_url()` and all subclasses to determine whether private-host/parser-confusion checks run before every fetch backend, especially Playwright/Puppeteer/Selenium-style navigation.

2. Review fetcher selection logic from stored watch settings:
   - allowed `fetch_backend` values,
   - whether API/UI users can choose backend,
   - whether backend changes bypass any URL guard.

3. Review full `Watch.put`, `/edit/<uuid>`, and related form/API schemas:
   - fields accepted,
   - proxy selection,
   - request headers/body,
   - processor config,
   - browser steps,
   - custom endpoints.

4. Review redirect behavior for browser backends:
   - whether navigations to private/restricted hosts after initial page load are blocked,
   - whether meta refresh, JavaScript redirects, iframes, subresources, or browser steps can change destination.

5. Review `is_safe_valid_url()` edge cases:
   - normalization order,
   - punycode/IDNA handling,
   - percent-encoding normalization,
   - parser differential behavior,
   - `source:` prefix stripping,
   - `SAFE_PROTOCOL_REGEX` or equivalent configuration if present,
   - `ALLOW_FILE_URI`.

6. Review `extract_url_hostnames()` and `is_private_hostname()`:
   - IPv4/IPv6 forms,
   - decimal/octal/hex IPs,
   - IPv4-mapped IPv6,
   - DNS rebinding assumptions,
   - trailing dots,
   - embedded credentials,
   - multiple host parser cases.

7. Review requests backend redirect handling:
   - whether all redirect status codes are covered,
   - whether relative redirects are normalized safely,
   - whether redirect target is checked before any follow-up request,
   - maximum redirect behavior.

8. Review notification validation:
   - implementation of `validate_notification_urls`,
   - whether it renders templates,
   - whether rendered URLs are checked for private hosts,
   - whether stored notification URLs are revalidated at send time.

9. Review Apprise integration:
   - which schemes can produce HTTP requests,
   - whether all HTTP-capable schemes pass through `custom_handlers.py`,
   - whether non-HTTP schemes can access local files, command-like handlers, local sockets, or internal services.

10. Review notification test endpoint:
    - auth behavior of `@login_optionally_required`,
    - whether `notification_urls` are validated before sending,
    - whether `window_url` can affect rendered outbound notification targets.

11. Review `jinja_render()` implementation:
    - sandboxing,
    - available globals/filters/functions,
    - autoescape and undefined behavior,
    - whether user templates can access application objects,
    - whether rendered URL output is revalidated after rendering.

12. Review static asset routes around the `send_from_directory()` calls:
    - full route decorators and converters,
    - source of `filename`,
    - whether UUID-only constraints are enforced,
    - whether path separators or encoded separators can reach `os.path.join`,
    - auth/password checks.

13. Review `watch.data_dir` construction:
    - whether derived only from canonical datastore path plus validated UUID,
    - whether user-controlled fields can influence it,
    - symlink handling in watch directories.

14. Review file-serving filename variables:
    - `screenshot_filename`,
    - `favicon_filename`,
    - history/snapshot filenames,
    - whether they are fixed, allowlisted, or user influenced.

15. Review environment-driven behavior:
    - `ALLOW_IANA_RESTRICTED_ADDRESSES`,
    - `ALLOW_FILE_URI`,
    - simple-host allowance,
    - proxy-related settings,
    - deployment defaults.

---

## Verifier feasibility

| Status | Reason | Required setup |
|---|---|---|
| feasible, after static scoping | Network-related candidates could likely be exercised with an isolated local canary service, but verifier design depends on which routes are exposed, auth mode, worker behavior, and fetch backend configuration. | Local changedetection.io instance, worker queue enabled, API key or UI session as appropriate, isolated Docker/network namespace, local canary HTTP service, controlled DNS/hostnames if testing parser or rebinding-like cases, notification plugin setup if testing notification paths. |

---

## Confidence

**Medium** for identifying relevant recon paths from the provided excerpts.

**Lower** for exact exploitability or guard coverage because several key functions and route bodies are not included, especially `validate_iana_url()`, notification dispatch, edit/update schemas, and static route definitions.

