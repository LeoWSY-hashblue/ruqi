# W3 changedetection.io Recon Context

## Target Metadata

- Target repo: `https://github.com/dgtlmoon/changedetection.io`
- Target path: `E:\tool\targets\changedetection.io`
- Target commit: `dd56a502c0b3d025a6a1d4e46942e9321b977bf8`
- Framework: Flask, Flask-RESTful, Flask blueprints
- Runtime notes: Service-oriented web app with worker queue and multiple fetch backends; Docker/runtime setup not exercised in this phase.
- Semgrep intake status: Run
- LLM: Not run
- Verifier: Not run
- Confirmed findings: 0

## Routing Map

| Entrypoint | Method / trigger | File | Handler | Auth / permissions | Notes |
| --- | --- | --- | --- | --- | --- |
| `/api/v1/watch` | POST | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | `CreateWatch.post` | `@auth.check_token` | Creates a watch from JSON `url`, stores extras, optional notification URLs. |
| `/api/v1/watch/<uuid>` | PUT | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | `Watch.put` | `@auth.check_token` | Updates watch URL, processor config, proxy, notifications. |
| `/form/add/quickwatch` | POST | `changedetectionio/blueprint/ui/views.py` | `form_quick_watch_add` | `@login_optionally_required` | UI quick-add path for a user-supplied watch URL. |
| `/edit/<uuid>` | GET/POST | `changedetectionio/blueprint/ui/edit.py` | `edit_page` | `@login_optionally_required` | UI edit path for watch settings; form class depends on processor. |
| `/notification/send-test[/<watch_uuid>]` | POST | `changedetectionio/blueprint/ui/notification.py` | `ajax_callback_send_notification_test` | `@login_optionally_required` | Sends a test notification using form-provided notification URLs. |
| `/api/v1/notifications` | GET/POST/PUT/DELETE | `changedetectionio/flask_app.py`, `changedetectionio/api/Notifications.py` | `Notifications` resource | `@auth.check_token` | API-level notification URL management. |
| Worker queue | Background fetch | `changedetectionio/worker.py`, `changedetectionio/processors/base.py` | `worker_handler`, `difference_detection_processor.call_browser` | Requires queued watch | Fetches stored watch URL through selected fetch backend. |
| Static/snapshot assets | GET | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | `send_from_directory` call sites | Password/auth checks vary | Serves screenshots, favicon, visual selector data from watch data directories. |

## Upload / URL / File / DB Input Surfaces

| Surface | Field / parameter | File | Validation | Storage / rewrite | Notes |
| --- | --- | --- | --- | --- | --- |
| URL fetch | JSON `url` | `changedetectionio/api/Watch.py` | `is_safe_valid_url(url)` | `datastore.add_watch(url=url, extras=extras)` | API create-watch path. |
| URL fetch | JSON `url` | `changedetectionio/api/Watch.py` | `is_safe_valid_url(new_url.strip())` | Watch update data | API update-watch path. |
| URL fetch | Form `url` | `changedetectionio/blueprint/ui/views.py`, `changedetectionio/forms.py` | `quickWatchForm` -> `validateURL` -> `is_safe_valid_url` | `datastore.add_watch(url=url, ...)` | UI quick-watch path. |
| Notification/webhook | `notification_urls` | `changedetectionio/api/Notifications.py`, `changedetectionio/blueprint/ui/notification.py` | `ValidateAppRiseServers`; runtime custom HTTP handler checks private hosts | Application settings or request-only test notification | SSRF-adjacent surface through Apprise/custom handlers. |
| Browser fetch | Stored watch URL | `changedetectionio/processors/base.py`, `changedetectionio/content_fetchers/playwright.py` | Calls `validate_iana_url`; requests fetcher also checks at fetch-time | URL passed to browser or requests backend | Browser-backed fetch may need separate SSRF/static review. |
| File serving | Watch UUID / static group path | `changedetectionio/flask_app.py`, `changedetectionio/api/Watch.py` | UUID converter/auth/password checks; `send_from_directory` | Watch data directory and fixed filenames | Path traversal review should focus on directory construction and filename constraints. |

## Semgrep Intake Summary

- Candidate count: 0
- RCE: 0
- SSRF: 0
- SQLi: 0
- Path Traversal: 0
- Note: Zero SSRF candidates may indicate Semgrep rule coverage gaps for this target's dataflow and custom SSRF guards, not proof that SSRF risk is absent.

| Candidate | File | Line | Sink type | Rule | Symbol | Initial note |
| --- | --- | ---: | --- | --- | --- | --- |
| None | N/A | N/A | N/A | N/A | N/A | Semgrep intake returned no candidates. |

## Selected Code Excerpts

### API Watch Creation And Update

```text
changedetectionio/flask_app.py:581
watch_api.add_resource(CreateWatch, '/api/v1/watch',
                       resource_class_kwargs={'datastore': datastore, 'update_q': update_q})

changedetectionio/flask_app.py:584
watch_api.add_resource(Watch, '/api/v1/watch/<uuid_str:uuid>',
                       resource_class_kwargs={'datastore': datastore, 'update_q': update_q})

changedetectionio/api/Watch.py:465
@auth.check_token
@validate_openapi_request('createWatch')
def post(self):
    json_data = strip_internal_api_fields(request.get_json())
    url = json_data['url'].strip()
    if not is_safe_valid_url(url):
        return "Invalid or unsupported URL", 400
    new_uuid = self.datastore.add_watch(url=url, extras=extras, tag=tags)

changedetectionio/api/Watch.py:172
if 'url' in request.json:
    new_url = request.json.get('url')
    if not is_safe_valid_url(new_url.strip()):
        return "Invalid or unsupported URL format. URL must use http://, https://, or ftp:// protocol", 400
```

### UI Watch Creation

```text
changedetectionio/blueprint/ui/views.py:11
@views_blueprint.route("/form/add/quickwatch", methods=['POST'])
@login_optionally_required
def form_quick_watch_add():
    form = forms.quickWatchForm(request.form)
    if not form.validate():
        ...
    url = request.form.get('url').strip()
    new_uuid = datastore.add_watch(url=url, tag=request.form.get('tags','').strip(), extras=extras)

changedetectionio/forms.py:774
class quickWatchForm(Form):
    url = StringField('URL', validators=[validateURL()])

changedetectionio/forms.py:580
def validate_url(test_url):
    from changedetectionio.validate_url import is_safe_valid_url
    if not is_safe_valid_url(test_url):
        raise ValidationError('Watch protocol is not permitted or invalid URL format')
```

### URL Validation And SSRF Guards

```text
changedetectionio/validate_url.py:168
def is_safe_valid_url(test_url):
    if test_url is None:
        return False
    if not isinstance(test_url, str):
        return False
    if not test_url.strip():
        return False
    allow_file_access = strtobool(os.getenv('ALLOW_FILE_URI', 'false'))
    safe_protocol_regex = '^(http|https|ftp|file):' if allow_file_access else '^(http|https|ftp):'
    test_url = re.compile('^source:', re.IGNORECASE).sub('', test_url)
    if '{%' in test_url or '{{' in test_url:
        test_url = jinja_render(test_url)
    if re.search(r'[<>]', test_url):
        return False
    if '\\' in test_url:
        return False
    test_url = normalize_url_encoding(test_url)
    if not pattern.match(test_url.strip()):
        return False
    if not test_url.strip().lower().startswith('file:') and not validators.url(test_url, simple_host=allow_simplehost):
        return False

changedetectionio/validate_url.py:112
def is_url_private_or_parser_confused(url):
    if '\\' in url:
        return True
    for hostname in extract_url_hostnames(url):
        if is_private_hostname(hostname):
            return True
    return False
```

### Requests Fetch Backend

```text
changedetectionio/content_fetchers/requests.py:86
allow_iana_restricted = strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false'))
if not allow_iana_restricted:
    if is_url_private_or_parser_confused(url):
        raise Exception(...)

changedetectionio/content_fetchers/requests.py:98
r = session.request(method=request_method,
                    data=request_body.encode('utf-8') if type(request_body) is str else request_body,
                    url=url,
                    headers=request_headers,
                    timeout=timeout,
                    proxies=proxies,
                    verify=False,
                    allow_redirects=False)

changedetectionio/content_fetchers/requests.py:115
if not allow_iana_restricted:
    if is_url_private_or_parser_confused(redirect_url):
        raise Exception(...)
```

### Worker To Fetcher Flow

```text
changedetectionio/worker.py:157
watch = datastore.data['watching'].get(uuid)
processor = watch.get('processor', 'text_json_diff')
processor_module = get_processor_module(processor)
update_handler = processor_module.perform_site_check(datastore=datastore, watch_uuid=uuid)
await update_handler.call_browser()

changedetectionio/processors/base.py:121
url = self.watch.link
if re.search(r'^file:', url.strip(), re.IGNORECASE):
    if not strtobool(os.getenv('ALLOW_FILE_URI', 'false')):
        raise Exception("file:// type access is denied for security reasons.")
await self.validate_iana_url()
prefer_fetch_backend = self.watch.get('fetch_backend', 'system')
self.fetcher = fetcher_obj(...)
```

### Browser Fetch Backend

```text
changedetectionio/content_fetchers/playwright.py:300
from changedetectionio.browser_steps.browser_steps import steppable_browser_interface
browsersteps_interface = steppable_browser_interface(start_url=url)
browsersteps_interface.page = self.page
response = await browsersteps_interface.action_goto_url(value=url)

changedetectionio/browser_steps/browser_steps.py:134
async def action_goto_url(self, selector=None, value=None):
    if not value:
        return None
    response = await self.page.goto(value, timeout=0, wait_until='load')
    return response
```

### Notification URL Surface

```text
changedetectionio/flask_app.py:603
watch_api.add_resource(Notifications, '/api/v1/notifications',
                       resource_class_kwargs={'datastore': datastore})

changedetectionio/api/Notifications.py:21
@auth.check_token
@validate_openapi_request('addNotifications')
def post(self):
    json_data = request.get_json()
    notification_urls = json_data.get("notification_urls", [])
    validate_notification_urls(notification_urls)
    for url in notification_urls:
        clean_url = url.strip()
        self.datastore.add_notification_url(clean_url)

changedetectionio/blueprint/ui/notification.py:12
@notification_blueprint.route("/notification/send-test/<string:watch_uuid>", methods=['POST'])
@login_optionally_required
def ajax_callback_send_notification_test(watch_uuid=None):
    notification_urls = request.form.get('notification_urls','').strip().splitlines()
    ...
    n_object = NotificationContextData({
        'watch_url': request.form.get('window_url', "https://changedetection.io"),
        'notification_urls': notification_urls
    })
```

### Notification Validation And Custom HTTP Handler

```text
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

changedetectionio/notification/apprise_plugin/custom_handlers.py:186
url: str = meta.get("url")
schema: str = meta.get("schema")
method: str = re.sub(r"s$", "", schema).upper()
parsed_url = apprise_parse_url(url)
url = re.sub(rf"^{schema}", "https" if schema.endswith("s") else "http", parsed_url.get("url"))
if not os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', '').lower() in ('true', '1', 'yes'):
    if is_url_private_or_parser_confused(url):
        raise ValueError(...)
response = requests.request(method=method, url=url, auth=auth, ...)
```

### Static And Watch File Serving

```text
changedetectionio/flask_app.py:769
response = make_response(send_from_directory(os.path.join(datastore_o.datastore_path, filename), screenshot_filename))

changedetectionio/flask_app.py:794
response = make_response(send_from_directory(watch.data_dir, favicon_filename))

changedetectionio/flask_app.py:808
watch_directory = str(os.path.join(datastore_o.datastore_path, filename))
if os.path.isfile(os.path.join(watch_directory, "elements.deflate")):
    response = make_response(send_from_directory(watch_directory, "elements.deflate"))

changedetectionio/api/Watch.py:451
response = make_response(send_from_directory(watch.data_dir, favicon_filename))
```

## Open Questions

- Which URL fetch entrypoints are active and exposed in the default deployment: API key-only, authenticated UI, or optionally unauthenticated UI?
- Does `difference_detection_processor.validate_iana_url()` apply the same private-host/parser-differential guard to all fetch backends, including Playwright/Puppeteer/Selenium, before browser navigation?
- Does any configured environment intentionally permit internal targets via `ALLOW_IANA_RESTRICTED_ADDRESSES=true`, `ALLOW_FILE_URI=true`, or a broadened `SAFE_PROTOCOL_REGEX`?
- Are notification URLs reachable by low-privileged users, and do all Apprise schemes that perform HTTP requests pass through the custom HTTP handler or an equivalent private-host guard?
- Can user-controlled `fetch_backend`, custom browser endpoint, proxy selection, request headers, request body, or browser steps change the target of a request after initial URL validation?
- Are `send_from_directory` paths always anchored by validated UUIDs/fixed filenames, and do any history/snapshot indexes permit user-controlled filenames?
- Does Semgrep miss SSRF because the network sink is inside custom fetcher/browser/notification dispatch code rather than direct route-to-requests dataflow?
- Is a dynamic SSRF verifier feasible with a local canary HTTP service and isolated Docker network without external services?

## Recon Constraints

- Do not write `confirmed`.
- Do not write a CVE-ready conclusion.
- Do not replace static triage or verifier work.
- Do not assume routes, parameters, or framework behavior that is absent from the provided context.
