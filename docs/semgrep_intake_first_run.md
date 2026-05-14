# Semgrep Intake First Run

Target repo: `audit_targets/flask-admin`

Command path exercised:

- raw scan via `vulnhuntr.semgrep_intake._run_semgrep_command()`
- normalized intake via `python vulnhuntr/scripts/run_semgrep_intake.py audit_targets/flask-admin`

## Raw Semgrep Summary

- Total raw hits: `138`
- Unique rule ids: `6`
- Normalized `Candidate` count: `0`

## Sink Type Distribution

Current `SinkType` coverage is empty on this repo:

- `rce`: `0`
- `ssrf`: `0`
- `sqli`: `0`
- `path_traversal`: `0`

## Rule Distribution

Top rule ids from `p/security-audit` on `flask-admin`:

1. `generic.html-templates.security.var-in-href.var-in-href` - `48`
2. `generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var` - `35`
3. `python.flask.security.audit.debug-enabled.debug-enabled` - `21`
4. `python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY` - `17`
5. `python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe` - `14`
6. `generic.html-templates.security.var-in-script-tag.var-in-script-tag` - `3`

## Mapping Coverage

Current `SEMGREP_RULE_TO_SINK` coverage on this run:

- mapped raw hits: `0`
- unmapped raw hits: `138`
- coverage: `0.00%`

Interpretation:

- the intake framework is working end to end
- `p/security-audit` is producing real findings on this target
- none of the emitted rule ids belong to the current four-type server-side sink taxonomy
- wiring Semgrep intake into the main flow now would produce no `Candidate` objects for `flask-admin`

## Sample Raw Findings

These are representative raw findings from the first run. They are included because no normalized `Candidate` objects were emitted on this target.

### Sample 1

```text
path: doc/_templates/toc.html
line: 2
rule_id: generic.html-templates.security.var-in-href.var-in-href
message: template variable used in href and may enable XSS via javascript: URI
snippet:
{%- if display_toc %}
  <h3><a href='{{ pathto(master_doc) }}'>{{ _('Table Of Contents') }}</a></h3>
  {{ toc }}
{%- endif %}
```

### Sample 2

```text
path: examples/auth/main.py
line: 38
rule_id: python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY
message: hardcoded SECRET_KEY detected
snippet:
app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret'
app.config['DATABASE_FILE'] = 'db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE_FILE']
```

### Sample 3

```text
path: examples/auth/main.py
line: 193
rule_id: python.flask.security.audit.debug-enabled.debug-enabled
message: Flask app runs with debug enabled
snippet:
            build_sample_db()

    app.run(debug=True)
```

### Sample 4

```text
path: examples/auth/templates/security/_macros.html
line: 4
rule_id: python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe
message: Jinja template uses the safe filter and may disable autoescaping
snippet:
<div class='form-group'>
    {{ field.label }} {{ field(class_='form-control', **kwargs)|safe }}
    {% if field.errors %}
    <ul>
```

## Normalized Candidate Samples

Normalized output on this target is an empty list:

```text
[]
```

That is expected with the current mapping table because all six observed rule ids are outside the `rce` / `ssrf` / `sqli` / `path_traversal` scope.

## Known Follow-Up

1. Decide whether W1 should narrow Semgrep intake to server-side sink families instead of all of `p/security-audit`.
2. Decide whether the normalized taxonomy should expand beyond four sink types before integrating intake into the main agent flow.
3. Keep raw Semgrep results and normalized `Candidate` generation separate until mapping coverage is high enough to justify routing into deeper LLM analysis.
