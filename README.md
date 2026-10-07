# BEC detections for Microsoft 365

**English** · [Nederlands](README.nl.md)

Detection logic for the 19 measures from **"Business E-mail Compromise (BEC) —
Technical advisory"** (NCSC, Cyclotron, April 2026). For every MITRE ATT&CK
technique in that advisory: does Microsoft provide a default alert for it, and
if not, which KQL and which data source do you need.

**Documentation site:** `docs/en/` (English) and `docs/nl/` (Nederlands).
Start with [the overview](docs/en/overzicht.md) — all 27 techniques in one
table, with the recommended detection per technique.

## Key finding

For **none** of the 27 techniques is a Defender alert sufficient on its own.
For nine there is a usable alert you should enable, but it leaves a gap that
matters in practice: it does not cover every way the technique is executed, or
it requires an E5 or add-on licence that SMEs — the audience of this advisory —
do not have. For the other eighteen there is nothing to rely on.

## Status of the queries

The queries have **not been run against a production tenant**. They are built
on table and column names from the Microsoft documentation and on published
hunting queries. See [the test status](docs/en/teststatus.md) per technique.
Do not adopt anything in production without running it yourself.

## Contributing

Welcome — and the most useful contribution is a test status from someone who
has actually run a query. See [CONTRIBUTING](docs/en/bijdragen.md).

## Building the site locally

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r requirements.txt
.venv-docs/bin/mkdocs serve
```

## Licence

[MIT](LICENSE). Free to use, modify and deploy commercially, provided the
copyright notice is retained.
