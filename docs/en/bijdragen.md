# Contributing

Improvements are welcome, and there is one kind of contribution we can use most
of all: **someone who has run a query in a real tenant.**

## What we would like to receive

- **A test status.** If you have executed a query, report whether it ran and
  whether the expected events came back. Update the row in
  [test status](teststatus.md), with the date and what you tested against.
- **Corrections of facts.** An alert name that no longer exists, a severity
  Microsoft has changed, a table or column that has a different name. Add the
  source that shows it; we take nothing on board without a reference.
- **A better query.** Fewer false positives, or coverage of a way of carrying
  out the action that we are missing. Explain in the pull request which case the
  current query misses.
- **A missing technique.** The advisory counts 27 techniques; if anyone sees a
  BEC-relevant action that is not in it, we would like to hear about it.

## How to go about it

1. Open an issue or send a pull request directly.
2. Keep to the format of the existing files: metadata, recommendation with
   label, required data source, KQL per platform, why it matters for BEC,
   references.
3. Back it up with a source. If you cannot verify something, write "not publicly
   documented" instead of an assumption. That is not a weakness here but the
   starting point.
4. Never invent an alert name, severity, table name or column name.

## License of contributions

What you contribute falls under the same [MIT license](https://github.com/zolderio/m365-bec-detections/blob/main/LICENSE) as the rest of the
repo.
