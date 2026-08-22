# Test status

Every query has one of these statuses:

| Status | Meaning |
|---|---|
| `untested` | Built on documented table and column names, not executed. |
| `syntax-ok` | Executed in an environment without relevant data: the query runs, no results. |
| `confirmed` | Executed against real data and the expected events came back. |

Goal before publication: every query at least `syntax-ok`, and the queries for
the measures with priority High at `confirmed`.

The repository contains **123 query blocks**. Each block carries machine-readable
metadata — see [QUERY-METADATA](https://github.com/zolderio/m365-bec-detections/blob/main/QUERY-METADATA.md).
Of those, **56 are marked `deployable`**: self-contained queries that make sense as a
scheduled analytics rule. The remaining 67 are advanced hunting queries, standalone
filter fragments or one-off inventories, and do not belong in a tenant as a rule.

| Technique | Sentinel query | XDR query | Tested against | Date |
|---|---|---|---|---|
| T1059 | untested | untested | — | — |
| T1068 | untested | untested | — | — |
| T1078 | untested | untested | — | — |
| T1078.004 | untested | untested | — | — |
| T1098.001 | untested | untested | — | — |
| T1110.003 | untested | untested | — | — |
| T1114.002 | untested | untested | — | — |
| T1114.003 | untested | untested | — | — |
| T1204 | untested | untested | — | — |
| T1530 | untested | untested | — | — |
| T1534 | untested | untested | — | — |
| T1537 | untested | untested | — | — |
| T1538 | untested | untested | — | — |
| T1539 | untested | untested | — | — |
| T1556.006 | untested | untested | — | — |
| T1557 | untested | untested | — | — |
| T1562.001 | untested | untested | — | — |
| T1564.008 | untested | untested | — | — |
| T1566.002 | untested | untested | — | — |
| T1566.003 | untested | untested | — | — |
| T1567 | untested | untested | — | — |
| T1598 | untested | untested | — | — |
| T1621 | untested | untested | — | — |
| T1656 | untested | untested | — | — |
| T1657 | untested | untested | — | — |
| T1671 | untested | untested | — | — |
| T1672 | untested | untested | — | — |
