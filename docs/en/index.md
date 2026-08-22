# Detection for the NCSC/Cyclotron BEC advisory

Working detection logic for the 19 measures from **"Business E-mail Compromise
(BEC) — Technical advisory"** (NCSC, Cyclotron, April 2026). For every MITRE
ATT&CK technique in that advisory, this repo states:

- whether Microsoft provides a **default alert** for it — with the exact policy
  name, the default severity and the licence level required;
- and if not (or if the alert is too low or too narrow): **KQL** for Microsoft
  Sentinel and for Defender XDR advanced hunting, with the table and the data
  connector that needs to be onboarded for it.

The advisory itself describes *which* measure you should take. This repo
describes how you see it going wrong.

## Why this is needed

For a considerable share of the techniques in the advisory there is no alert, or
only an alert at the lowest level. Two examples from Microsoft's own
documentation: creating a forwarding rule is `Informational`, and starting or
exporting an eDiscovery search across all mailboxes is too. See
[overview](overzicht.md).

## Which detection should you choose?

Every detection file opens with a **Recommendation** carrying one of these
labels. The rule of thumb: *if Defender covers the action completely without E5,
use Defender; if not, use your own Sentinel rule.*

| Label | When | What you do |
|---|---|---|
| `DEFENDER-ALERT` | There is a default alert policy, it covers the action completely, and it is included in E1/E3 without an add-on. | Enable the alert, raise the severity if needed, route it to where someone is looking. |
| `SENTINEL-RULE` | There is no alert, or the alert covers the action only partly, or it requires E5 / an add-on licence. | Your own analytic rule on the KQL in this file. |
| `DEFENDER-ALERT + SENTINEL-RULE` | The alert is useful as a safety net, but leaves a gap that matters in practice. | Both: alert on, KQL for the gap. |

Two things count towards "completely": does the alert cover *all* the ways the
action can be carried out (for instance from the desktop client as well), and is
the default severity such that someone actually looks at it. An `Informational`
alert that disappears into a dashboard is not a detection.

### Can you raise the severity of a built-in policy?

Microsoft's own documentation is contradictory on this, and that is relevant
enough to record here. On the same page it says:

> "On the Alert policies page, the names of these built-in policies are in bold
> and the policy type is defined as **System**. These policies are turned on by
> default. You can turn off these policies (or back on again), set up a list of
> recipients to send email notifications to, and set a daily notification limit.
> **The other settings for these policies can't be edited.**"

And further down, without distinguishing between System and custom policies, an
instruction *"Change the severity level for an alert policy"* that leads you via
**Edit** in the Defender portal to the severity dropdown menu.

In this repo, work from the first passage: assume that the severity of a
**System** policy cannot be changed, and therefore treat a severity that is too
low as a reason to build your own detection after all. The reliable route to a
severity of your own is a custom policy via `New-ProtectionAlert -Severity High`;
according to Microsoft, `Set-ProtectionAlert` does not work on default policies.
If you see this working differently in your own tenant, we would like to hear
about it and we will adjust.

Source: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

## What the inventory shows

For **not a single one** of the 27 techniques in the advisory is a Defender
alert sufficient on its own. For nine techniques there is a usable alert that
you should enable, but it leaves a gap that matters in practice: it does not
cover all the ways the action can be carried out, or it requires an E5 or add-on
licence that SMEs — the audience of this advisory — do not have. For the other
eighteen there is nothing to lean on. See [overview](overzicht.md).

## Structure

```
detections/<TECHNIQUE-ID>-<name>.md   one file per ATT&CK technique
overzicht.md                          all techniques in one table
teststatus.md                         test status per query
```

Every detection file has the same layout: metadata, "Is there a Defender alert
for this?", required data source, KQL per platform, why it matters for BEC,
references.

## Status of the queries

**The queries in this repo have not been executed against a production tenant.**
They are built on table and column names from the Microsoft documentation and on
published hunting queries. For each query, [test status](teststatus.md) states
whether it has been tested and against what. Do not take anything into
production without running it yourself.

## Accountability

Severities and policy names come from Microsoft Learn and are dated, because
Microsoft changes them: in June 2025, for example, several Defender for Cloud
Apps anomaly policies were turned off that still appear as coverage in many
detection inventories. Where a severity is not publicly documented, that is
stated as such — nothing is guessed.

## Contributing

Improvements are welcome, and the most useful of all is a test status from
someone who has run a query in a real tenant. See [contributing](bijdragen.md).

## License

[MIT](https://github.com/zolderio/m365-bec-detections/blob/main/LICENSE). Free to use, modify and deploy commercially,
provided the copyright notice is retained.
