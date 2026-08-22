# T1534 — Internal Spearphishing

| | |
|---|---|
| **MITRE tactic** | Lateral Movement |
| **Advisory phase** | 10. Lateral Movement |
| **Advisory measure** | 015 — Internal and outbound phishing detection (priority Medium, impact High, effort Medium) |
| **Related techniques** | [T1537](T1537-transfer-data-to-cloud-account.md) and [T1566.003](T1566.003-spearphishing-via-service.md) — same measure |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE`
>
> Three default alert policies cover the *outbound* side well and are included
> in E1/E3 without an add-on: `User restricted from sending email` (High),
> `Suspicious email sending patterns detected` (Medium) and `Email sending limit
> exceeded` (Medium). In the documentation on outbound spam policies, Microsoft
> explicitly recommends using these alert policies instead of the notification
> fields in the policy itself. So switch them on — but they fire on volume and
> on reputation signals, not on content, and **intra-org mail is not outbound
> mail**. A targeted message from a compromised account to three colleagues in
> accounts payable therefore stays below them. Add the intra-org rule below for
> that reason.

## Is there a Defender alert for this?

**Partly.** Three policies, all three without an add-on licence:

| Alert policy | Default severity | Licensing | What it is |
|---|---|---|---|
| `User restricted from sending email` | **High** | Microsoft Business Basic/Standard/Premium, E1/F1/G1, E3/F3/G3 or E5/G5 | Fires when someone has been blocked from sending mail. Microsoft: *"This alert typically indicates a compromised account."* Automated investigation: yes. |
| `Suspicious email sending patterns detected` | **Medium** | E1/F1/G1, E3/F3/G3 or E5/G5 | Early signal: suspicious sending behaviour that does not quite lead to a block yet. Automated investigation: yes. |
| `Email sending limit exceeded` | **Medium** | E1/F1/G1, E3/F3/G3 or E5/G5 | More mail sent than the outbound spam policy allows. |

Two adjacent policies at tenant level, both **High** and both in E1/E3:
`Suspicious tenant sending patterns observed` and `Tenant restricted from sending
email`. Those only fire once the whole tenant is in trouble — too late for
detection, useful as an escalation signal.

Microsoft, in the documentation on outbound spam policies:

> *"The default alert policies named **Email sending limit exceeded**,
> **Suspicious email sending patterns detected**, and **User restricted from
> sending email** already send email notifications to members of the
> **TenantAdmins** group (**Global Administrator** members) about unusual
> outbound email activity and blocked users due to outbound spam. […] We
> recommend that you use these alert policies instead of the notification
> options in outbound spam policies."*

That ties in directly with measure 011 from the advisory: those notifications go
only to Global Administrators by default. Forward them to the distribution group
or shared mailbox that the advisory prescribes.

**What the alerts do not cover.** All five concern mail that leaves the
organisation, or the reputation of the tenant. `EmailDirection` = `Intra-org`
falls outside that. And that is exactly the core of T1534: the advisory calls it
*"sending phishing emails from a compromised account to colleagues."*

## A precondition that is often forgotten: Safe Links is off internally

Safe Links is not automatically applied to internal mail. That is a separate
switch in the Safe Links policy:

> **Apply Safe Links to email messages sent within the organization**: *"Select
> this option to apply the Safe Links policy to messages between internal
> senders and internal recipients. Turning on this setting enables link wrapping
> for all intra-organization messages."*

In PowerShell: `New-SafeLinksPolicy … -EnableForInternalSenders $true` (or
`Set-SafeLinksPolicy`). If that is off, there is no `UrlClickEvents` record for
an internal phishing link and you lose half of the detection in this file.
Microsoft delivers Safe Links through Defender for Office 365; there is no
default Safe Links policy, but the **Built-in protection** preset gives all
recipients Safe Links protection.

Source: https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure

For completeness: ZAP does work on all cloud mailboxes without a separate
licence (*"There are no special licensing requirements for ZAP for malware, spam,
and phishing"*), but ZAP is remediation after the fact, not detection, and
Microsoft notes alongside it: *"ZAP isn't logged in the Exchange mailbox audit
logs as a system action."*

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` | Data connector **Microsoft Defender XDR**, with the Defender for Office 365 tables enabled. |
| Defender XDR advanced hunting | `EmailEvents`, `UrlClickEvents`, `AlertInfo`/`AlertEvidence` | No connector. Microsoft: `EmailEvents` *"is populated by records from Defender for Office 365. If your organization hasn't deployed the service […] queries that use the table aren't going to work or return any results."* |

`EmailEvents` therefore requires **Defender for Office 365** (Plan 1 or Plan 2,
or the E5 bundle). With EOP alone there is no intra-org detection on content;
you are then left with the three alert policies above and with the inbox rules
from [T1564.008](T1564.008-email-hiding-rules.md).

## KQL — Sentinel / Defender XDR (EmailEvents): intra-org phishing verdict

This query runs unchanged in both environments; `EmailEvents` has the same
column names in Sentinel as in advanced hunting.

```kql
// Internal mail labelled as phishing or malware by the filter stack.
// EmailDirection "Intra-org" is the crux: this is mail from an own account to
// an own colleague, and therefore by definition a lateral movement signal.
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Intra-org"
| where isnotempty(ThreatTypes)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize Recipients = dcount(RecipientEmailAddress),
            RecipientList = make_set(RecipientEmailAddress, 25),
            Subjects = make_set(Subject, 10),
            Verdicts = make_set(ThreatTypes, 5),
            Detection = make_set(DetectionMethods, 5),
            Delivered = countif(DeliveryAction == "Delivered"),
            Blocked = countif(DeliveryAction in ("Blocked", "Junked", "Replaced")),
            First = min(Timestamp), Last = max(Timestamp)
    by SenderFromAddress, SenderObjectId
| order by Delivered desc, Recipients desc
```

A `Delivered` verdict with `ThreatTypes has "Phish"` and `EmailDirection ==
"Intra-org"` is an incident in virtually every organisation: the filter stack
recognised it *and* it still ended up in a colleague's inbox.

## KQL — intra-org burst without a verdict

The verdict query above misses the case that BEC is usually about: a
substantively ordinary message, no link, no attachment, just a request to change
a bank account number. There is no filter verdict for that. What you can see is
the pattern: a single internal sender who, in a short period, sends the same
subject to an unusually large number of internal recipients.

```kql
// Internal sender with an unusual fan-out on a single subject.
// Tune Ontvangers and the window to your own organisation; in a tenant with
// many distribution lists the threshold is higher.
let lookback = 7d;
let window = 1h;
let minRecipients = 8;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Intra-org"
| where DeliveryAction == "Delivered"
| where isempty(DistributionList)          // real fan-out, not a distribution list
| summarize Recipients = dcount(RecipientEmailAddress),
            RecipientList = make_set(RecipientEmailAddress, 30),
            Messages = dcount(NetworkMessageId),
            FirstContact = countif(IsFirstContact == 1),
            Urls = sum(UrlCount), Attachments = sum(AttachmentCount)
    by SenderFromAddress, Subject, bin(Timestamp, window)
| where Recipients >= minRecipients
| order by Recipients desc
```

Combine this with the other techniques in this cluster: a fan-out that coincides
with a fresh inbox rule from
[T1564.008](T1564.008-email-hiding-rules.md) or with a new sharing link from
[T1537](T1537-transfer-data-to-cloud-account.md) is a complete BEC story.

## KQL — Defender XDR: clicks on internal links

```kql
// Clicks by internal recipients on links from intra-org mail.
// Requires EnableForInternalSenders $true in the Safe Links policy; otherwise
// this table is empty for internal mail.
let lookback = 7d;
let internalEmail = EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Intra-org"
    | project NetworkMessageId, SenderFromAddress, Subject, RecipientEmailAddress;
UrlClickEvents
| where Timestamp > ago(lookback)
| where Workload == "Email"
| join kind=inner internalEmail on NetworkMessageId
| project Timestamp, AccountUpn, SenderFromAddress, Subject, Url, UrlChain,
          ActionType, IsClickedThrough, ThreatTypes, DetectionMethods, IPAddress
| order by Timestamp desc
```

`IsClickedThrough == 1` means the user dismissed the warning page and went ahead
anyway. With an internal sender that is almost always a successful lateral
movement step.

## KQL — picking up the alerts themselves in Sentinel

Do not just switch the three alert policies on but also ingest them, so that
they sit alongside your own rules in the same incident stream:

```kql
// Titles match the policy names from alert-policies literally.
// The ServiceSource value for these policies is not verified; filter on
// Title and then check for yourself which ServiceSource goes with it.
AlertInfo
| where Timestamp > ago(7d)
| where Title in ("User restricted from sending email",
                  "Suspicious email sending patterns detected",
                  "Email sending limit exceeded",
                  "Suspicious tenant sending patterns observed",
                  "Tenant restricted from sending email")
| project Timestamp, AlertId, Title, Severity, ServiceSource, DetectionSource, Category
| order by Timestamp desc
```

## Why this matters for BEC

The advisory phrases the risk precisely: *"Many default security settings are
aimed primarily at the perimeter, which means internal traffic is often
insufficiently monitored. In a BEC scenario this is a major risk; once an
attacker has access to a mailbox, they can use that compromised account to send
credible 'internal' phishing emails to colleagues in order to expand the attack
further (Lateral Movement). Because employees trust emails from their own
colleagues more readily, the chance of a successful follow-on breach is
considerably greater without this internal detection."*

In BEC the internal message is rarely the attack itself — it is the
authorisation. The message from "the director" to accounts payable does not need
to contain a link or an attachment to cause damage; it is enough that it comes
from the real mailbox of the real director. That is why the fan-out query above
matters more than the verdict query, and why this technique should be correlated
with the other signals in this cluster rather than alerted on in isolation.

Microsoft explicitly links both alert rules to account compromise: with
`User restricted from sending email` it says *"This alert typically indicates a
compromised account"*, and with `Suspicious email sending patterns detected` and
`Email sending limit exceeded` Microsoft refers to its own procedure
*Responding to a compromised email account*.

## References

- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, configure outbound spam policies (recommendation to use the alert policies): https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure
- Microsoft, configure Safe Links policies (`EnableForInternalSenders`): https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure
- Microsoft, zero-hour auto purge: https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge
- Microsoft, EmailEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, UrlClickEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- MITRE ATT&CK T1534: https://attack.mitre.org/techniques/T1534/
