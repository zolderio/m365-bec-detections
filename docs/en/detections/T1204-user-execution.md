# T1204 — User Execution

| | |
|---|---|
| **Name in the advisory** | User Execution |
| **Name in MITRE ATT&CK** | User Execution |
| **MITRE tactic** | Execution (TA0002) |
| **Advisory measure** | 008 — Blocking risky extensions (priority High) |
| **Related technique** | [T1059](T1059-execution-via-malicious-scripts.md) — the same measure, the endpoint side instead of the mail side |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> The two alert policies that genuinely cover the click on a malicious link
> (`A potentially malicious URL click was detected` and `A user clicked through
> to a potentially malicious URL`, both **High**) require E5/G5 or a
> Defender for Office 365 Plan 2 add-on. What is left in E1/E3 is
> `Email messages containing malicious file removed after delivery` at
> **Informational**, and that only fires *after* ZAP has removed the mail — too
> late and too quiet. And the scenario the advisory specifically warns about,
> the `.html` attachment, has no alert at all: `htm`, `html` and `js` are
> **not** in the default list of the common attachments filter. Raising the
> severity is no way out here, because the settings of a default alert policy
> cannot be changed (see below). If you do have MDO Plan 2, switch the two
> click alerts on as a supplement; the KQL remains necessary for attachments.

## Is there a Defender alert for this?

**For the click yes, for the attachment no — and the click alerts cost an
add-on.**

| Alert policy | Default severity | Licensing |
|---|---|---|
| `A potentially malicious URL click was detected` | **High** | E5/G5 or Defender for Office 365 Plan 2 add-on |
| `A user clicked through to a potentially malicious URL` | **High** | E5/G5 or Defender for Office 365 Plan 2 add-on |
| `Email messages containing malicious file removed after delivery` | **Informational** | E1/F1/G1, E3/F3/G3 or E5/G5 |
| `Email messages containing malicious URL removed after delivery` | **Informational** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 or Defender for Office 365 Plan 2 add-on |
| `Messages containing malicious entity not removed after delivery` | **Medium** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 or Defender for Office 365 Plan 2 add-on |
| `Email reported by user as malware or phish` | **Low** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 or Defender for Office 365 Plan 2 add-on |

### You cannot raise the severity of a default policy

This differs from what is often assumed. Microsoft on the default alert
policies: *"You can turn off these policies (or back on again), set up a list of
recipients to send email notifications to, and set a daily notification limit.
**The other settings for these policies can't be edited.**"* And on
`Set-ProtectionAlert`: *"You can't use this cmdlet to edit default alert
policies. You can only modify alerts that you created using the
New-ProtectionAlert cmdlet."*

If you want the same activity at a higher severity, use `New-ProtectionAlert`
to create your **own** alert policy with `-Severity High`. Note the licensing
boundary that comes with it: alert policies based on a threshold or on
"unusual activity" require E5/G5 or an add-on; with E1/F1/G1 and E3/F3/G3 you
can only create policies that fire *every* time the activity occurs. This route
is **not verified** against a tenant.

### The common attachments filter does not block .html and .js by default

The filter sits in the anti-malware policy and therefore in EOP — available in
every organisation with cloud mailboxes, no add-on required. But the default
list is:

> `ace, ani, apk, app, appx, arj, bat, cab, cmd, com, deb, dex, dll, docm, elf,
> exe, hta, img, iso, jar, jnlp, kext, lha, lib, library, lnk, lzh, macho, msc,
> msi, msix, msp, mst, pif, ppa, ppam, reg, rev, scf, scr, sct, sys, uif, vb,
> vbe, vbs, vxd, wsc, wsf, wsh, xll, xz, z`

`vbs` is in it, `htm`, `html`, `js` and `jse` are **not** — those are in the
list of additional types you have to enable yourself. That is exactly the
measure the advisory asks for, and it is a manual action. The filter does
perform *true type matching*: an `.exe` renamed to `.txt` is still recognised
as `exe`, and `html` is in the list of supported true types.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `EmailEvents`, `EmailAttachmentInfo` | Data connector **Microsoft Defender XDR** with advanced hunting event streaming enabled. Ingestion of these tables is billable traffic. |
| Defender XDR advanced hunting | `EmailEvents`, `EmailAttachmentInfo` | **Defender for Office 365** (Plan 1 at minimum). Microsoft: *"This advanced hunting table is populated by records from Defender for Office 365."* Retention 30 days. |

Consequence for an EOP-only organisation: there is then no email table in
advanced hunting and therefore no query route. What remains is the message trace
and quarantine report in the portal, and the logging of the transport rule
itself. `UrlClickEvents` (the click side) is not used in this detection because
that table requires Safe Links and therefore MDO.

## KQL — Defender XDR advanced hunting (EmailAttachmentInfo + EmailEvents)

<!-- query
platform: defender-xdr
name: Script or HTML attachment delivered to the inbox
technique: T1204
severity: Medium
tactics: [Execution]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->
```kql
// Attachments with a script or HTML extension that actually landed in a
// mailbox. The filter logic deliberately uses DeliveryLocation and not
// ThreatTypes: the whole reason the advisory has these extensions blocked is
// that the filter stack does not mark them as a threat.
let lookback = 7d;
let riskyExtensions = dynamic(["html","htm","shtml","xhtml","svg",
                               "js","jse","vbs","vbe","wsf","hta","chm","iso","img"]);
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where tolower(FileExtension) in (riskyExtensions)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    // Inbound only: an internally sent .html is usually a report.
    | where EmailDirection == "Inbound"
    // Delivered to the mailbox, so not quarantined or blocked.
    | where DeliveryAction == "Delivered"
    | where DeliveryLocation in ("Inbox/folder", "Inbox/Folder")
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              SenderFromDomain, SenderIPv4, AuthenticationDetails, DeliveryLocation,
              ThreatTypes, LatestDeliveryLocation
  ) on NetworkMessageId, RecipientEmailAddress
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderFromDomain,
          Subject, FileName, FileExtension, SHA256, ThreatTypes, ThreatTypes1,
          AuthenticationDetails, LatestDeliveryLocation
| order by Timestamp desc
```

The values of `DeliveryLocation` appear in the schema documentation as
*"Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted
items"*. The exact capitalisation in the data is **not verified**; that is why
both variants are in the query. Check with
`EmailEvents | distinct DeliveryLocation` what your tenant writes.

## KQL — Microsoft Sentinel (EmailAttachmentInfo + EmailEvents)

<!-- query
platform: sentinel
name: Script or HTML attachment delivered without a transport rule match
technique: T1204
severity: Medium
tactics: [Execution]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// The same detection in Sentinel. Difference with Defender XDR: the time
// column is called TimeGenerated. The column names FileExtension,
// NetworkMessageId, RecipientEmailAddress and DeliveryLocation are identical.
let lookback = 7d;
let riskyExtensions = dynamic(["html","htm","shtml","xhtml","svg",
                               "js","jse","vbs","vbe","wsf","hta","chm","iso","img"]);
EmailAttachmentInfo
| where TimeGenerated > ago(lookback)
| where tolower(FileExtension) in (riskyExtensions)
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(lookback)
    | where EmailDirection == "Inbound"
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              SenderFromDomain, SenderIPv4, AuthenticationDetails, DeliveryLocation,
              LatestDeliveryLocation, ExchangeTransportRule
  ) on NetworkMessageId, RecipientEmailAddress
// ExchangeTransportRule empty = the transport rule from measure 008 did not
// catch it. That is the check on the measure itself, not just on the threat.
| extend TransportRuleCaught = isnotempty(ExchangeTransportRule)
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, SenderFromDomain,
          Subject, FileName, FileExtension, SHA256, DeliveryLocation,
          TransportRuleCaught, ExchangeTransportRule, AuthenticationDetails
| order by TimeGenerated desc
```

## Narrowing: first contact and authentication failure

An `.html` attachment from a known supplier is usually an invoice report. The
same attachment from a sender you have never exchanged mail with is not.
`EmailEvents` has a column for that:

<!-- query
platform: defender-xdr
name: Risky attachment from a first-contact sender with failing authentication
technique: T1204
severity: Medium
tactics: [Execution, InitialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->
```kql
| where IsFirstContact == 1        // in Sentinel this is a bool: == true
| where AuthenticationDetails has_any ("fail", "softpass", "none")
```

## Why this matters for BEC

T1204 is the only technique in this cluster where the user performs the action
themselves; everything that follows is the attacker's work. Microsoft describes
the sequence in its own documentation on illicit consent grants: the attacker
*"tricks an end user into granting that application consent to access their data
either through a phishing attack, or by injecting illicit code into a trusted
website"*. The same click is also the start of an AiTM session: the user signs
in on a reverse proxy, and the session token leaves while MFA simply succeeds.
That is why this detection belongs, in substance, with [T1671](T1671-illicit-consent-grant.md)
and [T1556.006](T1556.006-mfa-modification.md): this is step one, and those two
are the persistence that follows directly after it.

## References

- Microsoft, alert policies (names, severity, licensing): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, `Set-ProtectionAlert` (default policies cannot be edited): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-protectionalert
- Microsoft, anti-malware protection and the common attachments filter: https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about
- Microsoft, EmailEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, EmailAttachmentInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table
- Microsoft, EmailAttachmentInfo in Azure Monitor (Sentinel columns): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailattachmentinfo
- Microsoft, Detect and remediate illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- MITRE ATT&CK T1204: https://attack.mitre.org/techniques/T1204/
