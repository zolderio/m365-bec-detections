# T1656 — Impersonation

| | |
|---|---|
| **MITRE tactic** | Impact |
| **Advisory measure** | 019 — Administrative verification of payments (priority High) |
| **Related technique** | [T1657](T1657-financial-theft.md) — the same moment, the other half: the payment itself |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE`
>
> Impersonation protection is part of Defender for Office 365 and you have to
> switch it on — in the default anti-phishing policy the impersonation settings
> are in fact **off**, even if you hold the licence. But the alerts around it are
> all **Informational** and only cover the case where an *override* let a
> phishing message through after all; the two policies that did cover
> impersonation have been removed by Microsoft. Enable the override alerts and
> raise their severity, and build your own rule alongside them on what Defender
> does write into `EmailEvents`: messages that were recognised as impersonation
> but ended up in the inbox anyway.
>
> Read this file with the right expectation. The measure for this technique is
> **procedural** — four eyes, telephone verification of bank changes. The
> detection below is an aid to see that an attempt is being made, not a
> replacement for that process.

## Is there a Defender alert for this?

**Partly, and weaker than you would think.** Two alert policies that dealt
specifically with impersonation have been **removed**. Microsoft, in a footnote
to the alert policy table: the current override policies are *"part of the
replacement functionality for the **Phish delivered due to tenant or user
override** and **User impersonation phish delivered to inbox/folder** alert
policies that were removed based on user feedback."*

What replaced them:

| Alert policy | Default severity | Licensing |
|---|---|---|
| `Phish delivered due to an ETR override` | **Informational** | E1/F1/G1, E3/F3/G3 or E5/G5 |
| `Phish delivered due to an IP allow policy` | **Informational** | E1/F1/G1, E3/F3/G3 or E5/G5 |
| `Phish not zapped because ZAP is disabled` | **Informational** | E5/G5 or Defender for Office 365 Plan 2 add-on |

Three limitations that together explain why this is not a detection:

1. **All three Informational.** Without being raised they disappear into a
   dashboard. Raising the severity is not demonstrably possible for a System
   policy; Microsoft's documentation contradicts itself on that point — see the README.
2. **They fire on the override, not on the impersonation.** An impersonation
   message that simply passes the filters because the impersonation settings
   are not configured produces none of these alerts.
3. **They are about *high confidence phish*.** A BEC message without a link and
   without an attachment — just text with a new account number — often does not
   earn that label.

Source: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

Useful additional alerts from the same table, and at a workable level:
`Suspicious email sending patterns detected` (**Medium**, E1/E3/E5) and
`User restricted from sending email` (**High**) — those fire when the
compromised account itself starts sending. And `Potential nation-state
activity` (**High**).

## What Defender does deliver: impersonation protection

| | |
|---|---|
| **Where** | Anti-phishing policies in Microsoft Defender for Office 365 |
| **Licensing** | **Defender for Office 365 (Plan 1 or Plan 2)**. Microsoft: *"The impersonation settings for user impersonation protection, domain impersonation protection, mailbox intelligence, impersonation safety tips, and trusted senders and domains are available only in anti-phishing policies in Defender for Office 365."* The basic anti-phishing for all cloud mailboxes (spoof intelligence, first contact safety tip, unauthenticated sender indicators) contains **no** impersonation protection. |
| **Important** | *"The default anti-phishing policy in Defender for Office 365 provides spoof protection and mailbox intelligence for all recipients. However, the other available impersonation protection features and phishing email thresholds aren't configured in the default policy."* In other words: holding the licence is not enough, you have to enter the users and domains explicitly. |
| **Limits** | A maximum of **350** protected users and **50** custom domains per policy. If *Enable intelligence for impersonation protection* is on, user and domain impersonation protection does **not** work if sender and recipient have mailed each other before — precisely the case with a hijacked supplier thread. |
| **Source** | https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about |

For an overview of what has been detected there is the **impersonation
insight** in the Defender portal.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Defender XDR advanced hunting | `EmailEvents` | Populated by **Defender for Office 365**. Without that service the queries return nothing. |
| Defender XDR advanced hunting | `AlertInfo` / `AlertEvidence` | Alerts from Defender for Endpoint, Office 365, Cloud Apps, Identity and connected Sentinel workspaces. Join on `AlertId`. |
| Microsoft Sentinel | `SecurityAlert` | Data connector **Microsoft Defender XDR**. This is where the alerts from the Defender stack land, with `AlertName`, `AlertSeverity`, `ProviderName`, `Tactics` and `Techniques`. |
| Microsoft Sentinel | `OfficeActivity` | For correlation with what happened in the mailbox *after* the message (measure 012, UAL on). |

## KQL — Defender XDR advanced hunting (EmailEvents)

The key is `EmailActionPolicy`. Microsoft documents values for it including
`Anti-phishing domain impersonation`, `Anti-phishing user impersonation`,
`Anti-phishing spoof` and `Anti-phishing graph impersonation`. Those are the only
places where "impersonation" as such appears in the telemetry.

<!-- query
platform: defender-xdr
name: Impersonation-flagged mail that was still delivered to the inbox or junk folder
technique: T1656
severity: Medium
tactics: [Impact]
interval: PT1H
lookback: P7D
parameters: []
deployable: false
-->

```kql
// Messages that were recognised by impersonation protection but were still
// delivered to an inbox or folder. That is the gap: detected but not
// blocked, usually because the action is set to 'Don't apply any action'
// (which is the default value in the policy).
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where EmailActionPolicy has_any ("impersonation", "Anti-phishing spoof")
| where DeliveryLocation in~ ("Inbox/folder", "Junk")
| project Timestamp, NetworkMessageId, InternetMessageId, Subject,
          SenderFromAddress, SenderDisplayName, SenderFromDomain,
          SenderMailFromDomain, RecipientEmailAddress,
          DeliveryAction, DeliveryLocation, LatestDeliveryLocation,
          ThreatTypes, DetectionMethods, EmailActionPolicy, EmailAction,
          AuthenticationDetails, IsFirstContact, ExchangeTransportRule
| order by Timestamp desc
```

<!-- query
platform: defender-xdr
name: First-contact external mail with a payment-related subject
technique: T1656
severity: Low
tactics: [Impact]
interval: PT1H
lookback: P7D
parameters: [ownDomains]
deployable: false
-->

```kql
// First contact from a domain that closely resembles one of your own or a
// supplier's domain, with a payment-related subject. Deliberately no threat
// verdict as a condition: the BEC message that matters most does not have one.
let lookback = 7d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where IsFirstContact == 1
| where Subject has_any ("factuur", "invoice", "betaling", "payment", "iban",
                         "rekeningnummer", "bank details", "spoed", "urgent",
                         "wijziging", "remittance")
| extend SenderDomain = tolower(SenderFromDomain)
| where not(SenderDomain in~ (ownDomains))
| project Timestamp, Subject, SenderFromAddress, SenderDisplayName, SenderDomain,
          SenderMailFromDomain, RecipientEmailAddress, AuthenticationDetails,
          DeliveryLocation, ThreatTypes, DetectionMethods, ReportId
| order by Timestamp desc
```

> This query filters on first contact and subject, not on similarity of the
> domain. A reliable look-alike comparison (Levenshtein) is not available in
> KQL; Defender's domain impersonation protection is intended for that, with an
> explicit list of at most 50 protected domains. Expect noise and deploy it as a
> hunting query, not as an analytic rule.

<!-- query
platform: defender-xdr
name: External sender using the display name of an internal employee
technique: T1656
severity: Medium
tactics: [Impact]
interval: PT1H
lookback: P7D
parameters: []
deployable: false
-->

```kql
// The sender side: display name impersonation where the displayed name
// matches one of your own employees but the address is external.
let lookback = 7d;
let internalNames = EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Intra-org"
    | where isnotempty(SenderDisplayName)
    | distinct SenderDisplayName;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where SenderDisplayName in (internalNames)
| project Timestamp, Subject, SenderDisplayName, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, DeliveryLocation, AuthenticationDetails,
          EmailActionPolicy, IsFirstContact
| order by Timestamp desc
```

## KQL — Defender XDR advanced hunting (AlertInfo / AlertEvidence)

<!-- query
platform: defender-xdr
name: Defender alerts related to impersonation and business email compromise
technique: T1656
severity: Medium
tactics: [Impact]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->

```kql
// All alerts from the Defender stack tied to T1656 or to phishing/BEC,
// with the entities involved. Titles and severities come from the
// product data and are deliberately not hard-coded here.
let lookback = 30d;
AlertInfo
| where Timestamp > ago(lookback)
| where AttackTechniques has_any ("T1656", "T1534", "T1114")
       or Category in~ ("InitialAccess", "CredentialAccess")
       or Title has_any ("impersonat", "phish", "business email", "BEC")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Entities = make_set(strcat(EntityType, ":", coalesce(AccountUpn, RemoteUrl, FileName, "")), 20) by AlertId
) on AlertId
| project Timestamp, AlertId, Title, Category, Severity, ServiceSource,
          DetectionSource, AttackTechniques, Entities
| order by Timestamp desc
```

## KQL — Sentinel (SecurityAlert)

<!-- query
platform: sentinel
name: Defender impersonation and override alerts raised to a workable severity
technique: T1656
severity: Medium
tactics: [Impact]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
// Make sure the Defender alerts arrive in Sentinel at a level where someone
// is looking. The alert policies around overrides are Informational; this rule
// lifts them out instead of letting them sink away.
let lookback = 7d;
SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProviderName has_any ("MDATP", "Office 365 Advanced Threat Protection",
                              "Microsoft Defender XDR", "OATP")
       or ProductName has_any ("Microsoft Defender", "Office 365")
| where AlertName has_any ("impersonat", "phish", "override", "business email")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName,
          Description, CompromisedEntity, Tactics, Techniques, Entities, AlertLink
| order by TimeGenerated desc
```

`ProviderName` and `ProductName` values differ per tenant and per connector
version. Run the query first without the `where` filter on `ProviderName` and
see what is in your workspace; the exact set of values is not publicly
documented.

## Why this matters for BEC

In BEC, impersonation is not a technique but the entire plot: the attacker has
to break nothing, only to resemble someone who is allowed to have money
transferred. The NCSC/Cyclotron advisory deliberately places this in the Impact
phase and adds that the defence shifts here: *"In the Impact phase, technical
barriers have often already been passed. The defence shifts here from technology
to strict administrative procedures."*

That is also the honest conclusion of this file. Microsoft's impersonation
protection works against look-alike domains and display names, but the hardest
BEC scenario of all escapes it: a genuine, compromised supplier mailbox that has
been corresponding with you for years. Microsoft documents that itself as an
explicit limitation — mailbox intelligence does not flag a sender as
impersonation *"if the sender and recipient previously communicated via email"*.
That very thread is the attack path in invoice fraud.

The scale: in 2025 the FBI received 24,768 BEC reports with $3,046,598,558 in
reported losses (IC3 Annual Report 2025).

## References

- Microsoft, alert policies (incl. the footnote about the removed impersonation policies): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, anti-phishing policies and impersonation protection: https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about
- Microsoft, EmailEvents schema (EmailActionPolicy values): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, SecurityAlert schema (Sentinel): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert
- FBI IC3 Annual Report 2025: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- MITRE ATT&CK T1656: https://attack.mitre.org/techniques/T1656/
