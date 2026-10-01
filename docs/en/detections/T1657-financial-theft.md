# T1657 — Financial Theft

| | |
|---|---|
| **MITRE tactic** | Impact |
| **Advisory measure** | 019 — Administrative verification of payments (priority High) |
| **Related technique** | [T1656](T1656-impersonation.md) — the means; this file is about the outcome |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE` — with an honest caveat
>
> **There is no query that detects a fraudulent payment.** The act takes place in
> the banking package or the ERP system, not in Microsoft 365; the tenant's audit
> logs at best hold the message that asked for it. The only real technical safety
> net Microsoft provides is the BEC scenario of Defender XDR **attack
> disruption**, which automatically interrupts an attack launched from a
> compromised account — enable it if you have the licence. Because that requires
> an E5-class subscription *and* only fires once an account is compromised, it
> needs its own rule alongside it that brings the disruption incidents to the
> place where someone is looking and that makes the run-up visible.
>
> Measure 019 is and remains **procedural**: four eyes, telephone verification of
> bank changes via a known number, no exceptions for the executive team. The
> advisory says so itself: this is *"the last 'guardrail'"*. Do not build a
> detection here that gives the feeling of coverage, because that coverage does
> not exist.

## Is there a Defender alert for this?

**No alert policy. One XDR mechanism.**

None of the four sections of default alert policies (Information governance,
Mail flow, Permissions, Threat management) contains a policy about payments,
invoice fraud or financial theft. That is not an omission: Microsoft 365 does
not see the payment.

What does exist:

| | |
|---|---|
| **Mechanism** | Microsoft Defender XDR — **automatic attack disruption**, BEC fraud scenario |
| **What it is** | Not an alert policy but an incident-level capability that correlates signals from endpoint, identity, email and SaaS apps and interrupts the attack automatically. As an example of an incident title via the API, Microsoft literally states: *"BEC financial fraud attack launched from a compromised account (attack disruption)"*. |
| **Default severity** | Not publicly documented per scenario. In the portal, incidents get the *Attack Disruption* tag and a yellow banner. |
| **Confidence threshold** | Microsoft: *"For containment actions, Defender maintains a confidence level of 99% or higher based on real production data."* |
| **Response actions** | Among others *Disable user* (Defender for Identity), *Contain user* and *Contain device* (Defender for Endpoint), *Revoke user session* and *Suspend user in Entra* (Microsoft Entra ID). All actions can be reversed by the security team. |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption |

### Licensing requirements for attack disruption — exact

Microsoft requires one of the following subscriptions:

- Microsoft 365 E5 or A5
- Microsoft 365 E3 with the **Microsoft Defender Suite** add-on
- Microsoft 365 E3 with the **Enterprise Mobility + Security E5** add-on
- Microsoft 365 A3 with the Microsoft 365 A5 Security add-on
- Windows 10 Enterprise E5/A5 or Windows 11 Enterprise E5/A5
- Enterprise Mobility + Security (EMS) E5 or A5
- Office 365 E5 or A5
- Microsoft Defender for Endpoint (Plan 2)
- Microsoft Defender for Identity
- Microsoft Defender for Cloud Apps
- Defender for Office 365 (Plan 2)
- Microsoft Defender for Business

**More important than the licence is the deployment.** Microsoft: *"if a
Microsoft Defender for Cloud Apps signal is used in a certain detection, then
this product is required to detect the relevant specific attack scenario."* For
the BEC scenario that means three concrete preconditions:

1. **Defender for Cloud Apps** with a correctly configured Microsoft 365
   connector. Microsoft is unusually emphatic about this: *"all checkboxes must
   be selected, including the option to enable Microsoft Entra ID apps"*,
   otherwise partial functionality or the failure of disruption flows follows.
2. **Mailboxes in Exchange Online** (not on-premises).
3. **Mailbox audit logging** with at least these events:
   `MailItemsAccessed`, `UpdateInboxRules`, `MoveToDeletedItems`, `SoftDelete`,
   `HardDelete`.

Point 3 is the direct link to [T1114.002](T1114.002-remote-email-collection.md)
and measure 012: without those audit events even the most expensive safety net
does not work.

Source: https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Defender XDR advanced hunting | `AlertInfo` / `AlertEvidence` | Alerts from Defender for Endpoint, Office 365, Cloud Apps, Identity and connected Sentinel workspaces. Join on `AlertId`. |
| Microsoft Sentinel | `SecurityAlert` | Data connector **Microsoft Defender XDR**. Contains `AlertName`, `AlertSeverity`, `ProviderName`, `Tactics`, `Techniques`, `Entities`. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**. For the run-up in the mailbox. Requires measure 012 (UAL on). |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365. For outbound mail from the compromised account. |

## KQL — Sentinel (SecurityAlert): surface the disruption incident

<!-- query
platform: sentinel
name: Attack disruption and BEC-related alerts from the Defender stack
technique: T1657
severity: High
tactics: [Impact]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
// Attack disruption incidents and related alerts from the Defender stack.
// Via the API, Microsoft adds the string "(attack disruption)" to the title
// of incidents that have been interrupted automatically. Do not filter on that
// alone: the individual alerts within such an incident do not carry that string.
let lookback = 1d;
SecurityAlert
| where TimeGenerated > ago(lookback)
| where AlertName has_any ("attack disruption", "business email", "BEC",
                           "compromised account", "financial fraud")
       or Techniques has_any ("T1657", "T1656")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName,
          Description, CompromisedEntity, Tactics, Techniques, Entities,
          Status, IsIncident, AlertLink
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (AlertInfo / AlertEvidence)

<!-- query
platform: defender-xdr
name: Financial fraud and impersonation alerts with the accounts involved
technique: T1657
severity: High
tactics: [Impact]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->

```kql
// Alerts tied to financial theft or impersonation, with the accounts
// involved. Titles are deliberately not hard-coded: Microsoft publishes
// no complete list of alert titles per disruption scenario.
let lookback = 30d;
AlertInfo
| where Timestamp > ago(lookback)
| where AttackTechniques has_any ("T1657", "T1656")
       or Title has_any ("business email", "BEC", "financial fraud", "attack disruption")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType =~ "User"
    | summarize Accounts = make_set(AccountUpn, 20) by AlertId
) on AlertId
| project Timestamp, AlertId, Title, Category, Severity, ServiceSource,
          DetectionSource, AttackTechniques, Accounts
| order by Timestamp desc
```

## KQL — the run-up: what you can see

This does not detect the theft. It detects the combination that precedes it in
almost every BEC case file: an account that both manipulates the inbox and
starts mailing outwards. Treat this as hunting, not as an alert.

<!-- query
platform: sentinel
name: Account that changed an inbox rule and sent mail or granted mailbox permissions within 24 hours
technique: T1657
severity: Medium
tactics: [Impact]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->

```kql
// Sentinel - accounts that within 24 hours both created or modified an
// inbox rule and sent mail or granted mailbox permissions.
let lookback = 7d;
let rules = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    | project RuleTime = TimeGenerated, UserId, RuleIP = ClientIP, Parameters;
let sends = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("Send", "SendAs", "SendOnBehalf",
                           "Add-MailboxPermission", "Add-RecipientPermission")
    | project ActionTime = TimeGenerated, UserId, Operation, ActionIP = ClientIP;
rules
| join kind=inner sends on UserId
| where ActionTime between (RuleTime - 24h .. RuleTime + 24h)
| summarize Actions = make_set(Operation, 10), Count = count(),
            IPs = make_set(ActionIP, 5), Rule = any(Parameters)
        by UserId, bin(RuleTime, 1d)
| order by Count desc
```

<!-- query
platform: defender-xdr
name: Payment-related outbound mail from an account with an open alert
technique: T1657
severity: Medium
tactics: [Impact]
interval: PT1H
lookback: P7D
parameters: []
deployable: false
-->

```kql
// Defender XDR - outbound mail with payment-related subjects from an
// account that has an open alert in the same period.
let lookback = 7d;
let suspiciousAccounts = AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType =~ "User"
    | where isnotempty(AccountUpn)
    | distinct AccountUpn;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection in ("Outbound", "Intra-org")
| where SenderFromAddress in~ (suspiciousAccounts)
| where Subject has_any ("factuur", "invoice", "betaling", "payment", "iban",
                         "rekeningnummer", "bank details", "remittance",
                         "spoedbetaling", "urgent payment")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
          RecipientDomain, DeliveryAction, ThreatTypes, NetworkMessageId
| order by Timestamp desc
```

## What you should not build here

Three things that look attractive and that in practice cost effort without
return:

- **A regex on IBAN numbers in mail subjects or content.** The content of
  messages is not in `EmailEvents`, and a DLP rule on IBAN produces almost
  exclusively legitimate hits in a finance department.
- **A threshold on "urgency" words.** An unworkably low signal-to-noise ratio,
  and trivially avoided by the attacker who takes over the existing thread.
- **An alert on the payment itself.** That lives in the banking package or ERP
  system. If you want detection on it, it belongs there and not in the M365
  tenant.

## Why this matters for BEC

This *is* BEC — the rest of the kill chain exists to get here. The
NCSC/Cyclotron advisory frames it as the last guardrail: *"Even if an attacker
presents a technically perfect forged invoice through impersonation (T1656), a
procedural check can stop the transaction at the last moment."* The measures the
advisory lists are accordingly all non-technical: four eyes on every payment,
telephone validation of bank changes and urgent payments via a known and trusted
number, a protocol to which not even the executive team is an exception, and
encouraging the second approver to ask questions.

The scale at which this goes wrong, from the FBI IC3 Annual Report 2025:

| Year | BEC reports | Reported losses |
|---|---|---|
| 2025 | 24,768 | $3,046,598,558 |
| 2024 | 21,442 | $2,770,151,146 |
| 2023 | 21,489 | $2,946,830,270 |

The FBI explicitly defines BEC as *"a scam targeting businesses or individuals
working with suppliers and/or businesses regularly performing wire transfer
payments"* — the audience of measure 019, not of a SIEM rule.

## References

- Microsoft, automatic attack disruption (incl. the BEC incident title): https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption
- Microsoft, configuring attack disruption (licences, required mailbox audit events, MDCA connector): https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, AlertEvidence schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table
- Microsoft, EmailEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, SecurityAlert schema (Sentinel): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert
- Microsoft, OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- FBI IC3 Annual Report 2025: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- MITRE ATT&CK T1657: https://attack.mitre.org/techniques/T1657/
