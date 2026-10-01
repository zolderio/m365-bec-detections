# T1598 — Phishing for Information

| | |
|---|---|
| **MITRE tactic** | Reconnaissance |
| **Advisory measure** | 001 — Security awareness on OSINT (priority Medium) |
| **Related technique** | [T1566.002](T1566.002-spearphishing-link.md) — the same mail flow, but with a payload |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> Most of this technique happens outside your tenant: an attacker reading
> LinkedIn, the company website and commercial registers leaves no trace at all
> in Microsoft 365. What you can see is the second half — the message that asks
> for information. There is no alert policy for that, because every existing
> policy fires on a payload (URL, attachment, malware) and an information
> request has precisely no payload. So build your own rule on first-contact mail
> without a payload, and use the Forms alerts and the user report as separate
> safety nets.

## Is there a Defender alert for this?

**No, not for the action itself.** There is no alert policy that fires on the
gathering of open sources, nor one that fires on a payload-free information
request. Three policies touch on the technique indirectly.

| | |
|---|---|
| **Alert policy** | `Email reported by user as malware or phish` |
| **Default severity** | **Low** |
| **Licensing** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5, or Defender for Office 365 Plan 2 add-on |
| **Limitation** | Only fires once a user presses **Report** themselves. That is exactly the scenario in which the recon mail *was* spotted; the messages that are missed yield nothing. Severity **Low** means that in practice nobody looks at it, and raising it is not demonstrably possible for a System policy — see [severity of a built-in policy](../index.md#can-you-raise-the-severity-of-a-built-in-policy). |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

| | |
|---|---|
| **Alert policy** | `Form blocked due to potential phishing attempt` |
| **Default severity** | **High** |
| **Licensing** | E1, E3/F3, or E5 |
| **What it is** | Fires on a Microsoft Forms form created by your own organisation that shows suspicious behaviour. Relevant because a Forms form ("just fill in your details") is a common carrier for an information request. Covers Forms only, not email. |

A second Forms policy, `Form flagged and confirmed as phishing` (**High**,
E1, E3/F3, or E5), fires after Microsoft has confirmed a reported form as
phishing.

**What does not exist, and what you should therefore not expect:** there is no
alert policy in the *Threat management* category that fires on an inbound
message without a URL and without an attachment, however targeted the question
may be. The full list of default alert policies is in the Microsoft
documentation linked above; not one of them covers this action.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `EmailEvents` | Data connector **Microsoft Defender XDR**, under *Connect events* tick the Defender for Office 365 tables. Requires Defender for Office 365. |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365 rolled out in the Defender portal. **Advanced hunting itself is part of Defender for Office 365 Plan 2** — with Plan 1 only you get Real-time detections and no hunting tables. |

These queries do not depend on the Unified Audit Log (measure 012);
`EmailEvents` comes from the Defender for Office 365 filtering stack, not from
the UAL. If you only have EOP (no Defender for Office 365), the table does not
exist and message trace in the Defender portal is your only source — without
KQL.

## KQL — Sentinel and Defender XDR (EmailEvents)

The same table and the same column names in both platforms; the query does not
need to differ per platform. Only `Timestamp` is also called `TimeGenerated` in
Sentinel.

<!-- query
platform: sentinel
name: First-contact inbound mail with no attachment and no URL
technique: T1598
severity: Low
tactics: [Reconnaissance]
interval: P1D
lookback: P30D
parameters: [ownDomains]
deployable: false
-->

```kql
// First contact with an external sender, without a URL and without an attachment.
// That combination is unusual for ordinary business mail and typical of a
// reconnaissance question ("who handles payments at your company?", "can you
// confirm the bank account number?"). The filtering stack has given no verdict
// on it, so no Defender alert fires on this.
let lookback = 30d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where IsFirstContact == 1              // first time this sender mails this recipient
| where AttachmentCount == 0 and UrlCount == 0   // no payload = no alert trigger
| where DeliveryAction == "Delivered"    // only what the user actually saw
| where isempty(ThreatTypes)             // the stack made nothing of it; that is the heart of the problem
| where SenderFromDomain !in~ (ownDomains)
// Envelope and From domain diverging is an extra signal, not a filter:
| extend EnvelopeMismatch = tolower(SenderMailFromDomain) != tolower(SenderFromDomain)
| project Timestamp, SenderFromAddress, SenderFromDomain, SenderMailFromDomain,
          EnvelopeMismatch, RecipientEmailAddress, Subject, SenderIPv4, NetworkMessageId
| order by Timestamp desc
```

### Narrowing down to the people who really matter

In a normal tenant the query above returns too much. BEC reconnaissance targets
finance, executives and administrators; scope the rule to them.

<!-- query
platform: sentinel
name: First-contact inbound mail scoped to finance and executive mailboxes
technique: T1598
severity: Medium
tactics: [Reconnaissance]
interval: P1D
lookback: P30D
parameters: [targets]
deployable: false
-->

```kql
let targets = dynamic([
    "accountspayable@yourdomain.example", "finance@yourdomain.example",
    "management@yourdomain.example"                                  // <-- adjust
]);
| where tolower(RecipientEmailAddress) in~ (targets)
```

### Narrowing down to look-alike sender domains

A second, much sharper variant: first contact from a domain that contains your
own brand name but is not yours (typosquat, `-bv` variant, different TLD).

<!-- query
platform: sentinel
name: Inbound mail from a lookalike domain containing the company brand name
technique: T1598
severity: Medium
tactics: [Reconnaissance]
interval: P1D
lookback: P14D
parameters: [brand, ownDomains]
deployable: true
-->

```kql
let brand = "yourbrand";                  // <-- adjust, without TLD
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where SenderFromDomain has brand
| where SenderFromDomain !in~ (ownDomains)
| summarize Messages = count(),
            Recipients = dcount(RecipientEmailAddress),
            First = min(Timestamp), Last = max(Timestamp)
          by SenderFromDomain, SenderFromAddress
| order by Messages desc
```

## Why this matters for BEC

Credibility is the whole attack. The FBI Internet Crime Complaint Center counted
305,033 BEC incidents worldwide between October 2013 and December 2023 with
exposed losses of 55,499,915,582 dollars, and explicitly describes how criminals
use a compromised business email account to request personal data with which
they then compromise *other* accounts (I-091124-PSA, 11 September 2024). The
information request is therefore not an isolated annoyance but the first link in
the chain. MITRE places T1598 in the Reconnaissance tactic, ahead of any
technical action in the tenant.

## References

- MITRE ATT&CK T1598: https://attack.mitre.org/techniques/T1598/
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, EmailEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, Defender for Office 365 Plan 1 vs Plan 2: https://learn.microsoft.com/en-us/defender-office-365/mdo-about
- Microsoft, Defender XDR data into Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender
- FBI IC3 I-091124-PSA, *Business Email Compromise: The $55 Billion Scam*: https://www.ic3.gov/PSA/2024/PSA240911
