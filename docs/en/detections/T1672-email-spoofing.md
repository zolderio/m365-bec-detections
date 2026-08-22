# T1672 — E-mail Spoofing

| | |
|---|---|
| **MITRE tactic** | Resource Development (classification used by the advisory) |
| **Advisory measures** | 002 — Configure SPF, DKIM and DMARC correctly (priority Medium)<br>003 — Disable the Direct Send feature (priority High) |
| **Note on the ID** | `https://attack.mitre.org/techniques/T1672/` now redirects to **T1684.002 — Social Engineering: Email Spoofing** (tactic *Stealth*). The advisory uses T1672; that was the ID in force in April 2026. Both refer to the same technique. |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> On the prevention side Microsoft does a great deal: composite authentication,
> spoof intelligence and the anti-phishing policy together determine whether a
> forged message lands in the Inbox, in Junk or in quarantine — and that is
> present in every tenant with cloud mailboxes, without an add-on. But that is a
> *delivery decision*, not an alert: there is no default alert policy at all that
> fires on an inbound message spoofing your own domain, nor one on abuse of
> Direct Send. The real measure is preventive (`Set-OrganizationConfig
> -RejectDirectSend $true` and DMARC at `p=reject`); the detection around it is
> something you build yourself on `EmailEvents`.

## Is there a Defender alert for this?

**No.** The list of default alert policies contains no policy for inbound
spoofing or for Direct Send. What does exist is prevention and a few policies on
the outbound side.

### Prevention (no alert, but free)

| | |
|---|---|
| **Mechanism** | Composite authentication (`compauth`) + spoof intelligence + anti-phishing policy |
| **Licensing** | The built-in protection for all cloud mailboxes (EOP) — no add-on required |
| **What it looks like** | Intra-org spoofing: `Authentication-Results: ... compauth=fail reason=6xx` and `X-Forefront-Antispam-Report: ...CAT:SPOOF;...SFTY:9.11`. Cross-domain: `compauth=fail reason=000/001` and `SFTY:9.22`. |
| **Important nuance** | Microsoft: *"a composite authentication failure doesn't directly result in blocking a message."* A `compauth=fail` is therefore a signal, not a verdict. |
| **Source** | https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about |

### Turning off Direct Send

| | |
|---|---|
| **Setting** | `Set-OrganizationConfig -RejectDirectSend $true` (Exchange Online PowerShell, type `Boolean`) |
| **Effect** | Unauthenticated messages carrying the domain as sender are rejected. |
| **Alert** | None. There is no alert policy that reports that Direct Send is being used or abused; that visibility has to come from `EmailEvents`. |
| **Source** | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig |

### Policies that come close (all outbound)

| Alert policy | Severity | Licensing | Why it does *not* cover your technique |
|---|---|---|---|
| `Suspicious connector activity` | **High** | E1/F1/G1, E3/F3/G3, or E5/G5 | Fires on a compromised *inbound connector*, not on a spoofed message. |
| `Tenant restricted from sending unprovisioned email` | **High** | E1/F1/G1, E3/F3/G3, or E5/G5 | Fires when *your* tenant sends too much mail from unregistered domains. Signals abuse after the fact. |
| `Suspicious tenant sending patterns observed` | **High** | E1/F1/G1, E3/F3/G3, or E5/G5 | Likewise: outbound, and at tenant level. |

Source for severities and licensing: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `EmailEvents` | Data connector **Microsoft Defender XDR**, *Connect events* with the Defender for Office 365 tables. |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365 rolled out; **advanced hunting requires Defender for Office 365 Plan 2**. |

Not dependent on measure 012 (UAL). Entirely dependent on Defender for
Office 365, however: in an EOP-only tenant `EmailEvents` does not exist and only
message trace in the Defender portal remains.

## KQL — Direct Send abuse (EmailEvents, both platforms)

```kql
// Inbound message carrying one of your own domains as sender that did NOT
// arrive via a connector. That is precisely the signature of Direct Send:
// the message arrives unauthenticated at the MX endpoint and there is
// therefore no connector to point to. Legitimate internal mail is
// Intra-org, not Inbound.
let lookback = 30d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (ownDomains)
| where isempty(Connectors)              // no connector = not via an authenticated path
| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderIPv6,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          AuthenticationDetails, NetworkMessageId
| order by Timestamp desc
```

If you deliberately still have Direct Send enabled for printers or a line-of-business
application, exclude those sources by IP and monitor the volume — the advisory
asks for that explicitly:

```kql
let allowedIPs = dynamic(["203.0.113.10", "203.0.113.11"]);   // <-- adjust
| where SenderIPv4 !in (allowedIPs)
```

And to spot anomalous volume from those trusted addresses:

```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound" and isempty(Connectors)
| where SenderIPv4 in (dynamic(["203.0.113.10", "203.0.113.11"]))   // <-- adjust
| summarize Messages = count() by bin(Timestamp, 1h), SenderIPv4
| order by Messages desc
```

## KQL — failing email authentication on your own domain

```kql
// Messages posing as your domain where DMARC, SPF, DKIM or composite
// authentication fails. AuthenticationDetails is a single string column with
// the verdicts of all protocols; there is no separate column per protocol, so
// the filter is a has_any on the text.
let lookback = 14d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (ownDomains)
| where AuthenticationDetails has_any ("fail", "softfail", "none")
| project Timestamp, SenderFromAddress, SenderMailFromDomain, SenderIPv4,
          RecipientEmailAddress, Subject, AuthenticationDetails,
          DeliveryAction, DeliveryLocation, EmailActionPolicy, NetworkMessageId
| order by Timestamp desc
```

Two helper columns that make triage faster, both documented in the
`EmailEvents` schema:

- On a spoof verdict, `EmailActionPolicy` contains the value `Anti-phishing spoof`.
  That lets you separate "the stack saw it and acted" from "the stack did not see it".
- `DeliveryLocation` shows whether the message landed in `Inbox/Folder` despite
  the verdict. Those are the cases that really matter.

```kql
| extend StackCaughtIt = EmailActionPolicy == "Anti-phishing spoof"
| where DeliveryLocation in~ ("Inbox/folder", "Junk")
```

## Why this matters for BEC

In its own anti-spoofing documentation Microsoft uses a spoofed `contoso.com` as
the textbook example of BEC: *"Messages from spoofed senders might trick the
recipient into giving up their credentials, downloading malware, or replying to
a message with sensitive content (known as business email compromise or BEC)."*
MITRE names Direct Send explicitly under this technique: attackers abuse the
Direct Send feature of Microsoft 365 to spoof internal users by sending mail
without authentication. Exactly the measure the advisory puts at priority High
under ID 003.

## References

- MITRE ATT&CK T1684.002 (Social Engineering: Email Spoofing), which T1672 redirects to: https://attack.mitre.org/techniques/T1684/002/
- MITRE ATT&CK T1672: https://attack.mitre.org/techniques/T1672/
- Microsoft, anti-spoofing and composite authentication: https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about
- Microsoft, email authentication (SPF/DKIM/DMARC): https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about
- Microsoft, `Set-OrganizationConfig` (parameter `RejectDirectSend`): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, EmailEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
