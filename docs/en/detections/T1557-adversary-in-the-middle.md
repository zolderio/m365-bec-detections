# T1557 — Adversary-in-the-Middle

| | |
|---|---|
| **MITRE tactic** | Credential Access, Collection |
| **Advisory measures** | 004 — Phishing-resistant multi-factor authentication (priority High)<br>005 — Microsoft Defender for Office 365 (priority Medium) |
| **Related techniques** | [T1566.002](T1566.002-spearphishing-link.md) — the link that leads to the proxy<br>[T1539](T1539-steal-web-session-cookie.md) — the cookie the proxy intercepts |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> Microsoft has a detection that covers precisely this technique and that,
> according to Microsoft, is *high precision*: the Entra ID Protection detection
> **Attacker in the Middle**. There is one problem, and it is not a small one:
> the documented licence level is **Microsoft 365 E5 with Enterprise Mobility +
> Security E5** — as the only option, so even Entra ID P2 on its own is not
> enough. For the bulk of the SMEs this advisory is aimed at, the detection is
> therefore out of reach. What you do have without E5 are Safe Links clicks and
> the sign-in logs; the rule you build on those — a click on a link, shortly
> afterwards a successful sign-in from an ASN the user never uses — is the
> workable alternative.

## Is there a Defender alert for this?

**Yes, but at E5 level.** Note the name: the Entra detection is called
**Attacker in the Middle**, not "AiTM phishing attack".

| | |
|---|---|
| **Risk detection** | `Attacker in the Middle` (user risk, `riskEventType` = `attackerinTheMiddle`) |
| **Detection type** | Offline |
| **Licensing** | **Microsoft 365 E5 with Enterprise Mobility + Security E5** — this is the only combination Microsoft names for this detection |
| **Risk level** | Puts the user at **High** risk |
| **What it is** | Microsoft: *"this high precision detection is triggered when an authentication session is linked to a malicious reverse proxy."* Microsoft recommends manual investigation; clean-up requires a secure password reset or revoking existing sessions. |
| **Source** | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks |

Two Defender XDR alerts from the same scenario, with an official grading
playbook:

| Alert | Severity | Licensing |
|---|---|---|
| `Authentication request from AiTM-related phishing page` | Not publicly documented | Not publicly documented |
| `Stolen session cookie was used` | Not publicly documented | Not publicly documented |

Source: https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert

A third name, `Possible AiTM phishing attempt`, comes from the Microsoft
Security Blog of 8 June 2023 and was **not found in the Learn alert reference**.
Treat it as a name that may appear in the portal, but do not build detection
logic on it.

On the mail side, and only if Safe Links is enabled:

| Alert policy | Severity | Licensing | Limitation |
|---|---|---|---|
| `A potentially malicious URL click was detected` | **High** | E5/G5 or Defender for Office 365 Plan 2 add-on | Fires on a *verdict change*: the URL must have been recognised as malicious. A fresh AiTM proxy on a newly registered domain often has no verdict yet at the moment of the click. |
| `A user clicked through to a potentially malicious URL` | **High** | E5/G5 or Defender for Office 365 Plan 2 add-on | Only fires if the user deliberately clicks past the Safe Links warning page. |

**Retired, do not build on this any more.** The Defender for Cloud Apps policy
`Activity from anonymous IP addresses` was switched off as of June 2025 and,
according to Microsoft, migrated to `Activity from a TOR IP address` and
`Anonymous proxy activity`. `Activity from suspicious IP addresses` has also
been switched off. Both featured in many inventories as AiTM coverage.
Source: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `UrlClickEvents` | Data connector **Microsoft Defender XDR**, *Connect events* → Defender for Office 365. Only populated with Safe Links enabled. |
| Microsoft Sentinel | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Data connector **Microsoft Entra ID**; sign-in logs require Entra ID P1 or P2. |
| Microsoft Sentinel | `AADUserRiskEvents` | Same connector; detection details require P2. |
| Defender XDR advanced hunting | `UrlClickEvents`, `EmailEvents` | Defender for Office 365; **advanced hunting requires Plan 2**. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Replaces `AADSignInEventsBeta` as of 19 October 2026. |

Not dependent on measure 012 (UAL). Fully dependent on measure 005, however:
without Safe Links, `UrlClickEvents` does not exist.

## KQL — Defender XDR: click followed by a sign-in from a new ASN

<!-- query
platform: defender-xdr
name: Link click followed within an hour by a sign-in from an unseen IP address
technique: T1557
severity: Medium
tactics: [CredentialAccess, InitialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->
```kql
// The AiTM signature in telemetry: a user clicks a link, and within an hour
// there is a successful sign-in from a network that user has never come from in
// the past 30 days. Deliberately NOT filtered on a phish verdict - it is
// precisely the clicks without a verdict that are the gap the Defender alerts
// leave open.
let window   = 60m;
let lookback = 7d;
let known    =
    EntraIdSignInEvents
    | where Timestamp between (ago(37d) .. ago(lookback))
    | where ErrorCode == 0
    | summarize KnownIPs = make_set(IPAddress, 200) by AccountUpn;
let clicks =
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Workload == "Email"
    | project ClickTime = Timestamp, AccountUpn, Url, UrlChain, ActionType,
              IsClickedThrough, ThreatTypes, NetworkMessageId, ReportId;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where ClientAppUsed == "Browser"
| join kind=inner clicks on AccountUpn
| where Timestamp between (ClickTime .. ClickTime + window)
| join kind=leftouter known on AccountUpn
| where isempty(KnownIPs) or not(set_has_element(KnownIPs, IPAddress))
| project ClickTime, SignInTime = Timestamp, AccountUpn, Url, ThreatTypes,
          IsClickedThrough, IPAddress, Country, City, Application,
          AuthenticationRequirement, ConditionalAccessStatus, SessionId, UserAgent
| order by SignInTime desc
```

`SessionId` is in the output for a reason: you feed it straight into the session
theft query from [T1539](T1539-steal-web-session-cookie.md).

## KQL — Defender XDR: clicked through despite the Safe Links warning

This query comes from the Microsoft documentation of the `UrlClickEvents` table.

<!-- query
platform: defender-xdr
name: User clicked through a Safe Links warning on a phishing URL
technique: T1557
severity: Medium
tactics: [CredentialAccess, InitialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->
```kql
// Search for malicious links where user was allowed to proceed through
UrlClickEvents
| where ActionType == "ClickAllowed" or IsClickedThrough !="0"
| where ThreatTypes has "Phish"
| summarize by ReportId, IsClickedThrough, AccountUpn, NetworkMessageId, ThreatTypes, Timestamp
```

The complete list of `ActionType` values is **not in the schema
documentation**; `ClickAllowed` is the only value Microsoft names there. Use the
built-in schema reference in the Defender portal to establish the remaining
values for your tenant before filtering on them.

## KQL — Sentinel (SigninLogs)

Without `UrlClickEvents` — or as a supplement to it — this is the most usable
signal that is already available with Entra ID P1: a successful sign-in where
Entra itself already saw risk, or where MFA was satisfied from an unknown
network.

<!-- query
platform: sentinel
name: Successful MFA sign-in from an autonomous system not seen for this user
technique: T1557
severity: Medium
tactics: [CredentialAccess]
interval: P1D
lookback: P14D
parameters: []
deployable: true
-->
```kql
// Successful sign-ins from an ASN this user did not use in the preceding
// 30 days. In an AiTM attack the attacker signs in with a stolen token from
// their own infrastructure, so the ASN deviates while the MFA requirement IS
// satisfied - and that last part is exactly what makes it treacherous.
let lookback = 7d;
let baseline =
    SigninLogs
    | where TimeGenerated between (ago(37d) .. ago(lookback))
    | where ResultType == "0"
    | summarize KnownASN = make_set(AutonomousSystemNumber, 100) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where AuthenticationRequirement == "multiFactorAuthentication"
| join kind=leftouter baseline on UserPrincipalName
| where isempty(KnownASN) or not(set_has_element(KnownASN, AutonomousSystemNumber))
| project TimeGenerated, UserPrincipalName, IPAddress, AutonomousSystemNumber,
          Location, AppDisplayName, ClientAppUsed, UserAgent,
          ConditionalAccessStatus, RiskLevelDuringSignIn, RiskEventTypes_V2, SessionId
| order by TimeGenerated desc
```

And to retrieve the Entra detection if you do have the E5 combination:

<!-- query
platform: sentinel
name: Entra ID risk detection for adversary-in-the-middle
technique: T1557
severity: High
tactics: [CredentialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType == "attackerinTheMiddle"    // exact riskEventType from the Graph documentation
| project TimeGenerated, ActivityDateTime, UserPrincipalName, IpAddress, Location,
          RiskLevel, RiskState, RiskDetail, DetectionTimingType, Source, CorrelationId
| order by TimeGenerated desc
```

## Why this matters for BEC

AiTM is the reason "we have MFA" is no longer an answer. On 12 July 2022
Microsoft documented a campaign that had attempted to hit more than 10,000
organisations since September 2021, in which the proxy intercepted both the
password and the session cookie and the attacker started payment fraud within
*"as little time as five minutes"*. June 2023 brought a campaign in which, after
the AiTM step, the attacker registered their own MFA method, created an inbox
rule that moved mail to Archive and marked it as read, and from there sent more
than 16,000 phishing emails to the victim's contacts. That is the complete BEC
chain, and the starting point is this technique. This is why measure 004
(phishing-resistant MFA) carries priority High in the advisory: FIDO2 and
Windows Hello for Business are the only variants a reverse proxy cannot relay.

## References

- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- Microsoft, risk detections and licence levels (detection *Attacker in the Middle*): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, alert grading for session cookie theft: https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, UrlClickEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table
- Microsoft, EntraIdSignInEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, Defender for Cloud Apps anomaly detection policies (retired legacy policies): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft Security Blog, *From cookie theft to BEC* (12 July 2022): https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
- Microsoft Security Blog, *Detecting and mitigating a multi-stage AiTM phishing and BEC campaign* (8 June 2023): https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/
