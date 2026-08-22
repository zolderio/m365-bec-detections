# T1621 — Multi-Factor Authentication Request Generation

| | |
|---|---|
| **MITRE tactic** | Credential Access |
| **Advisory measures** | 004 — Phishing-resistant multi-factor authentication (priority High)<br>005 — Microsoft Defender for Office 365 (priority Medium) |
| **Related technique** | [T1110.003](T1110.003-password-spraying.md) — how the password that precedes this was found |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> There is no alert policy for MFA fatigue, and the two Entra detections that
> touch on it (`Suspicious MFA authentication approval` and `User reported
> suspicious activity`) both require Microsoft Entra ID P2. The good news is
> that the raw signal is very clean and already available with Entra ID P1: a
> series of sign-in attempts with `ResultType` **500121** on a single account
> within a short window is abnormal by definition, because a user signing in
> themselves presses deny once and not twelve times. Build that rule, and enable
> **Report suspicious activity** alongside it — that is a setting in the
> Authentication methods policy, not a licence.

## Is there a Defender alert for this?

**No, no alert policy.** The list of default alert policies contains nothing
about MFA. Coverage sits entirely in Entra ID Protection, and that is premium.

| | |
|---|---|
| **Risk detection** | `Suspicious MFA authentication approval` (sign-in risk, `riskEventType` = `authenticatorPhishing`) |
| **Detection type** | Real-time |
| **Licensing** | **Microsoft Entra ID P2** |
| **Risk level** | Marks the sign-in attempt as **High risk** |
| **What it is** | Fires on sessions with *Password + MFA* plus telemetry from the Microsoft Authenticator app, where unfamiliar properties (ASN, browser, device, GPS) point to social engineering. Microsoft analyses the distance between the device that *requests* the authentication and the device that *approves* it. |
| **Limitation** | Only works if the user uses the Microsoft Authenticator app. SMS- and phone-based MFA — precisely what measure 004 aims to phase out — does not produce this telemetry. |
| **Source** | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks |

| | |
|---|---|
| **Risk detection** | `User reported suspicious activity` (user risk, `riskEventType` = `userReportedSuspiciousActivity`) |
| **Detection type** | Offline |
| **Licensing** | The ID Protection reference classifies this detection as **Premium** (Entra ID P2). The MFA settings page, however, *also* describes how P1 tenants find the report in the Risk detections report. **Those two pages contradict each other; not verified which applies in practice.** Assume P2 until you have seen it in your own tenant. |
| **Prerequisite** | The **Report suspicious activity** feature must be enabled: *Entra ID > Authentication methods > Settings*. It defaults to *Microsoft managed*, and then it is off. |
| **What it produces** | The user goes to **High User Risk**. In the Risk detections report as detection type *User Reported Suspicious Activity*, risk level *High*, source *End user reported*. In the sign-in logs the result detail reads **MFA denied**. |
| **Limitation** | Microsoft: *"A user isn't reported as High Risk if they perform passwordless authentication."* |
| **Source** | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings |

**Retired.** The legacy features *Block/unblock users*, *Fraud alert* and
*Notifications* were removed on 1 March 2025 and replaced by
*Report suspicious activity*. References to Fraud alert in older runbooks are
dead.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `SigninLogs` | Data connector **Microsoft Entra ID**. Microsoft: *"A Microsoft Entra ID P1 or P2 license is required to ingest sign-in logs into Microsoft Sentinel."* |
| Microsoft Sentinel | `AADUserRiskEvents` | Same connector (log type *User risk events*); detection details require P2. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Replaces `AADSignInEventsBeta` as of 19 October 2026. |

Not dependent on measure 012 (UAL).

## The error code it all revolves around

| | |
|---|---|
| **Code** | `500121` |
| **Meaning** | *"Authentication failed during strong authentication request."* Microsoft: *"The user didn't complete the MFA prompt. They may have decided not to authenticate, timed out while doing other work, or has an issue with their authentication setup."* |
| **Source** | https://login.microsoftonline.com/error?code=500121 |
| **Note** | 500121 is **not** in the AADSTS error code reference on Microsoft Learn; the description above comes from Microsoft's own error code lookup. |

A single 500121 is therefore not an incident — that is a user who did not have
their phone to hand. The pattern is the signal: many of these codes on one
account in a short window, from an IP the user does not know.

## KQL — Sentinel (SigninLogs)

<!-- query
platform: sentinel
name: Burst of denied or timed-out MFA prompts on a single account
technique: T1621
severity: Medium
tactics: [CredentialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
// MFA fatigue: a series of failed MFA challenges on the same account within
// a short window. The password is already correct (otherwise the error would have
// been 50126 and the MFA step would never have been reached) - that makes this a
// post-credential signal and therefore more urgent than a failed sign-in.
let window = 15m;
let threshold = 5;                       // <-- tune this; start high and work down
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "500121"
| summarize Attempts  = count(),
            IPs       = make_set(IPAddress, 10),
            IPCount   = dcount(IPAddress),
            Countries = make_set(Location, 10),
            Apps      = make_set(AppDisplayName, 10),
            First     = min(TimeGenerated),
            Last      = max(TimeGenerated)
          by UserPrincipalName, bin(TimeGenerated, window)
| where Attempts >= threshold
| order by Attempts desc
```

### The variant that really matters: fatigue followed by success

<!-- query
platform: sentinel
name: Successful sign-in from the same IP right after a burst of denied MFA prompts
technique: T1621
severity: High
tactics: [CredentialAccess, InitialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
// A series of denied MFA prompts and then a successful sign-in from the same
// IP: the user eventually gave in. This is the query you want as an analytic
// rule, not the one above.
let window    = 30m;
let threshold = 5;
let fatigue   =
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "500121"
    | summarize Attempts = count(), Start = min(TimeGenerated), End = max(TimeGenerated)
              by UserPrincipalName, IPAddress
    | where Attempts >= threshold;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| join kind=inner fatigue on UserPrincipalName, IPAddress
| where TimeGenerated between (Start .. End + window)
| project SucceededAt = TimeGenerated, UserPrincipalName, IPAddress, Location,
          Attempts, AppDisplayName, ClientAppUsed, UserAgent,
          AuthenticationRequirement, ConditionalAccessStatus, SessionId
| order by SucceededAt desc
```

### The user who reports it themselves

If *Report suspicious activity* is enabled, Entra writes the result detail
**MFA denied** into `AuthenticationDetails`. That is a single string column
holding the outcome of every authentication step, so a `has` is the right
filter.

<!-- query
platform: sentinel
name: Sign-in where the user rejected the MFA prompt as suspicious
technique: T1621
severity: Medium
tactics: [CredentialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationDetails has "MFA denied"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          ResultType, ResultDescription, AuthenticationDetails,
          AuthenticationRequirement, RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated desc
```

And the risk detection itself, if you have P2:

<!-- query
platform: sentinel
name: Entra ID Protection risk detections for suspicious or user-reported MFA activity
technique: T1621
severity: Medium
tactics: [CredentialAccess]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->

```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType in ("userReportedSuspiciousActivity", "authenticatorPhishing")
| project TimeGenerated, ActivityDateTime, UserPrincipalName, IpAddress, Location,
          RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType, Source
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (EntraIdSignInEvents)

<!-- query
platform: defender-xdr
name: Burst of denied MFA prompts on one account in Defender XDR sign-in events
technique: T1621
severity: Medium
tactics: [CredentialAccess]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->

```kql
// Same logic. ErrorCode is an int here instead of a string.
let window = 15m;
let threshold = 5;
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 500121
| summarize Attempts  = count(),
            IPs       = make_set(IPAddress, 10),
            Countries = make_set(Country, 10),
            Apps      = make_set(Application, 10),
            First     = min(Timestamp),
            Last      = max(Timestamp)
          by AccountUpn, bin(Timestamp, window)
| where Attempts >= threshold
| order by Attempts desc
```

## Why this matters for BEC

FBI, CISA, NSA, CSE, AFP and ASD's ACSC describe in joint advisory
**AA24-290A** (16 October 2024) how actors, after a successful password spray,
*"send MFA requests to legitimate users seeking acceptance of the request"*, and
name the technique explicitly: *"bombarding users with mobile phone push
notifications until the user either approves the request by accident or stops
the notifications — is known as 'MFA fatigue' or 'push bombing' [T1621]"*.
The same advisory describes how the attackers then register their own device as
an MFA method to retain access. That is why this signal counts: every 500121
series is an attacker who already *has* the password.

## References

- MITRE ATT&CK T1621: https://attack.mitre.org/techniques/T1621/
- Microsoft, risk detections and licence levels in Entra ID Protection: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, configuring *Report suspicious activity*: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings
- Microsoft, error code 500121: https://login.microsoftonline.com/error?code=500121
- Microsoft, AADSTS error code reference (which does *not* list 500121): https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Microsoft, SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, AADUserRiskEvents schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents
- Microsoft, EntraIdSignInEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, Entra ID data into Sentinel (licence requirements): https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory
- CISA/FBI AA24-290A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a
