# T1539 — Steal Web Session Cookie

| | |
|---|---|
| **MITRE tactic** | Credential Access |
| **Advisory measures** | 004 — Phishing-resistant multifactor authentication (priority High)<br>005 — Microsoft Defender for Office 365 (priority Medium) |
| **Related techniques** | [T1557](T1557-adversary-in-the-middle.md) — how the cookie is usually captured<br>[T1078.004](T1078.004-cloud-accounts.md) — what happens with the session |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE` — both
>
> Here Microsoft has something that is missing for most techniques in this
> advisory: two named alerts (`Stolen session cookie was used` and
> `Authentication request from AiTM-related phishing page`) with an official
> alert grading playbook. Switch those on. The gap is in the timing and in the
> licensing: the alert fires at the moment the stolen cookie is *used*, and the
> investigation Microsoft itself prescribes alongside it leans on
> `EntraIdSignInEvents` — a table that requires Microsoft Entra ID P2. The
> Sentinel rule on one session ID from two countries fills that gap, and works
> on `SigninLogs`, which you already have with P1.

## Is there a Defender alert for this?

**Yes, two — with unknown severity.**

| | |
|---|---|
| **Alert** | `Stolen session cookie was used` |
| **Product** | Microsoft Defender XDR |
| **Default severity** | **Not publicly documented** — the alert grading page names the alert and the investigation path, not a severity |
| **Licensing** | **Not publicly documented** on the alert page. The investigation Microsoft describes alongside it uses `AADSignInEventsBeta`/`EntraIdSignInEvents`, and those require Entra ID P2. |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert |

| | |
|---|---|
| **Alert** | `Authentication request from AiTM-related phishing page` |
| **Product** | Microsoft Defender XDR |
| **Default severity** | **Not publicly documented** |
| **Licensing** | **Not publicly documented** |
| **What it is** | Same playbook, different angle: the authentication request comes in via a reverse proxy. See [T1557](T1557-adversary-in-the-middle.md). |

In addition, three relevant Entra ID Protection detections:

| Risk detection | Type | Licensing | Why it matters |
|---|---|---|---|
| `Anomalous Token` (sign-in and user, `riskEventType` = `anomalousToken`) | Real-time or offline | **Microsoft Entra ID P2** | According to Microsoft it explicitly covers *"Session Tokens"* and *"Refresh Tokens"*: an unusual lifetime, or a token replayed from an unfamiliar location. Microsoft itself warns about false positives at low and medium risk. |
| `Unfamiliar sign-in properties` (`unfamiliarFeatures`) | Real-time | **Microsoft Entra ID P2** | Microsoft: *"When this detection is detected on non-interactive sign-ins, it deserves increased scrutiny due to the risk of token replay attacks."* |
| `Token issuer anomaly` (`tokenIssuerAnomaly`) | Offline | **Microsoft Entra ID P2** | For the AD FS/SAML scenario: the token issuer itself may be compromised. |

Source: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

Without P2 these three appear as `Additional risk detected`, without details.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Data connector **Microsoft Entra ID**; sign-in logs require Entra ID P1 or P2. |
| Microsoft Sentinel | `AADUserRiskEvents` | Same connector; detection details require P2. |
| Microsoft Sentinel | `CloudAppEvents` | Data connector **Microsoft Defender XDR**, *Connect events* → Defender for Cloud Apps. Requires an enabled Unified Audit Log (**measure 012**) for the Exchange activities. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Replaces `AADSignInEventsBeta` as of **19 October 2026**. |
| Defender XDR advanced hunting | `CloudAppEvents`, `AlertInfo`, `AlertEvidence` | Defender for Cloud Apps connected (**Settings > Cloud apps > App connectors**, with *Microsoft 365 activities* ticked). |

## KQL — Defender XDR: one session, two countries

The query below is the session theft hunting query published by Microsoft,
ported from `AADSignInEventsBeta` to its successor `EntraIdSignInEvents`. The
column names are the same in both tables.

```kql
// A session starts with a successful interactive browser sign-in to the
// OfficeHome app; the country at that moment is the "real" location. If the
// same SessionId is subsequently used from another country for another
// application, the cookie has almost certainly been replayed elsewhere.
let OfficeHomeSessionIds =
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId == "4765445b-32c6-49b0-83e6-1d93765276ca"   // OfficeHome
| where ClientAppUsed == "Browser"
| where LogonType has "interactiveUser"
| summarize arg_min(Timestamp, Country) by SessionId;
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ApplicationId != "4765445b-32c6-49b0-83e6-1d93765276ca"
| where ClientAppUsed == "Browser"
| project OtherTimestamp = Timestamp, Application, ApplicationId,
          AccountObjectId, AccountDisplayName, OtherCountry = Country, SessionId
| join OfficeHomeSessionIds on SessionId
| where OtherTimestamp > Timestamp and OtherCountry != Country
```

### Inbox rules created within a suspicious session

This too is Microsoft's own query, taken over unchanged. It links the Entra
alert `Anomalous Token` to the mailbox action that follows it in a BEC scenario.

```kql
// Look for tokens flagged by the Entra alert "Anomalous Token"
let suspiciousSessionIds = materialize(
AlertInfo
| where Timestamp > ago(7d)
| where Title == "Anomalous Token"
| join (AlertEvidence | where Timestamp > ago(7d) | where EntityType == "CloudLogonSession") on AlertId
| project sessionId = todynamic(AdditionalFields).SessionId);
// And check whether an inbox rule was created within such a session
let hasSuspiciousSessionIds = isnotempty(toscalar(suspiciousSessionIds));
CloudAppEvents
| where hasSuspiciousSessionIds
| where Timestamp > ago(21d)
| where ActionType == "New-InboxRule"
| where RawEventData.SessionId in (suspiciousSessionIds)
```

## KQL — Sentinel (SigninLogs)

`SigninLogs` has the same `SessionId`, plus `UniqueTokenIdentifier` — *"a
unique base64 encoded request identifier used to track tokens issued by Azure AD
as they are redeemed at resource providers"*. For token replay that is a
sharper anchor than the session.

```kql
// One token being redeemed at resource providers from multiple IP addresses
// or from multiple countries. In a normal session that happens from one
// place; with a stolen cookie or refresh token it does not.
let lookback = 7d;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(UniqueTokenIdentifier)
| summarize Countries    = make_set(Location, 10),
            CountryCount = dcount(Location),
            IPs          = make_set(IPAddress, 10),
            IPCount      = dcount(IPAddress),
            Apps         = make_set(AppDisplayName, 10),
            First        = min(TimeGenerated),
            Last         = max(TimeGenerated)
          by UniqueTokenIdentifier, UserPrincipalName
| where CountryCount > 1
| extend Span = Last - First
| order by CountryCount desc, IPCount desc
```

And the session variant, which stays closer to the XDR query:

```kql
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(SessionId)
| summarize Countries = make_set(Location, 10), CountryCount = dcount(Location),
            IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10)
          by SessionId, UserPrincipalName
| where CountryCount > 1
```

Both queries produce noise for users behind a VPN with changing exit nodes and
for mobile users switching networks. Filter on ASN instead of IP if that yields
too much in your environment — `AutonomousSystemNumber` is present in both
sign-in tables.

## Why this matters for BEC

On 12 July 2022 Microsoft described a campaign that had attempted to hit more
than 10,000 organisations since September 2021: AiTM sites stole passwords and
session cookies, thereby bypassing MFA, and the stolen sessions were used to run
BEC campaigns from the mailbox against other targets. In the same piece
Microsoft measures that it could take *"as little time as five minutes"* between
the theft and the first payment fraud. In the alert grading documentation
Microsoft puts it even more briefly: *"BEC campaigns are an excellent example."*
The cookie is attractive because it skips both a password change and an MFA
prompt — precisely the two measures an organisation reaches for first after an
incident.

## References

- MITRE ATT&CK T1539: https://attack.mitre.org/techniques/T1539/
- Microsoft, alert grading for session cookie theft (source of both alert names and of the hunting queries): https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
- Microsoft, risk detections and licensing levels in Entra ID Protection: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, EntraIdSignInEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, AADSignInEventsBeta (deprecation 19 Oct 2026): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table
- Microsoft, SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, CloudAppEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, AlertEvidence schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table
- Microsoft Security Blog, *From cookie theft to BEC* (12 July 2022): https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
