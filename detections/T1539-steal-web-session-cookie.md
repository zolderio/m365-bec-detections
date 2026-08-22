# T1539 — Steal Web Session Cookie

| | |
|---|---|
| **MITRE-tactiek** | Credential Access |
| **Whitepaper-maatregelen** | 004 — Phishing-resistente multifactorauthenticatie (prioriteit Hoog)<br>005 — Microsoft Defender for Office 365 (prioriteit Midden) |
| **Verwante technieken** | [T1557](T1557-adversary-in-the-middle.md) — hoe het cookie meestal wordt buitgemaakt<br>[T1078.004](T1078.004-cloud-accounts.md) — wat er met de sessie gebeurt |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../TESTING.md) |

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE` — beide
>
> Microsoft heeft hier iets wat bij de meeste technieken in dit advies
> ontbreekt: twee benoemde alerts (`Stolen session cookie was used` en
> `Authentication request from AiTM-related phishing page`) mét een officieel
> alert-grading-playbook. Zet die aan. Het gat zit in de timing en in de
> licentie: het alert vuurt op het moment dat het gestolen cookie *gebruikt*
> wordt, en het onderzoek dat Microsoft er zelf bij voorschrijft leunt op
> `EntraIdSignInEvents` — een tabel die Microsoft Entra ID P2 vereist. De
> Sentinel-rule op één sessie-ID vanuit twee landen vult dat gat, en werkt op
> `SigninLogs` die je met P1 al hebt.

## Is er een Defender-alert voor?

**Ja, twee — met onbekende severity.**

| | |
|---|---|
| **Alert** | `Stolen session cookie was used` |
| **Product** | Microsoft Defender XDR |
| **Standaard severity** | **Niet publiek gedocumenteerd** — de alert-grading-pagina noemt de naam en het onderzoekspad, geen severity |
| **Licentie** | **Niet publiek gedocumenteerd** op de alertpagina. Het onderzoek dat Microsoft erbij beschrijft gebruikt `AADSignInEventsBeta`/`EntraIdSignInEvents`, en die vereisen Entra ID P2. |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert |

| | |
|---|---|
| **Alert** | `Authentication request from AiTM-related phishing page` |
| **Product** | Microsoft Defender XDR |
| **Standaard severity** | **Niet publiek gedocumenteerd** |
| **Licentie** | **Niet publiek gedocumenteerd** |
| **Wat het is** | Zelfde playbook, andere invalshoek: de authenticatieaanvraag komt via een reverse proxy binnen. Zie [T1557](T1557-adversary-in-the-middle.md). |

Daarnaast drie relevante Entra ID Protection-detecties:

| Risk detection | Type | Licentie | Waarom relevant |
|---|---|---|---|
| `Anomalous Token` (sign-in én user, `riskEventType` = `anomalousToken`) | Real-time of offline | **Microsoft Entra ID P2** | Dekt volgens Microsoft expliciet *"Session Tokens"* en *"Refresh Tokens"*: ongebruikelijke levensduur, of een token afgespeeld vanaf een onbekende locatie. Microsoft waarschuwt zelf voor false positives op low en medium risk. |
| `Unfamiliar sign-in properties` (`unfamiliarFeatures`) | Real-time | **Microsoft Entra ID P2** | Microsoft: *"When this detection is detected on non-interactive sign-ins, it deserves increased scrutiny due to the risk of token replay attacks."* |
| `Token issuer anomaly` (`tokenIssuerAnomaly`) | Offline | **Microsoft Entra ID P2** | Voor het AD FS-/SAML-scenario: de tokenuitgever zelf is mogelijk gecompromitteerd. |

Bron: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

Zonder P2 verschijnen deze drie als `Additional risk detected`, zonder details.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Data connector **Microsoft Entra ID**; sign-in logs vereisen Entra ID P1 of P2. |
| Microsoft Sentinel | `AADUserRiskEvents` | Zelfde connector; detectiedetails vereisen P2. |
| Microsoft Sentinel | `CloudAppEvents` | Data connector **Microsoft Defender XDR**, *Connect events* → Defender for Cloud Apps. Vereist een ingeschakelde Unified Audit Log (**maatregel 012**) voor de Exchange-activiteiten. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Vervangt `AADSignInEventsBeta` per **19 oktober 2026**. |
| Defender XDR advanced hunting | `CloudAppEvents`, `AlertInfo`, `AlertEvidence` | Defender for Cloud Apps gekoppeld (**Settings > Cloud apps > App connectors**, met *Microsoft 365 activities* aangevinkt). |

## KQL — Defender XDR: één sessie, twee landen

Onderstaande query is de door Microsoft gepubliceerde
sessiediefstal-hunting-query, overgezet van `AADSignInEventsBeta` naar de
opvolger `EntraIdSignInEvents`. De kolomnamen zijn in beide tabellen gelijk.

```kql
// Een sessie begint met een geslaagde interactieve browser-aanmelding op de
// OfficeHome-app; het land van dat moment is de "echte" locatie. Wordt
// dezelfde SessionId daarna vanuit een ander land gebruikt voor een andere
// applicatie, dan is het cookie vrijwel zeker elders afgespeeld.
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

### Inboxregels die binnen een verdachte sessie zijn gemaakt

Ook dit is Microsofts eigen query, ongewijzigd overgenomen. Hij koppelt het
Entra-alert `Anomalous Token` aan de mailboxhandeling die er in een BEC-scenario
op volgt.

```kql
// Zoek tokens die door het Entra-alert "Anomalous Token" zijn gemarkeerd
let suspiciousSessionIds = materialize(
AlertInfo
| where Timestamp > ago(7d)
| where Title == "Anomalous Token"
| join (AlertEvidence | where Timestamp > ago(7d) | where EntityType == "CloudLogonSession") on AlertId
| project sessionId = todynamic(AdditionalFields).SessionId);
// En kijk of er binnen zo'n sessie een inboxregel is aangemaakt
let hasSuspiciousSessionIds = isnotempty(toscalar(suspiciousSessionIds));
CloudAppEvents
| where hasSuspiciousSessionIds
| where Timestamp > ago(21d)
| where ActionType == "New-InboxRule"
| where RawEventData.SessionId in (suspiciousSessionIds)
```

## KQL — Sentinel (SigninLogs)

`SigninLogs` heeft dezelfde `SessionId`, plus `UniqueTokenIdentifier` — *"a
unique base64 encoded request identifier used to track tokens issued by Azure AD
as they are redeemed at resource providers"*. Dat is voor tokenreplay een
scherper anker dan de sessie.

```kql
// Eén token dat bij resource providers wordt ingewisseld vanaf meerdere
// IP-adressen of vanuit meerdere landen. Bij een normale sessie gebeurt dat
// vanaf één plek; bij een gestolen cookie of refresh token niet.
let lookback = 7d;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(UniqueTokenIdentifier)
| summarize Landen        = make_set(Location, 10),
            AantalLanden  = dcount(Location),
            IPs           = make_set(IPAddress, 10),
            AantalIPs     = dcount(IPAddress),
            Apps          = make_set(AppDisplayName, 10),
            Eerste        = min(TimeGenerated),
            Laatste       = max(TimeGenerated)
          by UniqueTokenIdentifier, UserPrincipalName
| where AantalLanden > 1
| extend Spanne = Laatste - Eerste
| order by AantalLanden desc, AantalIPs desc
```

En de sessievariant, die dichter bij de XDR-query blijft:

```kql
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(SessionId)
| summarize Landen = make_set(Location, 10), AantalLanden = dcount(Location),
            IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10)
          by SessionId, UserPrincipalName
| where AantalLanden > 1
```

Beide queries geven ruis bij gebruikers achter een VPN met wisselende exit-nodes
en bij mobiele gebruikers die van netwerk wisselen. Filter op ASN in plaats van
IP als dat in jouw omgeving te veel oplevert — `AutonomousSystemNumber` staat in
beide sign-in-tabellen.

## Waarom dit BEC is

Microsoft beschreef op 12 juli 2022 een campagne die sinds september 2021 meer
dan 10.000 organisaties probeerde te raken: AiTM-sites stalen wachtwoorden én
sessiecookies, omzeilden daarmee MFA, en de gestolen sessies werden gebruikt om
vanuit de mailbox BEC-campagnes tegen andere doelen te voeren. Microsoft meet in
datzelfde stuk dat het *"as little time as five minutes"* kon duren tussen de
diefstal en de eerste betalingsfraude. In de alert-grading-documentatie zegt
Microsoft het nog korter: *"BEC campaigns are an excellent example."* Het cookie
is aantrekkelijk omdat het een wachtwoordwijziging én een MFA-prompt overslaat —
precies de twee maatregelen waar een organisatie na een incident als eerste naar
grijpt.

## Referenties

- MITRE ATT&CK T1539: https://attack.mitre.org/techniques/T1539/
- Microsoft, alert grading voor session cookie theft (bron van beide alertnamen en van de hunting-queries): https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
- Microsoft, risk detections en licentieniveaus in Entra ID Protection: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, EntraIdSignInEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, AADSignInEventsBeta (afschaffing 19 okt 2026): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table
- Microsoft, SigninLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, CloudAppEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, AlertEvidence-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table
- Microsoft Security Blog, *From cookie theft to BEC* (12 juli 2022): https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
