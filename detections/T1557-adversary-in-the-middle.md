# T1557 — Adversary-in-the-Middle

| | |
|---|---|
| **MITRE-tactiek** | Credential Access, Collection |
| **Whitepaper-maatregelen** | 004 — Phishing-resistente multifactorauthenticatie (prioriteit Hoog)<br>005 — Microsoft Defender for Office 365 (prioriteit Midden) |
| **Verwante technieken** | [T1566.002](T1566.002-spearphishing-link.md) — de link die naar de proxy leidt<br>[T1539](T1539-steal-web-session-cookie.md) — het cookie dat de proxy onderschept |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../TESTING.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> Microsoft heeft een detectie die precies deze techniek dekt en volgens
> Microsoft *high precision* is: de Entra ID Protection-detectie **Attacker in
> the Middle**. Er is één probleem, en dat is niet klein: het gedocumenteerde
> licentieniveau is **Microsoft 365 E5 met Enterprise Mobility + Security E5** —
> als enige optie, dus zelfs Entra ID P2 alleen volstaat niet. Voor het gros van
> het mkb waar dit advies zich op richt is de detectie daarmee onbereikbaar.
> Wat je zonder E5 wél hebt zijn Safe Links-kliks en de sign-in logs; de rule
> die je daarop bouwt — klik op een link, kort daarna een geslaagde aanmelding
> vanaf een ASN die de gebruiker nooit gebruikt — is het bruikbare alternatief.

## Is er een Defender-alert voor?

**Ja, maar op E5-niveau.** Let op de naam: de Entra-detectie heet **Attacker in
the Middle**, niet "AiTM phishing attack".

| | |
|---|---|
| **Risk detection** | `Attacker in the Middle` (user risk, `riskEventType` = `attackerinTheMiddle`) |
| **Detectietype** | Offline |
| **Licentie** | **Microsoft 365 E5 met Enterprise Mobility + Security E5** — dit is de enige combinatie die Microsoft bij deze detectie noemt |
| **Risk level** | Zet de gebruiker op **High** risk |
| **Wat het is** | Microsoft: *"this high precision detection is triggered when an authentication session is linked to a malicious reverse proxy."* Microsoft raadt handmatig onderzoek aan; opruimen vergt een veilige wachtwoordreset of het intrekken van bestaande sessies. |
| **Bron** | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks |

Twee Defender XDR-alerts uit hetzelfde scenario, met een officieel
grading-playbook:

| Alert | Severity | Licentie |
|---|---|---|
| `Authentication request from AiTM-related phishing page` | Niet publiek gedocumenteerd | Niet publiek gedocumenteerd |
| `Stolen session cookie was used` | Niet publiek gedocumenteerd | Niet publiek gedocumenteerd |

Bron: https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert

Een derde naam, `Possible AiTM phishing attempt`, komt uit de Microsoft Security
Blog van 8 juni 2023 en is **niet teruggevonden in de Learn-alertreferentie**.
Behandel hem als een naam die in het portaal kan voorkomen, maar bouw er geen
detectielogica op.

Aan de mailkant, en alleen als Safe Links aanstaat:

| Alert policy | Severity | Licentie | Beperking |
|---|---|---|---|
| `A potentially malicious URL click was detected` | **High** | E5/G5 of Defender for Office 365 Plan 2 add-on | Vuurt bij een *verdict change*: de URL moet als kwaadaardig herkend zijn. Een verse AiTM-proxy op een net geregistreerd domein heeft op het moment van klikken vaak nog geen verdict. |
| `A user clicked through to a potentially malicious URL` | **High** | E5/G5 of Defender for Office 365 Plan 2 add-on | Vuurt alleen als de gebruiker de Safe Links-waarschuwingspagina bewust wegklikt. |

**Vervallen, niet meer op bouwen.** De Defender for Cloud Apps-policy
`Activity from anonymous IP addresses` is per juni 2025 uitgezet en volgens
Microsoft gemigreerd naar `Activity from a TOR IP address` en
`Anonymous proxy activity`. Ook `Activity from suspicious IP addresses` is
uitgezet. Beide stonden in veel inventarissen als AiTM-dekking.
Bron: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `UrlClickEvents` | Data connector **Microsoft Defender XDR**, *Connect events* → Defender for Office 365. Wordt alleen gevuld met Safe Links aan. |
| Microsoft Sentinel | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Data connector **Microsoft Entra ID**; sign-in logs vereisen Entra ID P1 of P2. |
| Microsoft Sentinel | `AADUserRiskEvents` | Zelfde connector; detectiedetails vereisen P2. |
| Defender XDR advanced hunting | `UrlClickEvents`, `EmailEvents` | Defender for Office 365; **advanced hunting vereist Plan 2**. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Vervangt `AADSignInEventsBeta` per 19 oktober 2026. |

Niet afhankelijk van maatregel 012 (UAL). Wel volledig afhankelijk van
maatregel 005: zonder Safe Links bestaat `UrlClickEvents` niet.

## KQL — Defender XDR: klik gevolgd door aanmelding vanaf een nieuwe ASN

```kql
// De AiTM-handtekening in telemetrie: een gebruiker klikt op een link, en
// binnen een uur is er een geslaagde aanmelding vanaf een netwerk waar die
// gebruiker de afgelopen 30 dagen nooit vandaan kwam. Er wordt bewust NIET op
// een phish-verdict gefilterd - juist de kliks zonder verdict zijn het gat dat
// de Defender-alerts openlaten.
let venster   = 60m;
let lookback  = 7d;
let bekend =
    EntraIdSignInEvents
    | where Timestamp between (ago(37d) .. ago(lookback))
    | where ErrorCode == 0
    | summarize BekendeIPs = make_set(IPAddress, 200) by AccountUpn;
let kliks =
    UrlClickEvents
    | where Timestamp > ago(lookback)
    | where Workload == "Email"
    | project KlikTijd = Timestamp, AccountUpn, Url, UrlChain, ActionType,
              IsClickedThrough, ThreatTypes, NetworkMessageId, ReportId;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where ErrorCode == 0
| where ClientAppUsed == "Browser"
| join kind=inner kliks on AccountUpn
| where Timestamp between (KlikTijd .. KlikTijd + venster)
| join kind=leftouter bekend on AccountUpn
| where isempty(BekendeIPs) or not(set_has_element(BekendeIPs, IPAddress))
| project KlikTijd, AanmeldTijd = Timestamp, AccountUpn, Url, ThreatTypes,
          IsClickedThrough, IPAddress, Country, City, Application,
          AuthenticationRequirement, ConditionalAccessStatus, SessionId, UserAgent
| order by AanmeldTijd desc
```

`SessionId` staat er niet voor niets in de output: die voer je meteen door in de
sessiediefstal-query uit [T1539](T1539-steal-web-session-cookie.md).

## KQL — Defender XDR: doorgeklikt ondanks de Safe Links-waarschuwing

Deze query komt uit de Microsoft-documentatie van de `UrlClickEvents`-tabel.

```kql
// Search for malicious links where user was allowed to proceed through
UrlClickEvents
| where ActionType == "ClickAllowed" or IsClickedThrough !="0"
| where ThreatTypes has "Phish"
| summarize by ReportId, IsClickedThrough, AccountUpn, NetworkMessageId, ThreatTypes, Timestamp
```

De volledige waardenlijst van `ActionType` staat **niet in de
schemadocumentatie**; `ClickAllowed` is de enige waarde die Microsoft daar
noemt. Gebruik in het Defender-portaal de ingebouwde schemareferentie om de
overige waarden voor jouw tenant vast te stellen voordat je erop filtert.

## KQL — Sentinel (SigninLogs)

Zonder `UrlClickEvents` — of als aanvulling erop — is dit het bruikbaarste
signaal dat met Entra ID P1 al beschikbaar is: een geslaagde aanmelding waarbij
Entra zelf al risico zag, of waarbij MFA is voldaan vanaf een onbekend netwerk.

```kql
// Geslaagde aanmeldingen vanaf een ASN die deze gebruiker in de voorgaande
// 30 dagen niet gebruikte. Bij AiTM meldt de aanvaller zich aan met een
// gestolen token vanaf zijn eigen infrastructuur, dus het ASN wijkt af terwijl
// de MFA-eis wél is voldaan - dat laatste maakt het juist verraderlijk.
let lookback = 7d;
let baseline =
    SigninLogs
    | where TimeGenerated between (ago(37d) .. ago(lookback))
    | where ResultType == "0"
    | summarize BekendeASN = make_set(AutonomousSystemNumber, 100) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where AuthenticationRequirement == "multiFactorAuthentication"
| join kind=leftouter baseline on UserPrincipalName
| where isempty(BekendeASN) or not(set_has_element(BekendeASN, AutonomousSystemNumber))
| project TimeGenerated, UserPrincipalName, IPAddress, AutonomousSystemNumber,
          Location, AppDisplayName, ClientAppUsed, UserAgent,
          ConditionalAccessStatus, RiskLevelDuringSignIn, RiskEventTypes_V2, SessionId
| order by TimeGenerated desc
```

En om de Entra-detectie op te halen als je de E5-combinatie wél hebt:

```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType == "attackerinTheMiddle"    // exacte riskEventType uit de Graph-documentatie
| project TimeGenerated, ActivityDateTime, UserPrincipalName, IpAddress, Location,
          RiskLevel, RiskState, RiskDetail, DetectionTimingType, Source, CorrelationId
| order by TimeGenerated desc
```

## Waarom dit BEC is

AiTM is de reden dat "wij hebben MFA" geen antwoord meer is. Microsoft
documenteerde op 12 juli 2022 een campagne die sinds september 2021 meer dan
10.000 organisaties probeerde te raken, waarbij de proxy zowel het wachtwoord
als het sessiecookie onderschepte en de aanvaller binnen *"as little time as
five minutes"* aan betalingsfraude begon. In juni 2023 volgde een campagne
waarin de aanvaller na de AiTM-stap een eigen MFA-methode registreerde, een
inboxregel aanmaakte die mail naar Archive verplaatste en als gelezen markeerde,
en van daaruit meer dan 16.000 phishingmails naar de contacten van het
slachtoffer stuurde. Dat is de volledige BEC-keten, en het startpunt is deze
techniek. Daarom staat maatregel 004 (phishing-resistente MFA) in het advies op
prioriteit Hoog: FIDO2 en Windows Hello for Business zijn de enige varianten die
een reverse proxy niet kan doorgeven.

## Referenties

- MITRE ATT&CK T1557: https://attack.mitre.org/techniques/T1557/
- Microsoft, risk detections en licentieniveaus (detectie *Attacker in the Middle*): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, alert grading voor session cookie theft: https://learn.microsoft.com/en-us/defender-xdr/session-cookie-theft-alert
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, UrlClickEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table
- Microsoft, EntraIdSignInEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, SigninLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, Defender for Cloud Apps anomaly detection policies (uitgezette legacy policies): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft Security Blog, *From cookie theft to BEC* (12 juli 2022): https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/
- Microsoft Security Blog, *Detecting and mitigating a multi-stage AiTM phishing and BEC campaign* (8 juni 2023): https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/
