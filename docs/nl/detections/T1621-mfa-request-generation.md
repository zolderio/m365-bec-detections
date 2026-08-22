# T1621 — Multi-Factor Authentication Request Generation

| | |
|---|---|
| **MITRE-tactiek** | Credential Access |
| **Whitepaper-maatregelen** | 004 — Phishing-resistente multifactorauthenticatie (prioriteit Hoog)<br>005 — Microsoft Defender for Office 365 (prioriteit Midden) |
| **Verwante techniek** | [T1110.003](T1110.003-password-spraying.md) — hoe het wachtwoord dat hieraan voorafgaat is gevonden |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> Er is géén alert policy voor MFA-fatigue, en de twee Entra-detecties die het
> raken (`Suspicious MFA authentication approval` en `User reported suspicious
> activity`) vereisen allebei Microsoft Entra ID P2. Het goede nieuws is dat het
> ruwe signaal juist heel schoon is en met Entra ID P1 al beschikbaar: een reeks
> aanmeldpogingen met `ResultType` **500121** op één account binnen een kort
> venster is per definitie afwijkend, want een gebruiker die zelf inlogt drukt
> één keer op weigeren en niet twaalf keer. Bouw die rule, en zet daarnaast
> **Report suspicious activity** aan — dat is een instelling in het
> Authentication methods-beleid, geen licentie.

## Is er een Defender-alert voor?

**Nee, geen alert policy.** In de lijst met standaard alert policies staat niets
over MFA. De dekking zit volledig in Entra ID Protection, en die is premium.

| | |
|---|---|
| **Risk detection** | `Suspicious MFA authentication approval` (sign-in risk, `riskEventType` = `authenticatorPhishing`) |
| **Detectietype** | Real-time |
| **Licentie** | **Microsoft Entra ID P2** |
| **Risk level** | Markeert de aanmeldpoging als **High risk** |
| **Wat het is** | Vuurt op sessies met *Password + MFA* plus telemetrie uit de Microsoft Authenticator-app, waarbij onbekende eigenschappen (ASN, browser, device, GPS) op social engineering wijzen. Microsoft analyseert daarbij de afstand tussen het apparaat dat de authenticatie *aanvraagt* en het apparaat dat hem *goedkeurt*. |
| **Beperking** | Werkt alleen als de gebruiker de Microsoft Authenticator-app gebruikt. SMS- en telefoongebaseerde MFA — precies wat maatregel 004 wil uitfaseren — levert deze telemetrie niet. |
| **Bron** | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks |

| | |
|---|---|
| **Risk detection** | `User reported suspicious activity` (user risk, `riskEventType` = `userReportedSuspiciousActivity`) |
| **Detectietype** | Offline |
| **Licentie** | De ID Protection-referentie classificeert deze detectie als **Premium** (Entra ID P2). De MFA-instellingenpagina beschrijft echter óók hoe P1-tenants de melding terugvinden in het Risk detections report. **Die twee pagina's spreken elkaar tegen; niet geverifieerd welke in de praktijk geldt.** Ga uit van P2 tot je het in je eigen tenant hebt gezien. |
| **Voorwaarde** | De feature **Report suspicious activity** moet aanstaan: *Entra ID > Authentication methods > Settings*. Staat standaard op *Microsoft managed*, en dan is hij uit. |
| **Wat het oplevert** | Gebruiker gaat naar **High User Risk**. In het Risk detections report als detectietype *User Reported Suspicious Activity*, risk level *High*, source *End user reported*. In de sign-in logs staat het resultaatdetail als **MFA denied**. |
| **Beperking** | Microsoft: *"A user isn't reported as High Risk if they perform passwordless authentication."* |
| **Bron** | https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings |

**Vervallen.** De legacy features *Block/unblock users*, *Fraud alert* en
*Notifications* zijn op 1 maart 2025 verwijderd en vervangen door
*Report suspicious activity*. Verwijzingen naar Fraud alert in oudere runbooks
zijn dood.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `SigninLogs` | Data connector **Microsoft Entra ID**. Microsoft: *"A Microsoft Entra ID P1 or P2 license is required to ingest sign-in logs into Microsoft Sentinel."* |
| Microsoft Sentinel | `AADUserRiskEvents` | Zelfde connector (log type *User risk events*); detectiedetails vereisen P2. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | **Entra ID P2**. Vervangt `AADSignInEventsBeta` per 19 oktober 2026. |

Niet afhankelijk van maatregel 012 (UAL).

## De foutcode waar alles om draait

| | |
|---|---|
| **Code** | `500121` |
| **Betekenis** | *"Authentication failed during strong authentication request."* Microsoft: *"The user didn't complete the MFA prompt. They may have decided not to authenticate, timed out while doing other work, or has an issue with their authentication setup."* |
| **Bron** | https://login.microsoftonline.com/error?code=500121 |
| **Let op** | 500121 staat **niet** in de AADSTS-foutcodereferentie op Microsoft Learn; de omschrijving hierboven komt uit de foutcode-lookup van Microsoft zelf. |

Eén 500121 is dus geen incident — dat is een gebruiker die zijn telefoon niet
bij de hand had. Het patroon is het signaal: veel van deze codes op één account
in een kort venster, vanaf een IP dat de gebruiker niet kent.

## KQL — Sentinel (SigninLogs)

```kql
// MFA-fatigue: een reeks mislukte MFA-uitdagingen op hetzelfde account binnen
// een kort window. Het wachtwoord klopt al (anders was de fout 50126 geweest
// en was de MFA-stap nooit bereikt) - dat maakt dit een post-credential-signaal
// en dus urgenter dan een mislukte aanmelding.
let window = 15m;
let threshold = 5;                       // <-- afstemmen; begin hoog en zak af
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

### De variant die er echt toe doet: fatigue gevolgd door succes

```kql
// Een reeks geweigerde MFA-prompts en daarna een geslaagde aanmelding vanaf
// hetzelfde IP: de gebruiker is uiteindelijk gezwicht. Dit is de query die je
// als analytic rule wilt hebben, niet die hierboven.
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

### De gebruiker die het zelf meldt

Staat *Report suspicious activity* aan, dan schrijft Entra het resultaatdetail
**MFA denied** in `AuthenticationDetails`. Dat is één stringkolom met de
uitkomst van elke authenticatiestap, dus een `has` is het juiste filter.

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationDetails has "MFA denied"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName,
          ResultType, ResultDescription, AuthenticationDetails,
          AuthenticationRequirement, RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated desc
```

En de risicodetectie zelf, als je P2 hebt:

```kql
AADUserRiskEvents
| where TimeGenerated > ago(30d)
| where RiskEventType in ("userReportedSuspiciousActivity", "authenticatorPhishing")
| project TimeGenerated, ActivityDateTime, UserPrincipalName, IpAddress, Location,
          RiskEventType, RiskLevel, RiskState, RiskDetail, DetectionTimingType, Source
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (EntraIdSignInEvents)

```kql
// Zelfde logica. ErrorCode is hier een int in plaats van een string.
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

## Waarom dit BEC is

FBI, CISA, NSA, CSE, AFP en ASD's ACSC beschrijven in joint advisory
**AA24-290A** (16 oktober 2024) hoe actoren na een geslaagde password spray
*"send MFA requests to legitimate users seeking acceptance of the request"*, en
noemen de techniek bij naam: *"bombarding users with mobile phone push
notifications until the user either approves the request by accident or stops
the notifications — is known as 'MFA fatigue' or 'push bombing' [T1621]"*.
Dezelfde advisory beschrijft dat de aanvallers daarna hun eigen apparaat als
MFA-methode registreren om de toegang vast te houden. Dat is waarom dit signaal
telt: elke 500121-reeks is een aanvaller die het wachtwoord al héeft.

## Referenties

- MITRE ATT&CK T1621: https://attack.mitre.org/techniques/T1621/
- Microsoft, risk detections en licentieniveaus in Entra ID Protection: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, *Report suspicious activity* configureren: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings
- Microsoft, foutcode 500121: https://login.microsoftonline.com/error?code=500121
- Microsoft, AADSTS-foutcodereferentie (waar 500121 níet in staat): https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Microsoft, SigninLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, AADUserRiskEvents-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents
- Microsoft, EntraIdSignInEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, Entra ID-data naar Sentinel (licentievereisten): https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory
- CISA/FBI AA24-290A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a
