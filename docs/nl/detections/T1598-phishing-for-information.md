# T1598 — Phishing for Information

| | |
|---|---|
| **MITRE-tactiek** | Reconnaissance |
| **Whitepaper-maatregel** | 001 — Security Awareness op OSINT (prioriteit Midden) |
| **Verwante techniek** | [T1566.002](T1566.002-spearphishing-link.md) — dezelfde mailstroom, maar dan mét payload |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> Het grootste deel van deze techniek gebeurt buiten je tenant: een aanvaller
> die LinkedIn, de bedrijfswebsite en handelsregisters leest laat in Microsoft
> 365 geen enkel spoor achter. Wat je wél kunt zien is de tweede helft — de mail
> waarin om informatie wordt gevraagd. Daar bestaat geen alert policy voor,
> omdat elke bestaande policy op een payload vuurt (URL, bijlage, malware) en
> een informatievraag juist geen payload heeft. Bouw dus een eigen rule op
> eerste-contact-mail zonder payload, en gebruik de Forms-alerts en de
> gebruikersmelding als losse vangnetten.

## Is er een Defender-alert voor?

**Nee, niet voor de handeling zelf.** Er is geen alert policy die vuurt op het
verzamelen van open bronnen, en ook geen die vuurt op een payloadloze
informatieaanvraag. Drie policies raken de techniek zijdelings.

| | |
|---|---|
| **Alert policy** | `Email reported by user as malware or phish` |
| **Standaard severity** | **Low** |
| **Licentie** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5, of Defender for Office 365 Plan 2 add-on |
| **Beperking** | Vuurt pas als een gebruiker zelf op **Report** drukt. Dat is precies het scenario waarin de recon-mail wél is opgemerkt; de gemiste mails leveren niets op. Severity **Low** betekent dat er in de praktijk niemand naar kijkt, en ophogen is bij een System-policy niet aantoonbaar mogelijk — zie de README. |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

| | |
|---|---|
| **Alert policy** | `Form blocked due to potential phishing attempt` |
| **Standaard severity** | **High** |
| **Licentie** | E1, E3/F3, of E5 |
| **Wat het is** | Vuurt op een Microsoft Forms-formulier dat door de eigen organisatie is gemaakt en dat verdacht gedrag vertoont. Relevant omdat een Forms-formulier ("vul even je gegevens in") een gebruikelijke drager is voor een informatievraag. Dekt alleen Forms, niet e-mail. |

Een tweede Forms-policy, `Form flagged and confirmed as phishing` (**High**,
E1, E3/F3, of E5), vuurt nadat Microsoft een gemeld formulier als phishing heeft
bevestigd.

**Wat er niet is, en wat je dus niet moet verwachten:** er bestaat geen alert
policy in de categorie *Threat management* die vuurt op een inkomend bericht
zonder URL en zonder bijlage, hoe gericht de vraag ook is. Het volledige
overzicht van standaard alert policies staat in de Microsoft-documentatie
hierboven; er zit geen enkele bij die deze handeling dekt.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `EmailEvents` | Data connector **Microsoft Defender XDR**, onder *Connect events* de Defender for Office 365-tabellen aanvinken. Vereist Defender for Office 365. |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365 uitgerold in de Defender-portal. **Advanced hunting zelf zit in Defender for Office 365 Plan 2** — met alleen Plan 1 heb je Real-time detections en geen hunting-tabellen. |

Deze queries zijn niet afhankelijk van de Unified Audit Log (maatregel 012);
`EmailEvents` komt uit de filterstack van Defender for Office 365, niet uit de
UAL. Heb je alleen EOP (geen Defender for Office 365), dan bestaat de tabel niet
en is message trace in het Defender-portaal je enige bron — zonder KQL.

## KQL — Sentinel en Defender XDR (EmailEvents)

Dezelfde tabel en dezelfde kolomnamen in beide platforms; de query hoeft niet
per platform te verschillen. Alleen `Timestamp` heet in Sentinel óók
`TimeGenerated`.

```kql
// Eerste contact met een externe afzender, zonder URL en zonder bijlage.
// Die combinatie is ongewoon voor gewone zakelijke mail en typisch voor een
// verkennende vraag ("wie doet bij jullie de betalingen?", "kun je het
// bankrekeningnummer bevestigen?"). De filterstack heeft er geen verdict op
// gegeven, dus geen enkel Defender-alert vuurt hierop.
let lookback = 30d;
let eigenDomeinen = dynamic(["eigendomein.nl", "eigendomein.com"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where IsFirstContact == 1              // eerste keer dat deze afzender deze ontvanger mailt
| where AttachmentCount == 0 and UrlCount == 0   // geen payload = geen alert-trigger
| where DeliveryAction == "Delivered"    // alleen wat de gebruiker echt heeft gezien
| where isempty(ThreatTypes)             // de stack vond er niets van; dat is de kern van het probleem
| where SenderFromDomain !in~ (eigenDomeinen)
// Envelope- en From-domein die uit elkaar lopen is een extra signaal, geen filter:
| extend EnvelopeMismatch = tolower(SenderMailFromDomain) != tolower(SenderFromDomain)
| project Timestamp, SenderFromAddress, SenderFromDomain, SenderMailFromDomain,
          EnvelopeMismatch, RecipientEmailAddress, Subject, SenderIPv4, NetworkMessageId
| order by Timestamp desc
```

### Aanscherpen op de mensen die er echt toe doen

Bovenstaande query levert in een normale tenant te veel op. BEC-verkenning
richt zich op finance, directie en beheer; scope de rule daarop.

```kql
let doelwitten = dynamic([
    "crediteuren@eigendomein.nl", "finance@eigendomein.nl",
    "directie@eigendomein.nl"                                  // <-- aanpassen
]);
| where tolower(RecipientEmailAddress) in~ (doelwitten)
```

### Aanscherpen op lijkende afzenderdomeinen

Een tweede, veel scherpere variant: eerste contact vanaf een domein waar de
eigen merknaam in zit maar dat niet van jou is (typosquat, `-bv`-variant,
andere TLD).

```kql
let merk = "eigenmerk";                  // <-- aanpassen, zonder TLD
let eigenDomeinen = dynamic(["eigendomein.nl", "eigendomein.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where SenderFromDomain has merk
| where SenderFromDomain !in~ (eigenDomeinen)
| summarize Berichten = count(),
            Ontvangers = dcount(RecipientEmailAddress),
            Eerste = min(Timestamp), Laatste = max(Timestamp)
          by SenderFromDomain, SenderFromAddress
| order by Berichten desc
```

## Waarom dit BEC is

Geloofwaardigheid is de hele aanval. Het FBI Internet Crime Complaint Center
telde tussen oktober 2013 en december 2023 wereldwijd 305.033 BEC-incidenten met
een blootgestelde schade van 55.499.915.582 dollar, en beschrijft daarbij expliciet
dat criminelen een gecompromitteerd zakelijk mailaccount gebruiken om
persoonsgegevens op te vragen waarmee ze vervolgens *andere* accounts
compromitteren (I-091124-PSA, 11 september 2024). De informatievraag is dus geen
losse ergernis maar de eerste schakel. MITRE plaatst T1598 in de tactiek
Reconnaissance, vóór elke technische handeling in de tenant.

## Referenties

- MITRE ATT&CK T1598: https://attack.mitre.org/techniques/T1598/
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, EmailEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, Defender for Office 365 Plan 1 vs Plan 2: https://learn.microsoft.com/en-us/defender-office-365/mdo-about
- Microsoft, Defender XDR-data naar Sentinel: https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender
- FBI IC3 I-091124-PSA, *Business Email Compromise: The $55 Billion Scam*: https://www.ic3.gov/PSA/2024/PSA240911
