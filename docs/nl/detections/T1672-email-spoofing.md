# T1672 — E-mail Spoofing

| | |
|---|---|
| **MITRE-tactiek** | Resource Development (indeling van het advies) |
| **Whitepaper-maatregelen** | 002 — SPF, DKIM en DMARC correct configureren (prioriteit Midden)<br>003 — Direct Send-functie uitschakelen (prioriteit Hoog) |
| **Let op de ID** | `https://attack.mitre.org/techniques/T1672/` redirect inmiddels naar **T1684.002 — Social Engineering: Email Spoofing** (tactiek *Stealth*). Het advies gebruikt T1672; dat is de ID zoals die in april 2026 gold. Beide verwijzen naar dezelfde techniek. |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> Microsoft doet aan de preventiekant veel: composite authentication, spoof
> intelligence en het anti-phishingbeleid bepalen samen of een vervalst bericht
> in de Inbox, in Junk of in quarantaine belandt — en dat zit in elke tenant met
> cloudmailboxen, zonder add-on. Maar dat is een *bezorgbeslissing*, geen alert:
> er is geen enkele standaard alert policy die vuurt op een inkomend bericht dat
> jouw eigen domein vervalst, en ook geen op misbruik van Direct Send. De echte
> maatregel is preventief (`Set-OrganizationConfig -RejectDirectSend $true` en
> DMARC op `p=reject`); de detectie eromheen bouw je zelf op `EmailEvents`.

## Is er een Defender-alert voor?

**Nee.** In de lijst met standaard alert policies staat geen policy voor
inkomende spoofing of voor Direct Send. Wat er wél is, is preventie en een paar
policies aan de uitgaande kant.

### Preventie (geen alert, wel gratis)

| | |
|---|---|
| **Mechanisme** | Composite authentication (`compauth`) + spoof intelligence + anti-phishingbeleid |
| **Licentie** | De ingebouwde beveiliging voor alle cloudmailboxen (EOP) — geen add-on nodig |
| **Hoe het eruitziet** | Intra-org spoofing: `Authentication-Results: ... compauth=fail reason=6xx` en `X-Forefront-Antispam-Report: ...CAT:SPOOF;...SFTY:9.11`. Cross-domain: `compauth=fail reason=000/001` en `SFTY:9.22`. |
| **Belangrijke nuance** | Microsoft: *"a composite authentication failure doesn't directly result in blocking a message."* Een `compauth=fail` is dus een signaal, geen verdict. |
| **Bron** | https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about |

### Direct Send afzetten

| | |
|---|---|
| **Instelling** | `Set-OrganizationConfig -RejectDirectSend $true` (Exchange Online PowerShell, type `Boolean`) |
| **Effect** | Ongeauthenticeerde berichten die het domein als afzender voeren worden geweigerd. |
| **Alert** | Geen. Er is geen alert policy die meldt dat Direct Send gebruikt of misbruikt wordt; die zichtbaarheid moet uit `EmailEvents` komen. |
| **Bron** | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig |

### Policies die er in de buurt komen (allemaal uitgaand)

| Alert policy | Severity | Licentie | Waarom het jouw techniek níet dekt |
|---|---|---|---|
| `Suspicious connector activity` | **High** | E1/F1/G1, E3/F3/G3, of E5/G5 | Vuurt op een gecompromitteerde *inbound connector*, niet op een gespooft bericht. |
| `Tenant restricted from sending unprovisioned email` | **High** | E1/F1/G1, E3/F3/G3, of E5/G5 | Vuurt als jóuw tenant te veel mail vanaf niet-geregistreerde domeinen stuurt. Signaleert misbruik ná de feiten. |
| `Suspicious tenant sending patterns observed` | **High** | E1/F1/G1, E3/F3/G3, of E5/G5 | Idem: uitgaand, en op tenantniveau. |

Bron voor severities en licenties: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `EmailEvents` | Data connector **Microsoft Defender XDR**, *Connect events* met de Defender for Office 365-tabellen. |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365 uitgerold; **advanced hunting vereist Defender for Office 365 Plan 2**. |

Niet afhankelijk van maatregel 012 (UAL). Wel volledig afhankelijk van Defender
for Office 365: in een EOP-only tenant bestaat `EmailEvents` niet en blijft
alleen message trace in het Defender-portaal over.

## KQL — Direct Send-misbruik (EmailEvents, beide platforms)

<!-- query
platform: both
name: Inbound mail from your own domain that did not arrive through a connector (Direct Send)
technique: T1672
severity: Medium
tactics: [ResourceDevelopment]
interval: PT1H
lookback: P1D
parameters: [ownDomains]
deployable: true
-->

```kql
// Inkomend bericht dat een van je eigen domeinen als afzender voert en dat
// NIET via een connector is binnengekomen. Dat is precies de handtekening van
// Direct Send: het bericht komt ongeauthenticeerd binnen op de MX-endpoint en
// er is dus geen connector aan te wijzen. Legitieme interne mail is
// Intra-org, niet Inbound.
let lookback = 1d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (ownDomains)
| where isempty(Connectors)              // geen connector = niet via een geauthenticeerd pad
| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderIPv6,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          AuthenticationDetails, NetworkMessageId
| order by Timestamp desc
```

## KQL — inventarisatie vóór je de maatregel aanzet

Maatregel 003 is één boolean, maar hij kan legitieme mailstromen breken:
printers, scanners, een boekhoudpakket dat facturen mailt, een alarmsysteem.
Inventariseer dus eerst wie er vandaag gebruik van maakt. Deze query telt niet
de berichten maar de *bronnen*, want dat is de lijst waarop je een besluit neemt.

<!-- query
platform: both
name: Direct Send inventory by source IP before enabling RejectDirectSend
technique: T1672
severity: Informational
tactics: [ResourceDevelopment]
interval: P1D
lookback: P30D
parameters: [ownDomains]
deployable: false
-->

```kql
// Inventarisatie: welke bronnen gebruiken Direct Send, hoe vaak, en sinds wanneer.
// Draai dit VOORDAT je RejectDirectSend omzet. Elke regel is een apparaat of
// applicatie die na de wijziging een 550 5.7.68 gaat krijgen.
let lookback = 30d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (ownDomains)
| where isempty(Connectors)
| extend Bron = coalesce(SenderIPv4, SenderIPv6)
| summarize Berichten          = count(),
            Afzenders          = make_set(SenderFromAddress, 10),
            Onderwerpen        = make_set(Subject, 5),
            Ontvangers         = dcount(RecipientEmailAddress),
            EersteKeer         = min(Timestamp),
            LaatsteKeer        = max(Timestamp),
            Bezorgd            = countif(DeliveryAction == "Delivered"),
            Tegengehouden      = countif(DeliveryAction != "Delivered")
        by Bron
| extend DagenActief = datetime_diff("day", LaatsteKeer, EersteKeer)
| order by Berichten desc
```

Hoe je de uitkomst leest:

- **Weinig bronnen, hoog volume, elke dag actief, één vast afzenderadres** — dat
  is het profiel van een printer of lijnapplicatie. Zet die op de uitzonderingslijst
  of, beter, verhuis ze naar een geauthenticeerd pad voordat je de knop omzet.
- **Veel losse IP-adressen, lage aantallen, wisselende afzenders** — dat is geen
  printer. Dat is misbruik, en dan is de maatregel precies waarvoor hij bedoeld is.
- **Een lege uitkomst** is het beste antwoord: niemand gebruikt het, de knop kan om.

**Let op de licentie.** `EmailEvents` en de rest van de e-mailtabellen in
advanced hunting zitten in **Defender for Office 365 Plan 2**, en Plan 2 zit
alleen in E5, A5 en GCC G5. Microsoft 365 Business Premium krijgt Plan 1, en
per 1 juli 2026 geldt hetzelfde voor Office 365 E3 en Microsoft 365 E3. In de
featuretabel van de service description staat "Integration with Microsoft
Defender XDR" voor Plan 1 op **No**; Plan 1 heeft Real-time detections, Plan 2
heeft Threat Explorer en advanced hunting. Business Premium-klanten kunnen Plan 2
los bijkopen via de Defender Suite-add-on, maar zonder die stap is deze query
niet beschikbaar. Dat is precies het patroon dat in de [kernbevinding](../index.md)
staat: de zichtbaarheid bestaat, maar achter een licentie die de doelgroep van
dit advies meestal niet heeft.

Zonder Plan 2 doe je dezelfde inventarisatie met een **message trace** in het
Exchange admin center (Mail flow > Message trace > Start a trace):

| Veld | Waarde |
|---|---|
| Senders | `*@jouwdomein.nl` — wildcards mogen, maar één per waarde |
| Direction | `Inbound` (onder Detailed search options) |
| Time range | tot 90 dagen |
| Report type | **Enhanced summary report** |

Het moet de *enhanced summary* zijn: alleen die CSV bevat `connector_id`,
`original_client_ip` en `directionality`. De gewone summary heeft ze niet. Die
rapportvorm eist ook een filter op afzender, ontvanger of message-ID — het
wildcard-afzenderfilter hierboven voldoet daaraan.

In de CSV is de regel simpel: **`connector_id` leeg en `directionality` inbound =
Direct Send**. Groepeer daarna op `original_client_ip` en je hebt dezelfde lijst
als de KQL hierboven.

Twee beperkingen: `original_client_ip` wordt maar **10 dagen** bewaard, dus over
een langer venster zie je wél dát het gebeurt maar niet meer waarvandaan. En het
rapport komt als download die uren kan duren. Trager en handmatiger dan de KQL
dus, maar het zit in elke tenant met cloudmailboxen — en dat is voor de doelgroep
van dit advies het verschil tussen wel en niet kunnen kijken.

Heb je Direct Send bewust nog aanstaan voor printers of een lijnapplicatie,
sluit die bronnen dan uit op IP en monitor het volume — het advies vraagt daar
expliciet om:

<!-- query
platform: both
name: Direct Send filter excluding known printer and line-of-business IP addresses
technique: T1672
severity: Medium
tactics: [ResourceDevelopment]
interval: PT1H
lookback: P1D
parameters: [allowedIPs]
deployable: true
-->

```kql
let allowedIPs = dynamic(["203.0.113.10", "203.0.113.11"]);   // <-- aanpassen
| where SenderIPv4 !in (allowedIPs)
```

En om afwijkend volume vanaf die vertrouwde adressen te zien:

<!-- query
platform: both
name: Message volume from the IP addresses allowed to use Direct Send
technique: T1672
severity: Informational
tactics: [ResourceDevelopment]
interval: P1D
lookback: P30D
parameters: []
deployable: true
-->

```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound" and isempty(Connectors)
| where SenderIPv4 in (dynamic(["203.0.113.10", "203.0.113.11"]))   // <-- aanpassen
| summarize Messages = count() by bin(Timestamp, 1h), SenderIPv4
| order by Messages desc
```

## KQL — falende e-mailauthenticatie op je eigen domein

<!-- query
platform: defender-xdr
name: Inbound mail spoofing your own domain that fails SPF, DKIM, DMARC or composite authentication
technique: T1672
severity: Medium
tactics: [ResourceDevelopment]
interval: PT1H
lookback: P14D
parameters: [ownDomains]
deployable: false
-->

```kql
// Berichten die zich voordoen als jouw domein en waarbij DMARC, SPF, DKIM of
// composite authentication faalt. AuthenticationDetails is één stringkolom met
// de verdicten van alle protocollen; er is geen aparte kolom per protocol, dus
// het filter is een has_any op de tekst.
let lookback = 14d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
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

Twee hulpkolommen die de triage sneller maken, allebei gedocumenteerd in het
`EmailEvents`-schema:

- `EmailActionPolicy` bevat bij een spoofverdict de waarde `Anti-phishing spoof`.
  Daarmee scheid je "de stack zag het en handelde" van "de stack zag het niet".
- `DeliveryLocation` laat zien of het bericht ondanks het verdict in `Inbox/Folder`
  is geland. Dat zijn de gevallen die er echt toe doen.

<!-- query
platform: defender-xdr
name: Spoofed mail split by whether the filtering stack acted and where it landed
technique: T1672
severity: Low
tactics: [ResourceDevelopment]
interval: PT1H
lookback: P14D
parameters: []
deployable: false
-->

```kql
| extend StackCaughtIt = EmailActionPolicy == "Anti-phishing spoof"
| where DeliveryLocation in~ ("Inbox/folder", "Junk")
```

## Waarom dit BEC is

Microsoft gebruikt in de eigen anti-spoofingdocumentatie een gespooft
`contoso.com` als schoolvoorbeeld van BEC: *"Messages from spoofed senders might
trick the recipient into giving up their credentials, downloading malware, or
replying to a message with sensitive content (known as business email compromise
or BEC)."* MITRE noemt bij deze techniek Direct Send met naam en toenaam:
aanvallers misbruiken de Direct Send-functie van Microsoft 365 om interne
gebruikers te spoofen door mail te versturen zonder authenticatie. Precies de
maatregel die het advies onder ID 003 op prioriteit Hoog zet.

## Referenties

- MITRE ATT&CK T1684.002 (Social Engineering: Email Spoofing), waar T1672 naartoe redirect: https://attack.mitre.org/techniques/T1684/002/
- MITRE ATT&CK T1672: https://attack.mitre.org/techniques/T1672/
- Microsoft, anti-spoofing en composite authentication: https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-spoofing-about
- Microsoft, e-mailauthenticatie (SPF/DKIM/DMARC): https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about
- Microsoft, `Set-OrganizationConfig` (parameter `RejectDirectSend`): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-organizationconfig
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, EmailEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
