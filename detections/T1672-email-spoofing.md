# T1672 — E-mail Spoofing

| | |
|---|---|
| **MITRE-tactiek** | Resource Development (indeling van het advies) |
| **Whitepaper-maatregelen** | 002 — SPF, DKIM en DMARC correct configureren (prioriteit Midden)<br>003 — Direct Send-functie uitschakelen (prioriteit Hoog) |
| **Let op de ID** | `https://attack.mitre.org/techniques/T1672/` redirect inmiddels naar **T1684.002 — Social Engineering: Email Spoofing** (tactiek *Stealth*). Het advies gebruikt T1672; dat is de ID zoals die in april 2026 gold. Beide verwijzen naar dezelfde techniek. |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../TESTING.md) |

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

```kql
// Inkomend bericht dat een van je eigen domeinen als afzender voert en dat
// NIET via een connector is binnengekomen. Dat is precies de handtekening van
// Direct Send: het bericht komt ongeauthenticeerd binnen op de MX-endpoint en
// er is dus geen connector aan te wijzen. Legitieme interne mail is
// Intra-org, niet Inbound.
let lookback = 30d;
let eigenDomeinen = dynamic(["eigendomein.nl", "eigendomein.com"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (eigenDomeinen)
| where isempty(Connectors)              // geen connector = niet via een geauthenticeerd pad
| project Timestamp, SenderFromAddress, SenderMailFromAddress, SenderIPv4, SenderIPv6,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          AuthenticationDetails, NetworkMessageId
| order by Timestamp desc
```

Heb je Direct Send bewust nog aanstaan voor printers of een lijnapplicatie,
sluit die bronnen dan uit op IP en monitor het volume — het advies vraagt daar
expliciet om:

```kql
let toegestaneIPs = dynamic(["203.0.113.10", "203.0.113.11"]);   // <-- aanpassen
| where SenderIPv4 !in (toegestaneIPs)
```

En om afwijkend volume vanaf die vertrouwde adressen te zien:

```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound" and isempty(Connectors)
| where SenderIPv4 in (dynamic(["203.0.113.10", "203.0.113.11"]))   // <-- aanpassen
| summarize Berichten = count() by bin(Timestamp, 1h), SenderIPv4
| order by Berichten desc
```

## KQL — falende e-mailauthenticatie op je eigen domein

```kql
// Berichten die zich voordoen als jouw domein en waarbij DMARC, SPF, DKIM of
// composite authentication faalt. AuthenticationDetails is één stringkolom met
// de verdicten van alle protocollen; er is geen aparte kolom per protocol, dus
// het filter is een has_any op de tekst.
let lookback = 14d;
let eigenDomeinen = dynamic(["eigendomein.nl", "eigendomein.com"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where tolower(SenderFromDomain) in~ (eigenDomeinen)
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

```kql
| extend StackZagHet = EmailActionPolicy == "Anti-phishing spoof"
| where DeliveryLocation == "Inbox/Folder"
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
