# T1204 — User Execution

| | |
|---|---|
| **Naam in het advies** | User Execution |
| **Naam in MITRE ATT&CK** | User Execution |
| **MITRE-tactiek** | Execution (TA0002) |
| **Whitepaper-maatregel** | 008 — Blokkeren van riskante extensies (prioriteit Hoog) |
| **Verwante techniek** | [T1059](T1059-execution-via-malicious-scripts.md) — dezelfde maatregel, de endpointkant in plaats van de mailkant |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../TESTING.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> De twee alert policies die de klik op een kwaadaardige link echt dekken
> (`A potentially malicious URL click was detected` en `A user clicked through
> to a potentially malicious URL`, beide **High**) vereisen E5/G5 of een
> Defender for Office 365 Plan 2-add-on. Wat je in E1/E3 overhoudt, is
> `Email messages containing malicious file removed after delivery` op
> **Informational**, en dat vuurt pas nádat ZAP de mail heeft weggehaald — te
> laat en te stil. En het scenario waar het advies specifiek voor waarschuwt,
> de `.html`-bijlage, heeft helemaal geen alert: `htm`, `html` en `js` zitten
> **niet** in de standaardlijst van het common attachments filter. Severity
> ophogen is hier geen uitweg, want de instellingen van een standaard alert
> policy zijn niet te wijzigen (zie hieronder). Heb je wél MDO Plan 2, zet de
> twee klik-alerts dan aan als aanvulling; de KQL blijft nodig voor de bijlagen.

## Is er een Defender-alert voor?

**Voor de klik wel, voor de bijlage niet — en de klik-alerts kosten een
add-on.**

| Alert policy | Standaard severity | Licentie |
|---|---|---|
| `A potentially malicious URL click was detected` | **High** | E5/G5 of Defender for Office 365 Plan 2 add-on |
| `A user clicked through to a potentially malicious URL` | **High** | E5/G5 of Defender for Office 365 Plan 2 add-on |
| `Email messages containing malicious file removed after delivery` | **Informational** | E1/F1/G1, E3/F3/G3 of E5/G5 |
| `Email messages containing malicious URL removed after delivery` | **Informational** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 of Defender for Office 365 Plan 2 add-on |
| `Messages containing malicious entity not removed after delivery` | **Medium** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 of Defender for Office 365 Plan 2 add-on |
| `Email reported by user as malware or phish` | **Low** | E3/G3, Microsoft 365 Business Premium, Defender for Office 365 Plan 1 add-on, E5/G5 of Defender for Office 365 Plan 2 add-on |

### De severity van een standaardpolicy kun je niet ophogen

Dit wijkt af van wat vaak wordt aangenomen. Microsoft over de default alert
policies: *"You can turn off these policies (or back on again), set up a list of
recipients to send email notifications to, and set a daily notification limit.
**The other settings for these policies can't be edited.**"* En bij
`Set-ProtectionAlert`: *"You can't use this cmdlet to edit default alert
policies. You can only modify alerts that you created using the
New-ProtectionAlert cmdlet."*

Wil je dezelfde activiteit op een hogere severity, dan maak je met
`New-ProtectionAlert` een **eigen** alert policy met `-Severity High`. Let op de
licentiegrens die daarbij hoort: alert policies op basis van een drempelwaarde
of op "ongebruikelijke activiteit" vereisen E5/G5 of een add-on; met E1/F1/G1 en
E3/F3/G3 kun je alleen policies maken die vuren bij *elke* keer dat de
activiteit voorkomt. Deze route is **niet geverifieerd** tegen een tenant.

### Het common attachments filter blokkeert .html en .js niet standaard

Het filter zit in de anti-malware policy en dus in EOP — beschikbaar in elke
organisatie met cloudmailboxen, geen add-on nodig. Maar de standaardlijst is:

> `ace, ani, apk, app, appx, arj, bat, cab, cmd, com, deb, dex, dll, docm, elf,
> exe, hta, img, iso, jar, jnlp, kext, lha, lib, library, lnk, lzh, macho, msc,
> msi, msix, msp, mst, pif, ppa, ppam, reg, rev, scf, scr, sct, sys, uif, vb,
> vbe, vbs, vxd, wsc, wsf, wsh, xll, xz, z`

`vbs` staat erin, `htm`, `html`, `js` en `jse` **niet** — die staan in de lijst
met aanvullende types die je zelf moet aanzetten. Dat is exact de maatregel die
het advies vraagt en het is een handmatige handeling. Het filter doet wel *true
type matching*: een `.exe` die is hernoemd naar `.txt` wordt alsnog als `exe`
herkend, en `html` staat in de lijst met ondersteunde true types.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `EmailEvents`, `EmailAttachmentInfo` | Data connector **Microsoft Defender XDR** met advanced hunting event streaming aan. Ingestie van deze tabellen is betaald verkeer. |
| Defender XDR advanced hunting | `EmailEvents`, `EmailAttachmentInfo` | **Defender for Office 365** (minimaal Plan 1). Microsoft: *"This advanced hunting table is populated by records from Defender for Office 365."* Retentie 30 dagen. |

Consequentie voor een EOP-only organisatie: er is dan géén e-mailtabel in
advanced hunting en dus geen queryroute. Wat overblijft is het message trace-
en quarantainerapport in de portal, en de logging van de transportregel zelf.
`UrlClickEvents` (de klikkant) is niet in deze detectie gebruikt omdat die
tabel Safe Links vereist en dus MDO.

## KQL — Defender XDR advanced hunting (EmailAttachmentInfo + EmailEvents)

```kql
// Bijlagen met een script- of HTML-extensie die daadwerkelijk in een mailbox
// zijn beland. De filterlogica staat bewust op DeliveryLocation en niet op
// ThreatTypes: de hele reden dat het advies deze extensies laat blokkeren, is
// dat de filterstack ze niet als threat markeert.
let lookback = 7d;
let riskante_extensies = dynamic(["html","htm","shtml","xhtml","svg",
                                  "js","jse","vbs","vbe","wsf","hta","chm","iso","img"]);
EmailAttachmentInfo
| where Timestamp > ago(lookback)
| where tolower(FileExtension) in (riskante_extensies)
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(lookback)
    // Alleen inkomend: een intern verstuurde .html is meestal een rapport.
    | where EmailDirection == "Inbound"
    // Geleverd in de mailbox, dus niet gequarantainet of geblokkeerd.
    | where DeliveryAction == "Delivered"
    | where DeliveryLocation in ("Inbox/folder", "Inbox/Folder")
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              SenderFromDomain, SenderIPv4, AuthenticationDetails, DeliveryLocation,
              ThreatTypes, LatestDeliveryLocation
  ) on NetworkMessageId, RecipientEmailAddress
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderFromDomain,
          Subject, FileName, FileExtension, SHA256, ThreatTypes, ThreatTypes1,
          AuthenticationDetails, LatestDeliveryLocation
| order by Timestamp desc
```

De waarden van `DeliveryLocation` staan in de schemadocumentatie als
*"Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted
items"*. De exacte hoofdlettervorm in de data is **niet geverifieerd**; daarom
staan beide varianten in de query. Controleer met
`EmailEvents | distinct DeliveryLocation` wat jouw tenant schrijft.

## KQL — Microsoft Sentinel (EmailAttachmentInfo + EmailEvents)

```kql
// Zelfde detectie in Sentinel. Verschil met Defender XDR: de tijdkolom heet
// TimeGenerated. De kolomnamen FileExtension, NetworkMessageId,
// RecipientEmailAddress en DeliveryLocation zijn identiek.
let lookback = 7d;
let riskante_extensies = dynamic(["html","htm","shtml","xhtml","svg",
                                  "js","jse","vbs","vbe","wsf","hta","chm","iso","img"]);
EmailAttachmentInfo
| where TimeGenerated > ago(lookback)
| where tolower(FileExtension) in (riskante_extensies)
| join kind=inner (
    EmailEvents
    | where TimeGenerated > ago(lookback)
    | where EmailDirection == "Inbound"
    | where DeliveryAction == "Delivered"
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress,
              SenderFromDomain, SenderIPv4, AuthenticationDetails, DeliveryLocation,
              LatestDeliveryLocation, ExchangeTransportRule
  ) on NetworkMessageId, RecipientEmailAddress
// ExchangeTransportRule leeg = de transportregel uit maatregel 008 heeft niet
// gepakt. Dat is de controle op de maatregel zelf, niet alleen op de dreiging.
| extend TransportregelPakte = isnotempty(ExchangeTransportRule)
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, SenderFromDomain,
          Subject, FileName, FileExtension, SHA256, DeliveryLocation,
          TransportregelPakte, ExchangeTransportRule, AuthenticationDetails
| order by TimeGenerated desc
```

## Aanscherpen: eerste contact en authenticatiefalen

Een `.html`-bijlage van een bekende leverancier is meestal een factuurrapport.
Dezelfde bijlage van een afzender waarmee nog nooit gemaild is, is dat niet.
`EmailEvents` heeft daar een kolom voor:

```kql
| where IsFirstContact == 1        // in Sentinel is dit een bool: == true
| where AuthenticationDetails has_any ("fail", "softpass", "none")
```

## Waarom dit BEC is

T1204 is de enige techniek in dit cluster waar de gebruiker zelf de handeling
verricht; alles wat daarna komt is aanvallerswerk. Microsoft beschrijft de
opeenvolging in de eigen documentatie over illicit consent grants: de aanvaller
*"tricks an end user into granting that application consent to access their data
either through a phishing attack, or by injecting illicit code into a trusted
website"*. Dezelfde klik is ook de start van een AiTM-sessie: de gebruiker logt
in op een reverse proxy, en het sessietoken vertrekt terwijl MFA gewoon slaagt.
Daarom hoort deze detectie inhoudelijk bij [T1671](T1671-illicit-consent-grant.md)
en [T1556.006](T1556.006-mfa-modification.md): dit is stap één, die twee zijn de
persistentie die er direct achteraan komt.

## Referenties

- Microsoft, alert policies (namen, severity, licenties): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, `Set-ProtectionAlert` (default policies zijn niet te bewerken): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-protectionalert
- Microsoft, anti-malware protection en het common attachments filter: https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about
- Microsoft, EmailEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, EmailAttachmentInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table
- Microsoft, EmailAttachmentInfo in Azure Monitor (Sentinel-kolommen): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/emailattachmentinfo
- Microsoft, Detect and remediate illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- MITRE ATT&CK T1204: https://attack.mitre.org/techniques/T1204/
