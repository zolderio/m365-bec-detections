# T1656 — Impersonation

| | |
|---|---|
| **MITRE-tactiek** | Impact |
| **Whitepaper-maatregel** | 019 — Administratieve verificatie van betalingen (prioriteit Hoog) |
| **Verwante techniek** | [T1657](T1657-financial-theft.md) — hetzelfde moment, andere helft: de betaling zelf |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE`
>
> Impersonatiebescherming zit in Defender for Office 365 en die moet je aanzetten
> — in de standaard anti-phishingpolicy staan de impersonatie-instellingen
> namelijk **uit**, ook als je de licentie hebt. Maar de alerts eromheen zijn
> allemaal **Informational** en dekken alleen het geval waarin een *override*
> een phishingmail alsnog doorliet; de twee policies die wél over impersonatie
> gingen zijn door Microsoft verwijderd. Zet de override-alerts aan en verhoog
> hun severity, en bouw daarnaast een eigen rule op wat Defender wél in
> `EmailEvents` wegschrijft: berichten die als impersonatie zijn herkend maar
> tóch in de inbox zijn beland.
>
> Lees dit bestand met de goede verwachting. De maatregel bij deze techniek is
> **procedureel** — vier ogen, telefonische verificatie van bankwijzigingen. De
> detectie hieronder is een hulpmiddel om te zien dat er geprobeerd wordt, niet
> een vervanging van dat proces.

## Is er een Defender-alert voor?

**Deels, en zwakker dan je zou denken.** Twee alert policies die specifiek over
impersonatie gingen zijn **verwijderd**. Microsoft in een voetnoot bij de
alert-policytabel: de huidige override-policies zijn *"part of the replacement
functionality for the **Phish delivered due to tenant or user override** and
**User impersonation phish delivered to inbox/folder** alert policies that were
removed based on user feedback."*

Wat ervoor in de plaats kwam:

| Alert policy | Standaard severity | Licentie |
|---|---|---|
| `Phish delivered due to an ETR override` | **Informational** | E1/F1/G1, E3/F3/G3 of E5/G5 |
| `Phish delivered due to an IP allow policy` | **Informational** | E1/F1/G1, E3/F3/G3 of E5/G5 |
| `Phish not zapped because ZAP is disabled` | **Informational** | E5/G5 of Defender for Office 365 Plan 2 add-on |

Drie beperkingen die samen bepalen waarom dit geen detectie is:

1. **Alle drie Informational.** Zonder ophoging verdwijnen ze in een dashboard.
   Ophogen van de severity is bij een System-policy niet aantoonbaar mogelijk; Microsofts documentatie spreekt zichzelf op dat punt tegen — zie de README.
2. **Ze vuren op de override, niet op de impersonatie.** Een impersonatiemail
   die gewoon door de filters komt omdat de impersonatie-instellingen niet
   geconfigureerd zijn, levert geen van deze alerts op.
3. **Ze gaan over *high confidence phish*.** Een BEC-mail zonder link en zonder
   bijlage — alleen tekst met een nieuw rekeningnummer — haalt dat predicaat
   vaak niet.

Bron: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

Nuttige aanvullende alerts uit dezelfde tabel, wel op een bruikbaar niveau:
`Suspicious email sending patterns detected` (**Medium**, E1/E3/E5) en
`User restricted from sending email` (**High**) — die vuren als het
gecompromitteerde account zelf gaat versturen. En `Potential nation-state
activity` (**High**).

## Wat Defender wél levert: impersonatiebescherming

| | |
|---|---|
| **Waar** | Anti-phishingpolicies in Microsoft Defender for Office 365 |
| **Licentie** | **Defender for Office 365 (Plan 1 of Plan 2)**. Microsoft: *"The impersonation settings for user impersonation protection, domain impersonation protection, mailbox intelligence, impersonation safety tips, and trusted senders and domains are available only in anti-phishing policies in Defender for Office 365."* De basis-anti-phishing voor alle cloudmailboxen (spoof intelligence, first contact safety tip, unauthenticated sender indicators) bevat **geen** impersonatiebescherming. |
| **Belangrijk** | *"The default anti-phishing policy in Defender for Office 365 provides spoof protection and mailbox intelligence for all recipients. However, the other available impersonation protection features and phishing email thresholds aren't configured in the default policy."* Met andere woorden: de licentie hebben is niet genoeg, je moet de gebruikers en domeinen expliciet invullen. |
| **Grenzen** | Maximaal **350** te beschermen gebruikers en **50** custom domeinen per policy. Staat *Enable intelligence for impersonation protection* aan, dan werkt user- en domain-impersonatiebescherming **niet** als afzender en ontvanger al eerder gemaild hebben — precies het geval bij een gekaapte leveranciersthread. |
| **Bron** | https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about |

Voor het overzicht van wat er gedetecteerd is, is er de **impersonation
insight** in de Defender-portal.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Defender XDR advanced hunting | `EmailEvents` | Wordt gevuld door **Defender for Office 365**. Zonder die dienst geven de queries niets terug. |
| Defender XDR advanced hunting | `AlertInfo` / `AlertEvidence` | Alerts uit Defender for Endpoint, Office 365, Cloud Apps, Identity en aangesloten Sentinel-workspaces. Koppel op `AlertId`. |
| Microsoft Sentinel | `SecurityAlert` | Data connector **Microsoft Defender XDR**. Hierin landen de alerts uit de Defender-stack, met `AlertName`, `AlertSeverity`, `ProviderName`, `Tactics` en `Techniques`. |
| Microsoft Sentinel | `OfficeActivity` | Voor de correlatie met wat er ná de mail in de mailbox gebeurde (maatregel 012, UAL aan). |

## KQL — Defender XDR advanced hunting (EmailEvents)

De sleutel is `EmailActionPolicy`. Microsoft documenteert daarvoor onder meer de
waarden `Anti-phishing domain impersonation`, `Anti-phishing user impersonation`,
`Anti-phishing spoof` en `Anti-phishing graph impersonation`. Dat zijn de enige
plekken waar "impersonatie" als zodanig in de telemetrie staat.

```kql
// Berichten die door impersonatiebescherming zijn herkend maar tóch in een
// inbox of map zijn afgeleverd. Dat is het gat: gedetecteerd maar niet
// tegengehouden, doorgaans omdat de actie op 'Don't apply any action' staat
// (dat is de standaardwaarde in het beleid).
let lookback = 7d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where EmailActionPolicy has_any ("impersonation", "Anti-phishing spoof")
| where DeliveryLocation in~ ("Inbox/folder", "Junk")
| project Timestamp, NetworkMessageId, InternetMessageId, Subject,
          SenderFromAddress, SenderDisplayName, SenderFromDomain,
          SenderMailFromDomain, RecipientEmailAddress,
          DeliveryAction, DeliveryLocation, LatestDeliveryLocation,
          ThreatTypes, DetectionMethods, EmailActionPolicy, EmailAction,
          AuthenticationDetails, IsFirstContact, ExchangeTransportRule
| order by Timestamp desc
```

```kql
// Eerste contact vanaf een domein dat sterk op een eigen of leveranciersdomein
// lijkt, met een betaalgerelateerd onderwerp. Bewust geen dreigingsverdict als
// voorwaarde: de BEC-mail die er het meest toe doet heeft er geen.
let lookback = 7d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where IsFirstContact == 1
| where Subject has_any ("factuur", "invoice", "betaling", "payment", "iban",
                         "rekeningnummer", "bank details", "spoed", "urgent",
                         "wijziging", "remittance")
| extend SenderDomain = tolower(SenderFromDomain)
| where not(SenderDomain in~ (ownDomains))
| project Timestamp, Subject, SenderFromAddress, SenderDisplayName, SenderDomain,
          SenderMailFromDomain, RecipientEmailAddress, AuthenticationDetails,
          DeliveryLocation, ThreatTypes, DetectionMethods, ReportId
| order by Timestamp desc
```

> Deze query filtert op eerste contact en onderwerp, niet op gelijkenis van het
> domein. Een betrouwbare lookalike-vergelijking (Levenshtein) zit niet in KQL;
> daarvoor is de domain-impersonatiebescherming van Defender bedoeld, met een
> expliciete lijst van maximaal 50 te beschermen domeinen. Verwacht ruis en zet
> hem in als hunting-query, niet als analytic rule.

```kql
// De afzenderkant: display-naamimpersonatie waarbij de weergegeven naam
// overeenkomt met een eigen medewerker maar het adres extern is.
let lookback = 7d;
let internalNames = EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Intra-org"
    | where isnotempty(SenderDisplayName)
    | distinct SenderDisplayName;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound"
| where SenderDisplayName in (internalNames)
| project Timestamp, Subject, SenderDisplayName, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, DeliveryLocation, AuthenticationDetails,
          EmailActionPolicy, IsFirstContact
| order by Timestamp desc
```

## KQL — Defender XDR advanced hunting (AlertInfo / AlertEvidence)

```kql
// Alle alerts uit de Defender-stack die aan T1656 of aan phishing/BEC hangen,
// met de betrokken entiteiten erbij. Titels en severities komen uit de
// productdata en zijn hier bewust niet hardgecodeerd.
let lookback = 30d;
AlertInfo
| where Timestamp > ago(lookback)
| where AttackTechniques has_any ("T1656", "T1534", "T1114")
       or Category in~ ("InitialAccess", "CredentialAccess")
       or Title has_any ("impersonat", "phish", "business email", "BEC")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | summarize Entities = make_set(strcat(EntityType, ":", coalesce(AccountUpn, RemoteUrl, FileName, "")), 20) by AlertId
) on AlertId
| project Timestamp, AlertId, Title, Category, Severity, ServiceSource,
          DetectionSource, AttackTechniques, Entities
| order by Timestamp desc
```

## KQL — Sentinel (SecurityAlert)

```kql
// Zorg dat de Defender-alerts in Sentinel op een niveau binnenkomen waar iemand
// kijkt. De alert policies rond overrides zijn Informational; deze rule tilt ze
// eruit in plaats van ze te laten wegzakken.
let lookback = 7d;
SecurityAlert
| where TimeGenerated > ago(lookback)
| where ProviderName has_any ("MDATP", "Office 365 Advanced Threat Protection",
                              "Microsoft Defender XDR", "OATP")
       or ProductName has_any ("Microsoft Defender", "Office 365")
| where AlertName has_any ("impersonat", "phish", "override", "business email")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName,
          Description, CompromisedEntity, Tactics, Techniques, Entities, AlertLink
| order by TimeGenerated desc
```

`ProviderName`- en `ProductName`-waarden verschillen per tenant en per
connectorversie. Draai de query eerst zonder het `where`-filter op
`ProviderName` en kijk wat er in jouw workspace staat; de exacte set waarden is
niet publiek gedocumenteerd.

## Waarom dit BEC is

Impersonatie is bij BEC geen techniek maar het hele plot: de aanvaller hoeft
niets te breken, alleen te lijken op iemand die geld mag laten overmaken. Het
NCSC/Cyclotron-advies plaatst dit bewust in de Impact-fase en zegt erbij dat de
verdediging hier verschuift: *"In de Impact-fase zijn technische barrières vaak
al gepasseerd. De verdediging verschuift hier van techniek naar strikte
administratieve procedures."*

Dat is ook de eerlijke conclusie van dit bestand. Microsofts
impersonatiebescherming werkt tegen lookalike-domeinen en display-namen, maar
juist het lastigste BEC-scenario ontsnapt eraan: een échte, gecompromitteerde
leveranciersmailbox die al jaren met jou correspondeert. Microsoft documenteert
dat zelf als een expliciete beperking — mailbox intelligence markeert een
afzender niet als impersonatie *"if the sender and recipient previously
communicated via email"*. Precies die thread is bij factuurfraude de aanvalsweg.

De omvang: de FBI ontving in 2025 24.768 BEC-meldingen met $3.046.598.558
gerapporteerde schade (IC3 Annual Report 2025).

## Referenties

- Microsoft, alert policies (incl. de voetnoot over de verwijderde impersonatie-policies): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, anti-phishingpolicies en impersonatiebescherming: https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about
- Microsoft, EmailEvents-schema (EmailActionPolicy-waarden): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, SecurityAlert-schema (Sentinel): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert
- FBI IC3 Annual Report 2025: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- MITRE ATT&CK T1656: https://attack.mitre.org/techniques/T1656/
