# T1534 — Internal Spearphishing

| | |
|---|---|
| **MITRE-tactiek** | Lateral Movement |
| **Whitepaper-fase** | 10. Lateral Movement |
| **Whitepaper-maatregel** | 015 — Interne en uitgaande phishingdetectie (prioriteit Midden, impact Hoog, inspanning Midden) |
| **Verwante technieken** | [T1537](T1537-transfer-data-to-cloud-account.md) en [T1566.003](T1566.003-spearphishing-via-service.md) — zelfde maatregel |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE`
>
> Drie standaard alert policies dekken de *uitgaande* kant goed en zitten in
> E1/E3 zonder add-on: `User restricted from sending email` (High),
> `Suspicious email sending patterns detected` (Medium) en `Email sending limit
> exceeded` (Medium). Microsoft raadt in de documentatie van het
> outbound-spambeleid expliciet aan om deze alert policies te gebruiken in
> plaats van de notificatievelden in het beleid zelf. Zet ze dus aan — maar ze
> vuren op volume en op reputatiesignalen, niet op inhoud, en **intra-org mail
> is geen uitgaande mail**. Een gerichte mail van een gecompromitteerd account
> naar drie collega's van de crediteurenadministratie blijft er dus onder. Voeg
> daarom de intra-org-regel hieronder toe.

## Is er een Defender-alert voor?

**Deels.** Drie policies, alle drie zonder add-on-licentie:

| Alert policy | Standaard severity | Licentie | Wat het is |
|---|---|---|---|
| `User restricted from sending email` | **High** | Microsoft Business Basic/Standard/Premium, E1/F1/G1, E3/F3/G3 of E5/G5 | Vuurt wanneer iemand is geblokkeerd voor uitgaande mail. Microsoft: *"This alert typically indicates a compromised account."* Automated investigation: ja. |
| `Suspicious email sending patterns detected` | **Medium** | E1/F1/G1, E3/F3/G3 of E5/G5 | Vroegsignaal: verdacht verzendgedrag dat nog net niet tot blokkade leidt. Automated investigation: ja. |
| `Email sending limit exceeded` | **Medium** | E1/F1/G1, E3/F3/G3 of E5/G5 | Meer mail verzonden dan het outbound-spambeleid toestaat. |

Twee aanpalende policies op tenantniveau, beide **High** en beide in E1/E3:
`Suspicious tenant sending patterns observed` en `Tenant restricted from sending
email`. Die vuren pas als de hele tenant in de problemen zit — te laat voor
detectie, nuttig als escalatiesignaal.

Microsoft, in de documentatie van het outbound-spambeleid:

> *"The default alert policies named **Email sending limit exceeded**,
> **Suspicious email sending patterns detected**, and **User restricted from
> sending email** already send email notifications to members of the
> **TenantAdmins** group (**Global Administrator** members) about unusual
> outbound email activity and blocked users due to outbound spam. […] We
> recommend that you use these alert policies instead of the notification
> options in outbound spam policies."*

Dat sluit direct aan op maatregel 011 uit het advies: die notificaties gaan
standaard alléén naar Global Administrators. Stuur ze door naar de
distributiegroep of gedeelde mailbox die het advies voorschrijft.

**Wat de alerts niet dekken.** Alle vijf gaan over mail die de organisatie
verlaat of over de reputatie van de tenant. `EmailDirection` = `Intra-org`
valt daarbuiten. Juist dat is de kern van T1534: het advies noemt het *"Het
versturen van phishing-mails vanaf een gecompromitteerd account naar
collega's."*

## Een randvoorwaarde die vaak vergeten wordt: Safe Links staat intern uit

Safe Links wordt niet automatisch toegepast op interne mail. Dat is een aparte
schakelaar in het Safe Links-beleid:

> **Apply Safe Links to email messages sent within the organization**: *"Select
> this option to apply the Safe Links policy to messages between internal
> senders and internal recipients. Turning on this setting enables link wrapping
> for all intra-organization messages."*

In PowerShell: `New-SafeLinksPolicy … -EnableForInternalSenders $true` (of
`Set-SafeLinksPolicy`). Staat die uit, dan is er geen `UrlClickEvents`-record
voor een interne phishing-link en verliest u de helft van de detectie in dit
bestand. Microsoft levert Safe Links via Defender for Office 365; er is geen
standaard Safe Links-policy, maar de preset **Built-in protection** geeft alle
ontvangers Safe Links-bescherming.

Bron: https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure

Ter aanvulling: ZAP werkt wél op alle cloudmailboxen zonder aparte licentie
(*"There are no special licensing requirements for ZAP for malware, spam, and
phishing"*), maar ZAP is remediatie achteraf, geen detectie, en Microsoft
tekent erbij aan: *"ZAP isn't logged in the Exchange mailbox audit logs as a
system action."*

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents` | Data connector **Microsoft Defender XDR**, met de Defender for Office 365-tabellen aangezet. |
| Defender XDR advanced hunting | `EmailEvents`, `UrlClickEvents`, `AlertInfo`/`AlertEvidence` | Geen connector. Microsoft: `EmailEvents` *"is populated by records from Defender for Office 365. If your organization hasn't deployed the service […] queries that use the table aren't going to work or return any results."* |

`EmailEvents` vereist dus **Defender for Office 365** (Plan 1 of Plan 2, of de
E5-bundel). Met alleen EOP is er geen intra-org-detectie op inhoud; dan blijft
u aangewezen op de drie alert policies hierboven en op de inboxregels uit
[T1564.008](T1564.008-email-hiding-rules.md).

## KQL — Sentinel / Defender XDR (EmailEvents): intra-org phishing-verdict

Deze query draait ongewijzigd in beide omgevingen; `EmailEvents` heeft in
Sentinel dezelfde kolomnamen als in advanced hunting.

<!-- query
platform: sentinel
name: Intra-org mail with a phishing or malware verdict
technique: T1534
severity: High
tactics: [LateralMovement]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// Interne mail die door de filterstack als phishing of malware is bestempeld.
// EmailDirection "Intra-org" is de kern: dit is mail van een eigen account naar
// een eigen collega, en dus per definitie een lateral-movement-signaal.
let lookback = 1d;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Intra-org"
| where isnotempty(ThreatTypes)
| where ThreatTypes has_any ("Phish", "Malware")
| summarize Recipients = dcount(RecipientEmailAddress),
            RecipientList = make_set(RecipientEmailAddress, 25),
            Subjects = make_set(Subject, 10),
            Verdicts = make_set(ThreatTypes, 5),
            Detection = make_set(DetectionMethods, 5),
            Delivered = countif(DeliveryAction == "Delivered"),
            Blocked = countif(DeliveryAction in ("Blocked", "Junked", "Replaced")),
            First = min(Timestamp), Last = max(Timestamp)
    by SenderFromAddress, SenderObjectId
| order by Delivered desc, Recipients desc
```

Een `Delivered`-verdict met `ThreatTypes has "Phish"` en `EmailDirection ==
"Intra-org"` is in vrijwel elke organisatie een incident: de filterstack heeft
het herkend én het is toch in de inbox van een collega beland.

## KQL — intra-org burst zonder verdict

De verdict-query hierboven mist het geval waar het bij BEC meestal om gaat: een
inhoudelijk gewone mail, geen link, geen bijlage, gewoon een verzoek om een
rekeningnummer te wijzigen. Daar is geen filterverdict voor. Wat u wél kunt zien
is het patroon: één interne afzender die in korte tijd hetzelfde onderwerp naar
ongebruikelijk veel interne ontvangers stuurt.

<!-- query
platform: defender-xdr
name: Internal sender with an unusual fan-out on a single subject
technique: T1534
severity: Medium
tactics: [LateralMovement]
interval: PT1H
lookback: P7D
parameters: []
deployable: false
-->
```kql
// Interne afzender met een ongebruikelijke fan-out op een enkel onderwerp.
// Tune Ontvangers en het window op de eigen organisatie; in een tenant met
// veel distributielijsten ligt de threshold hoger.
let lookback = 7d;
let window = 1h;
let minRecipients = 8;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Intra-org"
| where DeliveryAction == "Delivered"
| where isempty(DistributionList)          // echte fan-out, geen distributielijst
| summarize Recipients = dcount(RecipientEmailAddress),
            RecipientList = make_set(RecipientEmailAddress, 30),
            Messages = dcount(NetworkMessageId),
            FirstContact = countif(IsFirstContact == 1),
            Urls = sum(UrlCount), Attachments = sum(AttachmentCount)
    by SenderFromAddress, Subject, bin(Timestamp, window)
| where Recipients >= minRecipients
| order by Recipients desc
```

Combineer dit met de andere technieken uit dit cluster: een fan-out die
samenvalt met een verse inboxregel uit
[T1564.008](T1564.008-email-hiding-rules.md) of met een nieuwe deel-link uit
[T1537](T1537-transfer-data-to-cloud-account.md) is een compleet BEC-verhaal.

## KQL — Defender XDR: kliks op interne links

<!-- query
platform: defender-xdr
name: Clicks by internal recipients on links in intra-org mail
technique: T1534
severity: Medium
tactics: [LateralMovement]
interval: PT1H
lookback: P7D
parameters: []
deployable: false
-->
```kql
// Klikken door interne ontvangers op links uit intra-org mail.
// Vereist EnableForInternalSenders $true in het Safe Links-beleid; anders is
// deze tabel leeg voor interne mail.
let lookback = 7d;
let internalEmail = EmailEvents
    | where Timestamp > ago(lookback)
    | where EmailDirection == "Intra-org"
    | project NetworkMessageId, SenderFromAddress, Subject, RecipientEmailAddress;
UrlClickEvents
| where Timestamp > ago(lookback)
| where Workload == "Email"
| join kind=inner internalEmail on NetworkMessageId
| project Timestamp, AccountUpn, SenderFromAddress, Subject, Url, UrlChain,
          ActionType, IsClickedThrough, ThreatTypes, DetectionMethods, IPAddress
| order by Timestamp desc
```

`IsClickedThrough == 1` betekent dat de gebruiker de waarschuwingspagina heeft
weggeklikt en alsnog is doorgegaan. Bij een interne afzender is dat vrijwel
altijd een geslaagde lateral-movement-stap.

## KQL — de alerts zelf oppikken in Sentinel

Zet de drie alert policies niet alleen aan maar haal ze ook binnen, zodat ze
naast de eigen regels in dezelfde incidentenstroom staan:

<!-- query
platform: sentinel
name: Outbound sending restriction and suspicious sending pattern alerts
technique: T1534
severity: Medium
tactics: [LateralMovement]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// Titels komen letterlijk overeen met de policynamen uit alert-policies.
// De ServiceSource-waarde voor deze policies is niet geverifieerd; filter op
// Title en kijk daarna zelf welke ServiceSource erbij hoort.
AlertInfo
| where Timestamp > ago(7d)
| where Title in ("User restricted from sending email",
                  "Suspicious email sending patterns detected",
                  "Email sending limit exceeded",
                  "Suspicious tenant sending patterns observed",
                  "Tenant restricted from sending email")
| project Timestamp, AlertId, Title, Severity, ServiceSource, DetectionSource, Category
| order by Timestamp desc
```

## Waarom dit BEC is

Het advies formuleert het risico precies: *"Veel
standaardbeveiligingsinstellingen zijn primair gericht op de perimeters,
waardoor intern verkeer vaak onvoldoende wordt gecontroleerd. In een
BEC-scenario is dit een groot risico; wanneer een aanvaller eenmaal toegang
heeft tot een mailbox, kan hij dat gecompromitteerde account gebruiken om
geloofwaardige 'interne' phishing-mails naar collega's te sturen om de aanval
verder uit te breiden (Lateral Movement). Omdat medewerkers e-mails van hun
eigen collega's sneller vertrouwen, is de kans op een succesvolle
vervolginbreuk zonder deze interne detectie aanzienlijk groter."*

Bij BEC is de interne mail zelden de aanval zelf — hij is de autorisatie. De
mail van "de directeur" aan de crediteurenadministratie hoeft geen link en geen
bijlage te bevatten om schade aan te richten; het volstaat dat hij uit de echte
mailbox van de echte directeur komt. Daarom is de fan-outquery hierboven
belangrijker dan de verdict-query, en daarom hoort deze techniek gecorreleerd te
worden met de andere signalen uit dit cluster in plaats van los te worden
gealerteerd.

Microsoft koppelt beide alertregels expliciet aan accountcompromittering: bij
`User restricted from sending email` staat *"This alert typically indicates a
compromised account"*, en bij `Suspicious email sending patterns detected` en
`Email sending limit exceeded` verwijst Microsoft naar de eigen procedure
*Responding to a compromised email account*.

## Referenties

- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, outbound-spambeleid configureren (aanbeveling om de alert policies te gebruiken): https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure
- Microsoft, Safe Links-beleid configureren (`EnableForInternalSenders`): https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure
- Microsoft, zero-hour auto purge: https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge
- Microsoft, EmailEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, UrlClickEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- MITRE ATT&CK T1534: https://attack.mitre.org/techniques/T1534/
