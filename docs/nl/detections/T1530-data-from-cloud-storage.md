# T1530 — Data from Cloud Storage

| | |
|---|---|
| **MITRE-tactiek** | Collection |
| **Whitepaper-maatregelen** | 016 — Blokkering van automatische e-mailforwarding (prioriteit Hoog)<br>017 — Teams & SharePoint-collaboration beperken (prioriteit Midden) |
| **Verwante technieken** | [T1114.002](T1114.002-remote-email-collection.md) — hetzelfde gedrag in de mailbox; [T1567](T1567-exfiltration-over-web-services.md) — het naar buiten brengen |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> De enige standaard alert policy die in de buurt komt,
> `Unusual volume of external file sharing`, wordt door Microsoft **uitgefaseerd
> wegens valse positieven** en vereist bovendien E5/G5 of Defender for Office
> 365 Plan 2. Wat er verder is, zijn de anomaliedetecties van Defender for Cloud
> Apps — die zitten niet in E3 zonder add-on en zijn gebouwd op volume, terwijl
> een BEC-aanvaller juist gericht en in klein aantal zoekt naar één factuur of
> één contract. Bouw dit zelf, op het zoeken en het benaderen, niet op het
> aantal.

## Is er een Defender-alert voor?

**Formeel wel, praktisch niet meer.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Standaard severity** | **Medium** |
| **Licentie** | E5/G5 of Defender for Office 365 Plan 2 add-on |
| **Categorie** | Information governance |
| **Status** | **Wordt uitgefaseerd.** Microsoft zet boven de hele sectie *Information governance alert policies*: *"The alert policies in this section are in the process of being deprecated based on customer feedback as false positives. To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* Deze policy is de enige in die sectie. Geverifieerd op 22 aug 2026, pagina met ms.date 2026-08-03. |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

Wat er wél overblijft aan kant-en-klare detectie, en waarom het het gat niet
dicht:

| | |
|---|---|
| **Mechanisme** | Defender for Cloud Apps, anomaliedetecties onder *Unusual activities (by user)* |
| **Namen** | `Unusual multiple file download activities`, `Unusual file share activities`, `Unusual file deletion activities` |
| **Status** | Actief. Deze staan **niet** in de lijst van policies die Microsoft per juni 2025 heeft uitgezet in de overgang naar het dynamische detectiemodel. |
| **Licentie** | Vereist Microsoft Defender for Cloud Apps. Standaard-severity niet publiek gedocumenteerd. |
| **Waarom niet genoeg** | Volume-gebaseerd, met een leerperiode van zeven dagen. Een aanvaller die vijf bestanden opent om een factuurformat te kopiëren, zit onder elke drempel. |
| **Bron** | https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy |

Er bestaat ook een `Suspicious OAuth app file download activities`-detectie
(app downloadt meerdere bestanden uit SharePoint of OneDrive op een voor de
gebruiker ongebruikelijke manier). Nuttig naast, niet in plaats van het
onderstaande.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** met de SharePoint-workload aan. SharePoint- en OneDrive-events komen in dezelfde tabel binnen, herkenbaar aan `OfficeWorkload` en `RecordType` (`SharePoint`, `SharePointFileOperation`, `SharePointSharingOperation`). Er is **geen** aparte `SharePointFileOperation`-tabel in Log Analytics; dat is een `RecordType`-waarde. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps met de Microsoft 365-appconnector en **Microsoft 365 activities** aangevinkt. Retentie 30 dagen. |

Afhankelijk van maatregel 012 (UAL aan). Daarnaast: `SearchQueryInitiatedSharePoint`
staat **niet standaard aan** en moet apart worden ingeschakeld — zie hieronder.

## Het belangrijkste event: waar de aanvaller naar zócht

De CISA-playbook noemt `SearchQueryInitiatedSharePoint` als het event waarmee je
de intentie van de aanvaller kunt lezen: *"the audit record for a
SearchQueryInitiatedSharePoint event contains the actual text of the search
query and indicates the type of SharePoint site that the threat actor
searched."* De zoektermen ("factuur", "IBAN", "betaalinstructie") zeggen meer
over BEC dan welk downloadvolume dan ook.

**Let op de randvoorwaarde:** CISA schrijft *"Users will also need to enable
SearchQueryInitiated logging for both Exchange and SharePoint since it is
disabled by default."* Voor Exchange is dat
`Set-Mailbox <identity> -AuditOwner @{Add="SearchQueryInitiated"}`. Staat dit
niet aan, dan levert de onderstaande query per definitie niets op.

## KQL — Sentinel (OfficeActivity)

```kql
// Zoekopdrachten in SharePoint/OneDrive en Exchange naast elkaar, met de
// zoektermen erbij. Vereist dat SearchQueryInitiated-logging is ingeschakeld
// (staat standaard uit).
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("SearchQueryInitiatedSharePoint", "SearchQueryInitiatedExchange", "SearchQueryPerformed")
| project TimeGenerated, UserId, Operation, OfficeWorkload, ClientIP, UserAgent,
          Site_Url, OfficeObjectId, ExtraProperties
| order by TimeGenerated desc
```

```kql
// Benaderen en downloaden van bestanden, gescheiden van het zoeken zodat je
// de twee kunt correleren op gebruiker en tijd.
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where RecordType in~ ("SharePointFileOperation", "SharePoint")
| where Operation in~ ("FileAccessed", "FileDownloaded", "FileSyncDownloadedFull",
                       "FileCopied", "FilePreviewed", "PageViewed")
| project TimeGenerated, UserId, Operation, ClientIP, UserAgent, Site_Url,
          SourceRelativeUrl, SourceFileName, SourceFileExtension, ItemType,
          IsManagedDevice, EventSource
| order by TimeGenerated desc
```

Financieel aanscherpen — dit is de filter die van "een bestand geopend" een
BEC-signaal maakt:

```kql
| extend File = tolower(strcat(SourceRelativeUrl, "/", SourceFileName))
| where File has_any ("factuur", "invoice", "iban", "betaling", "payment",
                         "creditor", "crediteur", "bankgegevens", "remittance",
                         "contract", "leverancier", "supplier")
```

En de sessiepivot, zodat je zoeken en openen aan elkaar knoopt:

```kql
// Gebruikers die binnen 30 minuten zowel zochten als bestanden openden,
// vanaf hetzelfde IP.
let lookback = 7d;
let searches = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("SearchQueryInitiatedSharePoint", "SearchQueryPerformed")
    | project SearchTime = TimeGenerated, UserId, ClientIP;
let opens = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("FileAccessed", "FileDownloaded")
    | project OpenTime = TimeGenerated, UserId, ClientIP, SourceFileName;
searches
| join kind=inner opens on UserId, ClientIP
| where OpenTime between (SearchTime .. SearchTime + 30m)
| summarize Files = make_set(SourceFileName, 25), Count = count()
        by UserId, ClientIP, bin(SearchTime, 1h)
| order by Count desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents)

```kql
let lookback = 7d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application in~ ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in~ ("FileAccessed", "FileDownloaded", "FileSyncDownloadedFull",
                        "FileCopied", "SearchQueryInitiatedSharePoint", "SearchQueryPerformed")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, AccountType,
          IsExternalUser, IsImpersonated, IPAddress, CountryCode, Isp, UserAgent,
          ObjectName, ObjectType, ObjectId, UncommonForUser, LastSeenForUser
| order by Timestamp desc
```

`UncommonForUser` en `LastSeenForUser` zijn hier de goedkoopste winst:
Defender for Cloud Apps verrijkt hoogwaardige events zelf met welke attributen
ongebruikelijk zijn voor die gebruiker. Microsoft waarschuwt wel dat events met
lage securitywaarde die verrijking niet doorlopen en dan `""` bevatten, terwijl
`[]` betekent "wél verrijkt, niets afwijkends" — filter dus op
`isnotempty(UncommonForUser) and UncommonForUser != "[]"` en niet op
`isnotempty()` alleen.

## Waarom dit BEC is

Bij BEC is de documentkant geen bijvangst maar de voorbereiding. De aanvaller
heeft een echt factuurformat, een echt contractnummer en een echte
leveranciersnaam nodig om een betaalverzoek geloofwaardig te maken; die staan
in SharePoint en OneDrive, niet in de mailbox. Het NCSC/Cyclotron-advies noemt
dit expliciet onder maatregel 017: *"Bij BEC richten aanvallers zich niet alleen
op e-mail, maar ook op samenwerkingsplatformen waar bedrijfsdocumenten,
contracten, financiële informatie en operationele data worden gedeeld."*

CISA's playbook zet daar de detectielogica naast: zoekopdrachten in SharePoint
zitten hoog in de Pyramid of Pain — een aanvaller wisselt moeiteloos van IP en
user agent, maar niet van wat hij zoekt. CISA adviseert dan ook expliciet om
zoekopdrachten te correleren met de bijbehorende bestandsoperaties: *"searched
for a file on SharePoint, with accompanying FileAccessed, FileCopied, or
FileDeleted operations."*

## Referenties

- Microsoft, alert policies (incl. de deprecation-notitie bij Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, anomaliedetectiebeleid Defender for Cloud Apps: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, OfficeActivity-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, Office 365 Management Activity API-schema (RecordType-waarden, SharePoint-schema): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- Microsoft, audit log activities: https://learn.microsoft.com/en-us/purview/audit-log-activities
- CISA, Microsoft Expanded Cloud Logs Implementation Playbook (bijgewerkt mei 2026): https://www.cisa.gov/sites/default/files/2026-07/MS%20Expanded%20Logging%20Playbook-Updated-May2026_Final%20approved_508%20Remediation%20Complete_published%20(1).pdf
- MITRE ATT&CK T1530: https://attack.mitre.org/techniques/T1530/
