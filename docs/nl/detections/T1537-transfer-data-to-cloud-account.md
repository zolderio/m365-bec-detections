# T1537 — Transfer Data to Cloud Account

| | |
|---|---|
| **MITRE-tactiek** | Exfiltration (ATT&CK); het advies plaatst de techniek onder Lateral Movement |
| **Whitepaper-fase** | 10. Lateral Movement |
| **Whitepaper-maatregel** | 015 — Interne en uitgaande phishingdetectie (prioriteit Midden, impact Hoog, inspanning Midden) |
| **Verwante technieken** | [T1534](T1534-internal-spearphishing.md) en [T1566.003](T1566.003-spearphishing-via-service.md) — zelfde maatregel |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — het enige alert is E5-only én wordt uitgefaseerd
>
> De enige standaard alert policy die hierop lijkt te vuren is `Unusual volume
> of external file sharing`, severity **Medium**, en die vereist **E5/G5 of de
> Defender for Office 365 Plan 2-add-on**. Bovendien staat hij in de sectie
> *Information governance alert policies*, waarover Microsoft schrijft: *"The
> alert policies in this section are in the process of being deprecated based on
> customer feedback as false positives."* Op een uitgefaseerd E5-alert bouw je
> geen dekking. Een severity-aanpassing lost dit niet op — het probleem is de
> licentie en de levensduur, niet het niveau. Bouw een eigen regel op de
> deel-operations in de Unified Audit Log; die zitten in elke licentie met
> Exchange/SharePoint Online.

## Is er een Defender-alert voor?

**Nauwelijks.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Standaard severity** | **Medium** |
| **Licentie** | **E5/G5 of Defender for Office 365 Plan 2-add-on** |
| **Wat het is** | Microsoft: *"Generates an alert when an unusually large number of files in SharePoint or OneDrive are shared with users outside of your organization."* |
| **Beperking 1** | Vuurt op *volume*. Bij BEC gaat het vaak om één map met facturen of één contractenset — geen ongewoon volume. |
| **Beperking 2** | Staat in de sectie *Information governance alert policies*, die Microsoft uitfaseert wegens false positives. Microsoft adviseert daar zelf: *"To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

**Defender for Cloud Apps.** De anomaliedetecties *Unusual file share
activities* en *Unusual multiple file download activities* staan nog in de lijst
met actieve *Unusual activities (by user)*-policies en zijn **niet** in de
juni-2025-opruiming meegegaan. Ze vereisen wel Defender for Cloud Apps en een
lerende periode van zeven dagen. Twee aanpalende policies zijn wél uitgezet en
worden vaak nog als dekking geteld: *Suspicious file access activity (by user)*
en *Ransomware activity*. Van de eerste zegt Microsoft dat hij is *"disabled,
migrated to the new dynamic model and renamed to **Suspicious file access
indicative of lateral movement** and **Suspicious file access from untrusted ISP
and user agent with malicious IP indicator**"*.
Bron: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**, met de SharePoint-workload aan. Deel-events komen binnen als `RecordType` **SharePointSharingOperation** (14), bestandsacties als **SharePointFileOperation** (6). Vereist maatregel 012 (UAL aan). |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps-integratie met **Microsoft 365 activities** aan. Retentie 30 dagen. |

## KQL — Sentinel (OfficeActivity): delen naar buiten

<!-- query
platform: sentinel
name: External sharing of SharePoint or OneDrive files
technique: T1537
severity: Low
tactics: [Exfiltration]
interval: PT1H
lookback: P1D
parameters: [ownDomains]
deployable: true
-->
```kql
// Deel-operations in SharePoint en OneDrive waarbij de ontvanger buiten de
// organisatie valt. De operationnamen komen letterlijk uit Microsofts
// auditactiviteiten-referentie.
let lookback = 1d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
let ShareOperations = dynamic([
    "AnonymousLinkCreated",       // link zonder authenticatie: iedereen die hem heeft
    "SecureLinkCreated",          // beveiligde deel-link
    "AddedToSecureLink",          // iemand toegevoegd aan een bestaande deel-link
    "SharingInvitationCreated",   // uitnodiging aan iemand buiten de organisatie
    "CompanyLinkCreated",         // organisatiebrede link
    "SharingSet"]);
OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload in~ ("SharePoint", "OneDrive")
| where Operation in~ (ShareOperations)
| extend Recipient = coalesce(TargetUserOrGroupName, UserSharedWith)
| extend RecipientDomain = tolower(tostring(split(Recipient, "@")[1]))
// Anonieme links hebben geen ontvanger: die zijn per definitie extern.
| extend External = Operation =~ "AnonymousLinkCreated"
                    or (isnotempty(RecipientDomain) and RecipientDomain !in~ (ownDomains))
                    or TargetUserOrGroupType in~ ("Guest", "Partner")
| where External
| extend ClientIPAddress = case(ClientIP has ".", tostring(split(ClientIP, ":")[0]), ClientIP)
| project TimeGenerated, UserId, Operation, Recipient, RecipientDomain,
          TargetUserOrGroupType, SourceFileName, SourceFileExtension,
          Site_Url, SourceRelativeUrl, ClientIPAddress, UserAgent, EventSource
| order by TimeGenerated desc
```

## KQL — Sentinel: het patroon dat er bij BEC toe doet

Losse externe deling is in de meeste organisaties dagelijks werk. Wat het bij
BEC verdacht maakt, is de combinatie: een gebruiker die in korte tijd meerdere
bestanden extern deelt naar een domein waarmee de organisatie nog nooit heeft
gedeeld, of die eerst bulk downloadt en daarna deelt.

<!-- query
platform: sentinel
name: Burst of external shares to a domain not seen in the past 30 days
technique: T1537
severity: Medium
tactics: [Exfiltration]
interval: P1D
lookback: P14D
parameters: [ownDomains]
deployable: true
-->
```kql
// Burst: veel externe deelacties door een gebruiker binnen een uur, naar een
// domein dat in de 30 dagen ervoor niet voorkwam.
let lookback = 7d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- aanpassen
let ShareOperations = dynamic(["AnonymousLinkCreated", "SecureLinkCreated",
                               "AddedToSecureLink", "SharingInvitationCreated", "SharingSet"]);
let KnownDomains =
    OfficeActivity
    | where TimeGenerated between (ago(37d) .. ago(7d))
    | where Operation in~ (ShareOperations)
    | extend D = tolower(tostring(split(coalesce(TargetUserOrGroupName, UserSharedWith), "@")[1]))
    | where isnotempty(D)
    | distinct D;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ (ShareOperations)
| extend RecipientDomain = tolower(tostring(split(coalesce(TargetUserOrGroupName, UserSharedWith), "@")[1]))
| where isnotempty(RecipientDomain)
| where RecipientDomain !in~ (ownDomains)
| where RecipientDomain !in (KnownDomains)          // nieuw extern domein
| summarize Actions = count(),
            Files = dcount(SourceFileName),
            FileList = make_set(SourceFileName, 25),
            Recipients = make_set(coalesce(TargetUserOrGroupName, UserSharedWith), 15),
            First = min(TimeGenerated), Last = max(TimeGenerated)
    by UserId, RecipientDomain, bin(TimeGenerated, 1h)
| where Files >= 3
| order by Files desc
```

En de bulk-download die er vaak aan voorafgaat:

<!-- query
platform: sentinel
name: Bulk file download by a single account within an hour
technique: T1537
severity: Medium
tactics: [Exfiltration]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// Ongewoon veel gedownloade bestanden door één account binnen een uur.
let lookback = 1d;
let threshold = 100;                 // ijk op de eigen organisatie
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Files = dcount(SourceFileName),
            Extensions = make_set(SourceFileExtension, 15),
            Sites = make_set(Site_Url, 10),
            IPs = make_set(ClientIP, 10)
    by UserId, bin(TimeGenerated, 1h)
| where Files > threshold
| order by Files desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents)

<!-- query
platform: defender-xdr
name: Anonymous or guest sharing links created in SharePoint and OneDrive
technique: T1537
severity: Medium
tactics: [Exfiltration]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->
```kql
let lookback = 7d;
let ShareActions = dynamic(["AnonymousLinkCreated", "SecureLinkCreated",
                            "AddedToSecureLink", "SharingInvitationCreated",
                            "CompanyLinkCreated", "SharingSet"]);
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType in~ (ShareActions)
| extend Target = tostring(RawEventData.TargetUserOrGroupName)
| extend TargetType = tostring(RawEventData.TargetUserOrGroupType)
| extend File = tostring(RawEventData.SourceFileName)
| where ActionType =~ "AnonymousLinkCreated" or TargetType in~ ("Guest", "Partner")
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, Target,
          TargetType, File, ObjectName, IPAddress, CountryCode, UserAgent,
          IsExternalUser, UncommonForUser
| order by Timestamp desc
```

De kolom `UncommonForUser` is hier bruikbaar als goedkope tuning: Microsoft
vult die met de attributen van het event die ongebruikelijk zijn voor deze
gebruiker. Een lege string betekent dat het event niet is verrijkt; `[]`
betekent verrijkt zonder afwijking.

## Waarom dit BEC is

Het advies vat T1537 samen als *"Het verplaatsen van data tussen verschillende
cloudresources"* en plaatst het onder Lateral Movement, samen met interne
spearphishing en spearphishing via een clouddienst. Dat is voor een BEC-context
de juiste plaatsing, ook al staat de techniek in ATT&CK onder Exfiltration: bij
BEC is het doel van het delen zelden de data zelf, maar het bereiken van een
volgend slachtoffer of het meenemen van het bewijsmateriaal dat een frauduleus
betaalverzoek geloofwaardig maakt.

Twee concrete BEC-patronen die deze queries raken:

1. **De factuurset.** De aanvaller deelt of downloadt de map met openstaande
   facturen en inkooporders. Die documenten leveren de bedragen, de
   referentienummers en de huisstijl waarmee het frauduleuze betaalverzoek
   overtuigend wordt. Volume laag, impact hoog — precies wat
   `Unusual volume of external file sharing` mist.
2. **Het deelbare aas.** De aanvaller zet een document in de eigen OneDrive,
   maakt er een anonieme link op en deelt die vervolgens intern. Zie
   [T1566.003](T1566.003-spearphishing-via-service.md); de deelactie is
   zichtbaar in dezelfde tabellen als hierboven.

Let bij het beoordelen op de combinatie met de andere technieken uit dit
cluster. Een externe deling die binnen hetzelfde uur valt als een nieuwe
verbergregel ([T1564.008](T1564.008-email-hiding-rules.md)) of een intra-org
fan-out ([T1534](T1534-internal-spearphishing.md)) is geen losse gebeurtenis
meer.

## Referenties

- Microsoft, alert policies (inclusief de uitfaseringsnotitie bij Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, auditactiviteiten (deel-operations SharePoint/OneDrive): https://learn.microsoft.com/en-us/purview/audit-log-activities
- Microsoft, anomaliedetectiebeleid Defender for Cloud Apps (welke policies zijn uitgezet): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, OfficeActivity-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, Management Activity API-schema (SharePointSharingOperation = 14, SharePointFileOperation = 6): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- MITRE ATT&CK T1537: https://attack.mitre.org/techniques/T1537/
