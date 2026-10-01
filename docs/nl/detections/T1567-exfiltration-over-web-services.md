# T1567 — Exfiltration Over Web Services

| | |
|---|---|
| **MITRE-tactiek** | Exfiltration |
| **Whitepaper-maatregel** | 018 — Access Reviews (prioriteit Midden) |
| **Verwante technieken** | [T1530](T1530-data-from-cloud-storage.md) — het verzamelen; [T1078](T1078-valid-accounts-guest-delegation.md) — de vergeten toegang die hier misbruikt wordt |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> De enige standaard alert policy op dit terrein,
> `Unusual volume of external file sharing`, is **Medium**, vereist E5/G5 of
> Defender for Office 365 Plan 2, én staat op de nominatie om te verdwijnen:
> Microsoft schrijft dat de policies in die sectie *"in the process of being
> deprecated based on customer feedback as false positives"* zijn, met het advies
> om er zelf een custom policy voor te maken. Dat is exact wat dit bestand doet.
> Bijkomend argument: de policy meet volume, terwijl bij BEC één anonieme link
> naar één map met facturen genoeg is.

## Is er een Defender-alert voor?

**Ja, maar hij wordt uitgefaseerd.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Beschrijving (Microsoft)** | *"Generates an alert when an unusually large number of files in SharePoint or OneDrive are shared with users outside of your organization."* |
| **Standaard severity** | **Medium** |
| **Licentie** | E5/G5 of Defender for Office 365 Plan 2 add-on |
| **Categorie** | Information governance |
| **Status** | **Wordt uitgefaseerd wegens valse positieven.** Boven de sectie *Information governance alert policies* staat: *"The alert policies in this section are in the process of being deprecated based on customer feedback as false positives. To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* Deze policy is de enige in die sectie. Geverifieerd 22 aug 2026 op de pagina met ms.date 2026-08-03. |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

Voor de toegangsbeoordelingen zelf (de kern van maatregel 018) bestaat geen
alert policy. Wél zijn de handelingen als Entra-auditactiviteiten
gedocumenteerd, onder de categorieën `Policy`, `UserManagement` en
`DirectoryManagement`: `Create access review`, `Update access review`,
`Delete access review`, `Access review ended`, `Apply decision`,
`Approve decision`, `Deny decision`, `Auto review`, `Auto apply review`,
`Apply review`. Daarmee kun je meten of de maatregel überhaupt draait — zie de
laatste query.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**, SharePoint-workload aan. Deelacties komen binnen met `RecordType` = `SharePointSharingOperation`; er is géén aparte `SharePointFileOperation`-tabel in Log Analytics. Vereist maatregel 012 (UAL aan). |
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, categorie *AuditLogs*. Voor de access-review-activiteiten. Access reviews zelf vereisen **Microsoft Entra ID Governance** of Entra ID P2 — dat is een randvoorwaarde van maatregel 018, geen detectiekeuze. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps, Microsoft 365-appconnector met *Microsoft 365 activities*. Retentie 30 dagen. |

## De deelacties die ertoe doen

Microsoft documenteert per manier van delen een eigen event. Voor exfiltratie
zijn dit de gevallen die je wilt zien, met de reden waarom:

| Operatie | Wat Microsoft erover zegt | Waarom dit BEC-relevant is |
|---|---|---|
| `AnonymousLinkCreated` | *"An anonymous link (also called an 'Anyone' link) is created for a resource. Because an anonymous link can be created and then copied, it's reasonable to assume that any document that has an anonymous link is shared with a target user."* | Geen ontvanger, geen authenticatie, geen intrekking bij het uitzetten van een account. De schoonste exfiltratieroute die SharePoint kent. |
| `AnonymousLinkUsed` | *"This event is logged when an anonymous link is used to access a resource."* | Bewijs dat de link daadwerkelijk gebruikt is, met IP. |
| `SecureLinkCreated` + `AddedToSecureLink` | *"A user creates a 'specific people link'… The person that the resource is shared with is identified in the audit record for the AddedToSecureLink event."* De tijdstempels van beide liggen vlak bij elkaar. | De ontvanger staat pas in het tweede event. Wie alleen op `SecureLinkCreated` filtert, ziet niet met wie er gedeeld is. |
| `SharingInvitationCreated` / `SharingInvitationAccepted` | Uitnodiging naar een extern adres, en het moment dat die wordt ingewisseld. | Het gat tussen die twee events is het venster waarin je nog kunt intrekken. |

Externe ontvangers herken je aan `TargetUserOrGroupType`. Microsoft: *"Identifies
whether the target user or group is a Member, Guest, SharePointGroup,
SecurityGroup, or Partner"* — bij een gedeelde resource met iemand buiten de
organisatie is de waarde **`Guest`**.

## KQL — Sentinel (OfficeActivity)

<!-- query
platform: sentinel
name: External file sharing operations in SharePoint and OneDrive
technique: T1567
severity: Low
tactics: [Exfiltration]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->

```kql
// Delen naar buiten: anonieme links, specific-people-links en uitnodigingen.
// AddedToSecureLink staat er expliciet bij omdat SecureLinkCreated de
// ontvanger niet bevat.
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where RecordType =~ "SharePointSharingOperation"
       or Operation in~ ("AnonymousLinkCreated", "AnonymousLinkUsed",
                         "SecureLinkCreated", "AddedToSecureLink",
                         "SharingInvitationCreated", "SharingInvitationAccepted",
                         "SharingSet", "CompanyLinkCreated")
| project TimeGenerated, UserId, Operation, TargetUserOrGroupName, TargetUserOrGroupType,
          SharingType, UniqueSharingId, Site_Url, SourceRelativeUrl, SourceFileName,
          SourceFileExtension, ClientIP, UserAgent, EventSource, EventData
| order by TimeGenerated desc
```

Aanscherpen op werkelijk extern:

<!-- query
platform: sentinel
name: External sharing narrowed to guest recipients, anonymous links or non-allowlisted domains
technique: T1567
severity: Low
tactics: [Exfiltration]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->

```kql
// (a) alleen ontvangers buiten de organisatie
| where TargetUserOrGroupType =~ "Guest"

// (b) of: anonieme links, ongeacht ontvanger — die hebben er per definitie geen
| where Operation in~ ("AnonymousLinkCreated", "AnonymousLinkUsed")

// (c) domeinfilter op de ontvanger, als er een allowlist is (maatregel 017)
| extend RecipientDomain = tolower(tostring(split(TargetUserOrGroupName, "@")[1]))
| where isnotempty(RecipientDomain)
| where RecipientDomain !in~ ("trustedpartner.example", "trustedcustomer.example")   // <-- aanpassen
```

Het patroon dat er in de praktijk het meest toe doet — een gebruiker die binnen
één uur meerdere externe deellinks maakt op financiële documenten:

<!-- query
platform: sentinel
name: Multiple external sharing links on finance-related documents within one hour
technique: T1567
severity: Medium
tactics: [Exfiltration]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
let lookback = 1d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("AnonymousLinkCreated", "SecureLinkCreated", "AddedToSecureLink",
                       "SharingInvitationCreated")
| extend Path = tolower(strcat(SourceRelativeUrl, "/", SourceFileName))
| where Path has_any ("factuur", "invoice", "iban", "betaling", "payment",
                     "crediteur", "creditor", "contract", "bankgegevens")
| summarize Count = count(),
            Files = make_set(SourceFileName, 25),
            Recipients = make_set(TargetUserOrGroupName, 25),
            IPs = make_set(ClientIP, 5)
        by UserId, bin(TimeGenerated, 1h)
| where Count >= 3          // <-- threshold afstemmen op je eigen baseline
| order by Count desc
```

## KQL — Sentinel (AuditLogs): draait maatregel 018 eigenlijk?

Deze query detecteert geen aanvaller maar het ontbreken van de maatregel. Dat is
bij 018 het punt: vergeten toegang ontstaat doordat niemand hem beoordeelt.

<!-- query
platform: sentinel
name: Access review activity in the tenant (control assurance check)
technique: T1567
severity: Informational
tactics: [Exfiltration]
interval: P1D
lookback: P90D
parameters: []
deployable: false
-->

```kql
// Access reviews die zijn aangemaakt, beëindigd of waarvan beslissingen zijn
// toegepast. Levert dit over 90 dagen niets op, dan bestaat de maatregel op
// papier en niet in de tenant.
let lookback = 90d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in~ ("Create access review", "Update access review",
                           "Delete access review", "Access review ended",
                           "Apply decision", "Approve decision", "Deny decision",
                           "Auto review", "Auto apply review", "Apply review")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| summarize Count = count(), Last = max(TimeGenerated), Actors = make_set(Actor, 10)
        by OperationName, Category
| order by Last desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents)

<!-- query
platform: defender-xdr
name: External sharing operations seen through Defender for Cloud Apps
technique: T1567
severity: Low
tactics: [Exfiltration]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->

```kql
let lookback = 7d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType in~ ("AnonymousLinkCreated", "AnonymousLinkUsed",
                        "SecureLinkCreated", "AddedToSecureLink",
                        "SharingInvitationCreated", "SharingInvitationAccepted",
                        "SharingSet", "CompanyLinkCreated")
| extend Recipient     = tostring(RawEventData.TargetUserOrGroupName)
| extend RecipientType = tostring(RawEventData.TargetUserOrGroupType)
| extend SiteUrl       = tostring(RawEventData.SiteUrl)
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId,
          Recipient, RecipientType, ObjectName, ObjectType, SiteUrl,
          IPAddress, CountryCode, UserAgent, IsExternalUser, UncommonForUser
| order by Timestamp desc
```

## Waarom dit BEC is

Bij BEC is exfiltratie zelden een grote datadump; het is één map met facturen
die via een "Anyone"-link naar buiten gaat, of een gastaccount van een
ex-leverancier dat er nog bij kan. Het NCSC/Cyclotron-advies koppelt T1567
daarom expliciet aan access reviews en niet aan een DLP-maatregel: *"Bij
BEC-incidenten maken aanvallers vaak misbruik van 'vergeten' toegang, zoals oude
gastaccounts die niet meer in gebruik zijn of onnodig ruime rechten op mappen
met gevoelige financiële informatie."*

De anonieme link is daarbij de scherpste variant, omdat Microsoft zelf stelt dat
je bij zo'n link moet aannemen dat het document gedeeld is — de link kan
gekopieerd zijn zonder dat er ergens een ontvanger geregistreerd staat.

## Referenties

- Microsoft, alert policies (incl. deprecation Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, sharing auditing in het auditlog: https://learn.microsoft.com/en-us/purview/audit-log-sharing
- Microsoft, Entra audit log activity reference (Access reviews): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, Office 365 Management Activity API-schema (SharePoint Sharing-schema): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- Microsoft, OfficeActivity-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- MITRE ATT&CK T1567: https://attack.mitre.org/techniques/T1567/
