# T1078 — Valid Accounts (gast- en delegatietoegang tot mail en SharePoint)

| | |
|---|---|
| **MITRE-tactiek** | Collection |
| **Whitepaper-maatregelen** | 016 — Blokkering van automatische e-mailforwarding (prioriteit Hoog)<br>017 — Teams & SharePoint-collaboration beperken (prioriteit Midden) |
| **Verwante technieken** | [T1114.002](T1114.002-remote-email-collection.md) — mailboxdelegatie; [T1530](T1530-data-from-cloud-storage.md) — wat de gast dan leest; [T1567](T1567-exfiltration-over-web-services.md) — vergeten gasttoegang opruimen |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — bouw hier een eigen analytic rule
>
> Er bestaat geen enkele standaard alert policy voor gasttoegang. De vier
> secties met default alert policies in de Defender-portal (Information
> governance, Mail flow, Permissions, Threat management) bevatten er geen die
> vuurt op het uitnodigen van een gast, het inwisselen van een uitnodiging, of
> op een gastaccount dat plotseling actief wordt. De enige policy in de
> categorie Permissions is `Elevation of Exchange admin privilege` (severity
> **Low**) en die gaat over Exchange-rolgroepen. Dit is dus volledig eigen werk.

## Is er een Defender-alert voor?

**Nee, voor geen van de drie ingangen.**

| Ingang | Alert policy | Oordeel |
|---|---|---|
| Gastaccount uitgenodigd of ingewisseld | geen | De Entra-auditactiviteiten `Invite external user` en `Redeem external user invite` bestaan wel, maar er is geen alert policy die erop vuurt. |
| Gastaccount benadert SharePoint of Teams | geen | Zie [T1530](T1530-data-from-cloud-storage.md); de MDCA-anomaliedetecties zijn volume-gebaseerd. |
| Mailboxdelegatie toegekend | geen | `Add-MailboxPermission` heeft geen alert policy. Zie [T1114.002](T1114.002-remote-email-collection.md) voor de delegatiequery. |

| | |
|---|---|
| **Alert policy (dichtstbijzijnde)** | `Elevation of Exchange admin privilege` |
| **Standaard severity** | **Low** |
| **Licentie** | E1/F1/G1, E3/F3/G3 of E5/G5 |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

Los daarvan: het risico dat een gastaccount kan inloggen zonder MFA of vanaf een
onbekende locatie hoort thuis bij maatregel 006 (voorwaardelijk toegangsbeleid)
en 007 (monitoring van verdachte inlogpogingen), niet bij deze detectie. Dit
bestand gaat over wat een geldig gast- of delegatie-account daarna dóét.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, categorie *AuditLogs*. Nodig voor uitnodigingen en gastlevenscyclus. |
| Microsoft Sentinel | `SigninLogs` | Data connector **Microsoft Entra ID**, categorie *SignInLogs*. Bevat de kolom `UserType` met waarden `member` en `guest`, plus `CrossTenantAccessType` en `HomeTenantId`. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** (SharePoint- en Exchange-workload). Voor wat de gast benadert; `TargetUserOrGroupType` is hier `Guest`. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps, Microsoft 365-appconnector met *Microsoft 365 activities*. Bevat `IsExternalUser` en `IsImpersonated`. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | Vereist **Microsoft Entra ID P2**. Bevat `IsGuestUser` en `IsExternalUser`. Vervangt per 19 okt 2026 `AADSignInEventsBeta`. |

Zonder maatregel 012 (UAL aan) doen de `OfficeActivity`-queries niets.

## KQL — Sentinel (AuditLogs, SigninLogs, OfficeActivity)

<!-- query
platform: sentinel
name: Guest account invited or invitation redeemed
technique: T1078
severity: Low
tactics: [InitialAccess, Persistence]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// 1. Gastaccounts die worden uitgenodigd en ingewisseld. De gedocumenteerde
//    Entra-auditactiviteiten staan onder de categorie UserManagement.
let lookback = 1d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in~ ("Invite external user",
                           "Invite external user with reset invitation status",
                           "Invite internal user to B2B collaboration",
                           "Redeem external user invite",
                           "Bulk invite users - finished (bulk)")
| extend Inviter = tostring(InitiatedBy.user.userPrincipalName)
| extend Guest   = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Category, Result, Inviter, Guest, TargetResources
| order by TimeGenerated desc
```

<!-- query
platform: sentinel
name: Dormant guest account signs in again
technique: T1078
severity: Medium
tactics: [InitialAccess, Persistence]
interval: P1D
lookback: P60D
parameters: []
deployable: true
-->
```kql
// 2. Gastaccount dat na langere stilte weer inlogt. Dat is het patroon van
//    'vergeten toegang' uit maatregel 018 en het patroon van een overgenomen
//    gastaccount. UserType is gedocumenteerd met de waarden member en guest.
let lookback     = 1d;
let baseline     = 60d;
let activeRecent = SigninLogs
    | where TimeGenerated > ago(baseline) and TimeGenerated < ago(lookback)
    | where UserType =~ "guest"
    | where ResultType == 0
    | distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(lookback)
| where UserType =~ "guest"
| where ResultType == 0
| where UserPrincipalName !in (activeRecent)
| project TimeGenerated, UserPrincipalName, UserDisplayName, AppDisplayName,
          ResourceDisplayName, IPAddress, Location, ClientAppUsed,
          CrossTenantAccessType, HomeTenantId, ConditionalAccessStatus,
          AuthenticationRequirement, RiskLevelDuringSignIn, SessionId
| order by TimeGenerated desc
```

<!-- query
platform: sentinel
name: Guest user activity in SharePoint or OneDrive
technique: T1078
severity: Informational
tactics: [Collection]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->
```kql
// 3. Wat de gast vervolgens doet in SharePoint/OneDrive. Bij deelacties staat
//    de ontvanger in TargetUserOrGroupName en is TargetUserOrGroupType 'Guest';
//    bij toegangsacties herken je de gast aan #EXT# in de UPN.
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload in~ ("SharePoint", "OneDrive")
| where UserId has "#EXT#" or TargetUserOrGroupType =~ "Guest"
| project TimeGenerated, UserId, Operation, RecordType,
          TargetUserOrGroupName, TargetUserOrGroupType, SharingType,
          Site_Url, SourceRelativeUrl, SourceFileName, ClientIP, UserAgent
| order by TimeGenerated desc
```

<!-- query
platform: sentinel
name: Mailbox delegation or folder permission granted
technique: T1078
severity: Medium
tactics: [Collection, Persistence]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// 4. Delegatie op de mailbox — dezelfde logica, andere workload.
//    Uitgebreide variant met parameter-extractie staat in T1114.002.
let lookback = 1d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("Add-MailboxPermission", "Add-RecipientPermission", "UpdateFolderPermissions")
| project TimeGenerated, UserId, Operation, MailboxOwnerUPN,
          Parameters, ClientIP, ExternalAccess, ResultStatus
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents, EntraIdSignInEvents)

<!-- query
platform: defender-xdr
name: External user activity summarised across connected cloud apps
technique: T1078
severity: Informational
tactics: [Collection]
interval: P1D
lookback: P7D
parameters: []
deployable: false
-->
```kql
// Activiteit van externe gebruikers over alle aangesloten workloads heen.
// IsExternalUser is een gedocumenteerde kolom van CloudAppEvents.
let lookback = 7d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where IsExternalUser == true
| summarize Actions   = count(),
            Kinds     = make_set(ActionType, 20),
            Apps      = make_set(Application, 10),
            IPs       = make_set(IPAddress, 10),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
        by AccountDisplayName, AccountObjectId
| order by Actions desc
```

<!-- query
platform: defender-xdr
name: Guest account signs in to a resource it never used before
technique: T1078
severity: Medium
tactics: [InitialAccess, Collection]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->
```kql
// Gastaccounts die een resource benaderen die ze niet eerder benaderden.
// EntraIdSignInEvents vereist Entra ID P2; tot 19 okt 2026 heet deze tabel
// ook nog AADSignInEventsBeta.
let lookback = 1d;
let baseline = 30d;
let known    = EntraIdSignInEvents
    | where Timestamp between (ago(baseline) .. ago(lookback))
    | where IsGuestUser == true
    | distinct AccountUpn, ResourceDisplayName;
EntraIdSignInEvents
| where Timestamp > ago(lookback)
| where IsGuestUser == true
| where ErrorCode == 0
| join kind=leftanti known on AccountUpn, ResourceDisplayName
| project Timestamp, AccountUpn, AccountObjectId, ResourceDisplayName,
          Application, IPAddress, Country, ClientAppUsed, UserAgent,
          AuthenticationRequirement, ConditionalAccessStatus, SessionId
| order by Timestamp desc
```

## Aanscherpen op vertrouwde domeinen

Maatregel 017 vraagt om een allowlist van vertrouwde domeinen. Zolang die er is,
is het interessante geval een gast van buiten die lijst. Vervang in query 1 en 2
de laatste filterregel:

<!-- query
platform: sentinel
name: Guest activity filtered to domains outside the trusted partner list
technique: T1078
severity: Low
tactics: [InitialAccess]
interval: PT1H
lookback: P1D
parameters: [trustedPartners]
deployable: false
-->
```kql
// bovenaan de query:
let trustedPartners = dynamic(["trustedpartner.example", "trustedcustomer.example"]);   // <-- aanpassen
// als laatste filterregel:
| extend GuestDomain = tolower(tostring(split(replace_string(Guest, "_", "@"), "@")[-1]))
| where not(GuestDomain in~ (trustedPartners))
```

Let op dat gast-UPN's in Entra de vorm `naam_extern.com#EXT#@yourdomain.onmicrosoft.com`
hebben; het echte domein zit vóór `#EXT#`, niet erachter. Test deze extractie
tegen je eigen data voordat je hem als filter gebruikt.

## Waarom dit BEC is

Een gastaccount is een geldig account: het passeert geen inbraakdetectie, het
staat niet in de lijst met medewerkers, en het verdwijnt niet bij een
uitdiensttreding. Het NCSC/Cyclotron-advies noemt onder maatregel 017 precies
deze drie ingangen — *"gastaccounts, verkeerd geconfigureerde deelinstellingen
of anonieme links"* — en onder maatregel 018 het gevolg: *"Bij BEC-incidenten
maken aanvallers vaak misbruik van 'vergeten' toegang, zoals oude gastaccounts
die niet meer in gebruik zijn."*

Voor de mailkant geldt hetzelfde met delegatie: FullAccess of Send-As op een
mailbox overleeft een wachtwoordwijziging en een MFA-reset van het slachtoffer,
net als een forwardingregel. Wie na een incident alleen het wachtwoord reset en
de sessies intrekt, laat deze twee ingangen open staan.

## Referenties

- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, Entra audit log activity reference (Access reviews, Invited users): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, SigninLogs-schema (kolom UserType): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, OfficeActivity-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents-schema (IsExternalUser): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, EntraIdSignInEvents-schema (IsGuestUser): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, sharing auditing in het auditlog (TargetUserOrGroupType): https://learn.microsoft.com/en-us/purview/audit-log-sharing
- Microsoft, mailbox auditing beheren (sign-in types Owner/Delegate/Admin): https://learn.microsoft.com/en-us/purview/audit-mailboxes
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
