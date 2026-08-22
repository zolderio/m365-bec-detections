# T1068 — Exploitation for Privilege Escalation

| | |
|---|---|
| **Naam in het advies** | Exploitation for Privilege Escalation — het misbruiken van configuratiefouten om beheerrechten te verkrijgen |
| **Naam in MITRE ATT&CK** | Exploitation for Privilege Escalation |
| **MITRE-tactiek** | Privilege Escalation (TA0004) |
| **Whitepaper-maatregel** | 010 — Least Privilege-principe & PIM (prioriteit Midden) |
| **Verwante technieken** | [T1098.001](T1098.001-additional-cloud-credentials.md) — MITRE plaatst die techniek óók onder Privilege Escalation |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../teststatus.md) |

> **Scopeverschil, bewust benoemd.** MITRE beschrijft T1068 als het misbruiken
> van softwarekwetsbaarheden om lokaal of kernel-niveau rechten te krijgen, met
> als platforms Containers, Linux, Windows en macOS — géén cloud- of
> identityplatform. Het advies gebruikt het ID voor iets anders: rechtenmisbruik
> in de tenant door te ruime of permanente beheerrollen. Deze detectie volgt de
> bedoeling van het advies (maatregel 010) en dus de identitykant. Wie
> T1068 in de MITRE-betekenis wil dekken, komt uit bij endpointdetectie en niet
> bij de tabellen hieronder.

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE` — allebei nodig
>
> `Elevation of Exchange admin privilege` bestaat, vereist géén E5 en zit in
> E1/E3, dus die zet je aan en die routeer je naar een postbus waar iemand
> kijkt. Maar hij dekt twee dingen niet. Ten eerste alleen Exchange Online: een
> toewijzing aan een Entra-directoryrol zoals Global Administrator of Privileged
> Role Administrator valt er buiten en heeft géén alert policy. Ten tweede is de
> standaard-severity **Low**, en anders dan vaak wordt aangenomen is die niet op
> te hogen: de instellingen van een standaardpolicy zijn niet te bewerken en
> `Set-ProtectionAlert` weigert default policies. Een eigen alert policy met
> `New-ProtectionAlert -Severity High` is de omweg. De Entra-kant bouw je in
> Sentinel op `AuditLogs`.

## Is er een Defender-alert voor?

**Voor Exchange wel, voor Entra niet — en de PIM-alert die er het dichtst bij
komt kost Entra ID P2.**

| | |
|---|---|
| **Alert policy** | `Elevation of Exchange admin privilege` |
| **Standaard severity** | **Low** |
| **Licentie** | E1/F1/G1, E3/F3/G3 of E5/G5 — geen add-on nodig |
| **Categorie** | Permissions |
| **Wat het dekt** | Microsoft: *"Generates an alert when someone is assigned administrative permissions in your Exchange Online organization. For example, when a user is added to the Organization Management role group in Exchange Online."* |
| **Wat het niet dekt** | Toewijzingen aan Microsoft Entra-directoryrollen. Daar is geen default alert policy voor. |

### Severity ophogen kan niet — dit is de correctie

Microsoft over de default alert policies: *"You can turn off these policies (or
back on again), set up a list of recipients to send email notifications to, and
set a daily notification limit. **The other settings for these policies can't be
edited.**"* En bij de cmdlet: *"You can't use this cmdlet to edit default alert
policies. You can only modify alerts that you created using the
New-ProtectionAlert cmdlet."*

De omweg is een eigen policy met `New-ProtectionAlert` en `-Severity High`.
Let op de licentiegrens: alert policies met een drempelwaarde of op basis van
"ongebruikelijke activiteit" vereisen E5/G5 of een add-on; met E1/F1/G1 of
E3/F3/G3 kun je alleen policies maken die vuren bij elke keer dat de activiteit
voorkomt. Voor rolwijzigingen is dat precies goed — het volume is laag. Deze
route is **niet geverifieerd** tegen een tenant.

Wat je wél zonder enige licentie kunt doen bij de bestaande policy: e-mail-
notificaties inschakelen en de ontvangers instellen. Dat is maatregel 011 uit
het advies (security alerts doorsturen) en het is hier de goedkoopste winst.

### Wat Entra zelf levert: PIM-alerts

Privileged Identity Management heeft eigen alerts, met een severity die Microsoft
per alert documenteert:

| PIM-alert | Severity |
|---|---|
| `Roles are being assigned outside of Privileged Identity Management` | **High** |
| `Potential stale accounts in a privileged role` | **Medium** |
| `Administrators aren't using their privileged roles` | **Low** |
| `Roles don't require multifactor authentication for activation` | **Low** |
| `There are too many Global Administrators` | **Low** |
| `Roles are being activated too frequently` | **Low** |
| `The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance` | **Low** |

De eerste is de detectie die bij maatregel 010 hoort: een rol die buiten PIM om
wordt toegekend is óf een procesfout óf een aanvaller. Microsoft: *"Privileged
role assignments made outside of Privileged Identity Management aren't properly
monitored and might indicate an active attack."* PIM stuurt voor deze alert
e-mail naar Privileged Role Administrators, Security Administrators en Global
Administrators, mits de alert in de alertinstellingen is ingeschakeld.

| | |
|---|---|
| **Licentie PIM** | Vereist licenties; zie *Microsoft Entra ID Governance licensing fundamentals*. In de praktijk Microsoft Entra ID P2 of Entra ID Governance — PIM heeft daar zelfs een eigen alert voor (`The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance`). |
| **Wie mag PIM-alerts lezen** | Alleen Global Administrator, Privileged Role Administrator, Global Reader, Security Administrator en Security Reader. |

### Entra ID Protection

`Anomalous user activity` (user risk, offline, riskEventType
`anomalousUserActivity`, **Microsoft Entra ID P2**) is de enige detectie die
hierbij in de buurt komt: *"This risk detection baselines normal administrative
user behavior in Microsoft Entra ID, and spots anomalous patterns of behavior
like suspicious changes to the directory."* Het is een heuristiek over
beheerdersgedrag, geen alert op een specifieke roltoewijzing. Zonder P2 zie je
alleen `Additional risk detected` zonder details.

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, logcategorie **AuditLogs** aangevinkt in de diagnostic setting. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** met de Exchange-workload aan, voor de Exchange-rolgroepen. Vereist een ingeschakelde Unified Audit Log — **whitepaper-maatregel 012**. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps met de Microsoft 365-connector. Retentie 30 dagen. |
| Defender XDR advanced hunting | `AlertInfo` | Om vast te stellen of `Elevation of Exchange admin privilege` daadwerkelijk vuurt. |

De Entra-kant hangt **niet** aan maatregel 012; de Exchange-kant (`OfficeActivity`)
wél. Staat de UAL uit, dan levert de Exchange-query niets op en is dat geen
detectieprobleem maar een loggingprobleem.

## KQL — Sentinel (AuditLogs): toewijzing aan een Entra-directoryrol

```kql
// Alle roltoewijzingen, permanent en eligible. De PIM-varianten staan er bewust
// bij: als de organisatie PIM gebruikt, is het onderscheid tussen "via PIM" en
// "erbuiten om" precies wat je wilt zien.
let lookback = 30d;
let gevoelige_rollen = dynamic([
    "Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator",
    "Exchange Administrator","Security Administrator","Application Administrator",
    "Cloud Application Administrator","User Administrator","Authentication Administrator",
    "Hybrid Identity Administrator","Partner Tier2 Support"]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "RoleManagement"
| where OperationName in ("Add member to role", "Add eligible member to role",
                          "Add scoped member to role",
                          "Add member to role scoped over Restricted Management Administrative Unit")
      or OperationName startswith "Add member to role in PIM"
      or OperationName startswith "Add eligible member to role in PIM"
| where Result == "success"
| extend Actor   = coalesce(tostring(InitiatedBy.user.userPrincipalName),
                            tostring(InitiatedBy.app.displayName))
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
// De doelgebruiker en de rolnaam zitten in verschillende elementen van
// TargetResources; mv-expand voorkomt dat je de rolnaam mist door een vaste index.
| mv-expand Doel = TargetResources
| extend DoelType = tostring(Doel.type)
| extend DoelNaam = coalesce(tostring(Doel.userPrincipalName), tostring(Doel.displayName))
| extend RolNaam  = tostring(parse_json(tostring(Doel.modifiedProperties))[1].newValue)
| extend RolNaam  = trim('"', tostring(RolNaam))
| extend Gevoelig = RolNaam in (gevoelige_rollen)
// LoggedByService laat zien of PIM de toewijzing deed. Is dat niet zo bij een
// tenant die PIM gebruikt, dan is dit de "assigned outside of PIM"-situatie.
| project TimeGenerated, OperationName, Actor, ActorIP, DoelType, DoelNaam,
          RolNaam, Gevoelig, LoggedByService, CorrelationId
| order by TimeGenerated desc
```

De positie van de rolnaam binnen `modifiedProperties` verschilt per
activiteitstype; de index `[1]` hierboven is de gebruikelijke plaats voor
`Role.DisplayName` maar is **niet geverifieerd**. Controleer met één
voorbeeldevent en pas aan, of laat de extractie weg en beoordeel
`Doel.modifiedProperties` handmatig.

## KQL — Sentinel: roltoewijzing buiten PIM om

```kql
// De Sentinel-tegenhanger van de PIM-alert "Roles are being assigned outside of
// Privileged Identity Management". Bruikbaar in tenants die PIM gebruiken.
// LoggedByService bevat volgens de tabeldocumentatie onder meer "Core Directory"
// en "Privileged Identity Management".
let lookback = 30d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "RoleManagement"
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
| where LoggedByService !has "Privileged Identity Management"
| extend Actor    = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorIP  = tostring(InitiatedBy.user.ipAddress)
| mv-expand Doel = TargetResources
| extend DoelNaam = coalesce(tostring(Doel.userPrincipalName), tostring(Doel.displayName))
| project TimeGenerated, OperationName, LoggedByService, Actor, ActorIP, DoelNaam,
          Doel, CorrelationId
| order by TimeGenerated desc
```

Draai eerst `AuditLogs | where Category == "RoleManagement" | distinct
LoggedByService` om vast te stellen welke waarden jouw tenant schrijft. De exacte
schrijfwijze van de PIM-waarde is **niet geverifieerd**.

## KQL — Sentinel (OfficeActivity): Exchange-rolgroepen

```kql
// De Exchange-kant, waar het alert Elevation of Exchange admin privilege op zit.
// Dit is de query die je gebruikt om te controleren of dat alert compleet is —
// en om er een eigen, hoger gewaardeerde regel op te bouwen.
let lookback = 30d;
let kritieke_rolgroepen = dynamic([
    "Organization Management","Recipient Management","Compliance Management",
    "Discovery Management","Records Management","Security Administrator",
    "Hygiene Management","View-Only Organization Management"]);
OfficeActivity
| where TimeGenerated > ago(lookback)
| where RecordType == "ExchangeAdmin"
| where Operation in~ ("Add-RoleGroupMember", "Update-RoleGroupMember",
                       "New-RoleGroup", "New-ManagementRoleAssignment",
                       "Add-MailboxPermission")
| extend Params = tostring(Parameters)
| extend Rolgroep = extract(@"(?i)""Name""\s*:\s*""Identity""\s*,\s*""Value""\s*:\s*""([^""]+)""", 1, Params)
| extend Kritiek = Rolgroep in~ (kritieke_rolgroepen)
| project TimeGenerated, UserId, Operation, ClientIP, Rolgroep, Kritiek, Params,
          OriginatingServer
| order by TimeGenerated desc
```

De parsing van `Parameters` is best effort: het is een JSON-string waarvan de
volgorde niet gegarandeerd is. Het `Params`-veld staat daarom ook in de output,
zodat een analist altijd de ruwe inhoud ziet.

## KQL — Defender XDR advanced hunting: vuurt het alert eigenlijk?

```kql
// Controleer of de alert policy daadwerkelijk alerts produceert en met welke
// severity ze binnenkomen. Een policy die aan staat maar nooit vuurt, is geen
// dekking.
AlertInfo
| where Timestamp > ago(90d)
| where Title has "Exchange admin privilege"
| project Timestamp, Title, Severity, Category, ServiceSource, DetectionSource, AlertId
| order by Timestamp desc
```

```kql
// Rolwijzigingen in CloudAppEvents, voor tenants die geen Entra-diagnostic
// setting naar Log Analytics hebben. Entra-auditevents komen binnen onder
// Application "Office 365".
let lookback = 30d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Office 365"
| where ActionType has_any ("Add member to role", "Add eligible member to role",
                            "Add-RoleGroupMember", "New-ManagementRoleAssignment")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress,
          CountryCode, Isp, UserAgent, IsAdminOperation, ObjectName, RawEventData
| order by Timestamp desc
```

De exacte `ActionType`-waarden voor rolwijzigingen in `CloudAppEvents` zijn
**niet geverifieerd**; `has_any` is hier bewust ruim gekozen. Inventariseer met
`CloudAppEvents | where Application == "Office 365" | where ActionType has "role"
| distinct ActionType`.

## Waarom dit BEC is

Bij BEC is rechtenescalatie zelden het doel op zich en bijna altijd de opmaat
naar bereik: van één mailbox naar alle mailboxen, of naar het uitzetten van de
logging en de alerts (maatregel 011 en 013). Het advies formuleert het bij
maatregel 010 zo: *"Te ruime of permanente beheerrechten geven aanvallers de
mogelijkheid om rechten aan te passen, nieuwe accounts te maken of
beveiligingsinstellingen uit te schakelen."*

De praktijkvariant staat in Microsofts responderguidance van 25 januari 2024:
de actor gaf zichzelf via een gecompromitteerde OAuth-app de rol
`full_access_as_app` op Office 365 Exchange Online — *"which allows access to
mailboxes"*. Dat is rechtenescalatie zonder dat er ooit een gebruiker aan een
rolgroep is toegevoegd, en het is de reden dat deze detectie samen met
[T1671](T1671-illicit-consent-grant.md) en
[T1098.001](T1098.001-additional-cloud-credentials.md) gelezen moet worden: in
Microsoft 365 loopt de weg naar meer rechten net zo vaak via een app als via een
rol.

## Referenties

- Microsoft, alert policies (`Elevation of Exchange admin privilege`, severity, licentie, en dat default policies niet te bewerken zijn): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, `Set-ProtectionAlert` (default policies niet bewerkbaar, `-Severity`-waarden): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-protectionalert
- Microsoft, PIM security alerts voor Microsoft Entra-rollen (alertnamen en severity): https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts
- Microsoft, Entra audit log activity reference (RoleManagement-activiteiten en de PIM-varianten): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, wat zijn risk detections (`Anomalous user activity`, P2): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, AuditLogs-tabel in Azure Monitor (kolom `LoggedByService`): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, Midnight Blizzard: Guidance for responders on nation-state attack (25 jan 2024): https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- MITRE ATT&CK T1068: https://attack.mitre.org/techniques/T1068/
