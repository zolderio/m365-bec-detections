# T1671 — Cloud Application Integration (Illicit Consent Grant)

| | |
|---|---|
| **Naam in het advies** | Illicit Consent Grant — gebruikers misleiden om een malafide OAuth-app toegang te geven tot mailboxen en data |
| **Naam in MITRE ATT&CK** | Cloud Application Integration |
| **MITRE-tactiek** | Persistence (TA0003) |
| **Whitepaper-maatregel** | 009 — OAuth-app consent beperken of uitschakelen (prioriteit Hoog) |
| **Verwante technieken** | [T1098.001](T1098.001-additional-cloud-credentials.md) — credentials op de app die consent kreeg; [T1204](T1204-user-execution.md) — de klik die eraan voorafgaat |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

> MITRE hernoemde T1671 naar **Cloud Application Integration**; het advies
> gebruikt de oudere aanduiding *Illicit Consent Grant*. Zelfde techniek-ID,
> zelfde tactiek (Persistence), geen sub-technieken.

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE` — allebei nodig
>
> App governance is voor deze techniek de beste dekking die Microsoft levert:
> ruim tien alerts die specifiek op malafide consent-patronen zitten, met
> mail-permissies als apart aandachtspunt en severity Medium in plaats van
> Informational. Zet het aan als je een Defender for Cloud Apps-licentie hebt —
> het staat niet standaard aan en het moet handmatig geactiveerd worden. Maar
> het dicht het gat niet: er is géén alert op de consentgebeurtenis zelf, alle
> app governance-detecties zijn gedragsheuristieken die pas achteraf vuren, en
> onder een MDA-licentie heb je helemaal niets — er bestaat geen Purview alert
> policy voor `Consent to application`. De Entra-auditlog registreert de consent
> wél volledig en direct. Bouw daar de regel op en scope hem op de scopes die
> ertoe doen.

## Is er een Defender-alert voor?

**Op de consentgebeurtenis niet. Op het gedrag van de app erna: ja, mits
gelicentieerd en aangezet.**

### App governance (Defender for Cloud Apps)

De relevante alerts, met de door Microsoft gedocumenteerde severity:

| Alert | Severity | ATT&CK-fase volgens Microsoft |
|---|---|---|
| `New app with mail permissions having low consent pattern` | **Medium** | Initial access |
| `New app with low consent rate accessing numerous emails` | **Medium** | Initial access |
| `Encoded app name with suspicious consent scopes` | **Medium** | Initial access |
| `App created recently has low consent rate` | **Low** | Initial access |
| `App with unusual display name and unusual TLD in Reply domain` | **Medium** | Initial access |
| `OAuth App with suspicious Reply URL` | **Medium** | Initial access |
| `App metadata associated with known phishing campaign` | **Medium** | Persistence |
| `App created recently has a high volume of revoked consents` | **Medium** | Persistence (T1566, T1098) |
| `Suspicious OAuth app email activity through Graph API` | **High** | Persistence |
| `Suspicious OAuth app email activity through EWS API` | **High** | Persistence |
| `OAuth app with suspicious metadata has Exchange permission` | **Medium** | Privilege escalation (T1078) |
| `App impersonating a Microsoft logo` | **Medium** | Defense evasion |
| `App is associated with a typosquatted domain` | **Medium** | Defense evasion |
| `App with EWS application permissions accessing numerous emails` | **Medium** | Collection |
| `App made anomalous Graph calls to read e-mail` | **Medium** | Collection (T1114) |

Microsoft zegt er expliciet bij dat er voor de fase **Execution** *"no alerts
currently defined"* zijn.

| | |
|---|---|
| **Licentie** | *"App governance is available to organizations with a valid Defender for Cloud Apps license."* Defender for Cloud Apps standalone of als onderdeel van een pakket. |
| **Regiobeperking** | Het factuuradres moet buiten Singapore, Polen, Italië, Qatar, Israël, Spanje, Mexico en Taiwan liggen. |
| **Aanzetten** | Handmatig, via **Settings > Cloud Apps > App governance > Use app governance**. Tot 10 uur wachttijd. Alerts stromen pas als zowel Defender for Cloud Apps als Microsoft Defender minstens één keer via hun portal zijn geopend. |

### Defender for Cloud Apps anomaly detection

`Suspicious OAuth app file download activities` bestaat nog en is actief. Let op
wat er sinds juni 2025 **niet** meer werkt: `Unusual ISP for an OAuth app` is
uitgezet en overgegaan in het dynamische model onder de naam
`OAuth application activity from an unknown ISP`. Neem de oude naam niet meer op
in een dekkingsoverzicht.

### Purview alert policies

Geen. De lijst met default alert policies bevat geen policy voor
`Consent to application`, en de severity van een standaardpolicy is sowieso niet
te wijzigen — Microsoft: *"The other settings for these policies can't be
edited."*

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, logcategorie **AuditLogs** aangevinkt. |
| Microsoft Sentinel | `SigninLogs` | Zelfde connector, aparte logcategorie. Nodig voor de correlatie met de sessie waarin consent werd gegeven. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps met de Microsoft 365-connector (**Settings > Cloud apps > App connectors**, vinkje *Microsoft 365 activities*). Retentie 30 dagen. |

Hangt **niet** aan maatregel 012 (UAL) voor de Sentinel-route; de
`CloudAppEvents`-route leunt wel op de Microsoft 365-connector van Defender for
Cloud Apps.

## De auditactiviteiten (exact, en wat we niet konden verifiëren)

Uit de Entra-auditreferentie, categorie **ApplicationManagement**, service
**Core Directory**:

| Activiteit | Wat het betekent |
|---|---|
| `Consent to application` | Een gebruiker of admin geeft consent. Volgens Microsoft: *"User grants consent to an application"*. |
| `Add delegated permission grant` | Delegated toegang wordt verleend. Microsoft: *"Granting delegated access to an app"*. |
| `Add app role assignment to service principal` | App-only toegang (application permissions). In de Entra-documentatie ook geschreven als *"Add app role assignment to the service principal"*. |
| `Add service principal` | De service principal wordt in de tenant aangemaakt — de eerste keer dat een multitenant-app landt. |
| `Add app role assignment to group` | Roltoewijzing aan een groep (categorie GroupManagement en UserManagement). |
| `Grant contextual consent to application` | Categorie GroupManagement. |

**Niet geverifieerd: `Add app role assignment grant to user`.** Die string komt
niet voor in de huidige Entra-auditreferentie. Wat er wél staat, is
`Remove app role assignment from user` (UserManagement) en
`Add app role assignment to group` (UserManagement) — de "add"-tegenhanger voor
een gebruiker ontbreekt in die tabel. De variant met "grant" wordt in het veld
breed gebruikt en zal in veel tenants voorkomen, maar wij nemen hem niet als
feit op. De queries hieronder filteren daarom met `has "app role assignment"` in
plaats van op een exacte string, zodat beide schrijfwijzen worden gevangen.

## KQL — Sentinel (AuditLogs): consent met risicovolle scopes

<!-- query
platform: sentinel
name: OAuth consent or permission grant covering mail or directory scopes
technique: T1671
severity: Medium
tactics: [Persistence]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->

```kql
// Consent en permission grants, met de mailscopes eruit gelicht. De scopes staan
// in modifiedProperties; welke property dat precies is verschilt per activiteit,
// dus we serialiseren het geheel en zoeken er tekstueel in. Dat is grover dan
// een geparste lookup, maar het breekt niet als Microsoft de volgorde wijzigt.
let lookback = 30d;
let riskScopes = dynamic([
    "Mail.Read","Mail.ReadWrite","Mail.ReadBasic","Mail.Send",
    "MailboxSettings.ReadWrite","full_access_as_app","EWS.AccessAsUser.All",
    "Files.ReadWrite.All","Directory.ReadWrite.All","offline_access",
    "User.ReadWrite.All","Application.ReadWrite.All"]);
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category in ("ApplicationManagement", "GroupManagement", "UserManagement")
| where OperationName in ("Consent to application", "Add delegated permission grant",
                          "Grant contextual consent to application")
      or OperationName has "app role assignment"
| where Result == "success"
| extend Actor         = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorIP       = tostring(InitiatedBy.user.ipAddress)
| extend AppName       = tostring(TargetResources[0].displayName)
| extend AppObjectId   = tostring(TargetResources[0].id)
| extend Props         = tostring(TargetResources[0].modifiedProperties)
// IsAdminConsent onderscheidt "één gebruiker gaf toestemming voor zichzelf" van
// "de hele tenant is opengezet". Microsoft wijst dit veld ook aan in de
// remediatiehandleiding voor illicit consent grants.
| extend AdminConsent  = Props has "ConsentContext.IsAdminConsent" and Props has "True"
// extract_all haalt alle scope-achtige strings uit de property-blob; de
// doorsnede met de lijst hierboven houdt alleen de scopes over die ertoe doen.
| extend MatchedScopes = set_intersect(
        riskScopes,
        extract_all(@"([A-Za-z]+\.[A-Za-z\.]+|full_access_as_app)", Props))
| where AdminConsent or array_length(MatchedScopes) > 0
| project TimeGenerated, OperationName, Actor, ActorIP, AppName, AppObjectId,
          AdminConsent, MatchedScopes, Props, CorrelationId
| order by TimeGenerated desc
```

Simpeler en robuuster als je de scope-extractie niet vertrouwt:

<!-- query
platform: sentinel
name: Consent grant filtered down to mail scopes or admin consent
technique: T1671
severity: Medium
tactics: [Persistence]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->

```kql
| extend TouchesMail = Props has_any ("Mail.Read","Mail.ReadWrite","Mail.Send",
                                      "MailboxSettings","full_access_as_app","EWS.AccessAsUser.All")
| where TouchesMail or AdminConsent
```

## KQL — Sentinel: consent kort na een sign-in vanaf een onbekend IP

<!-- query
platform: sentinel
name: OAuth consent granted shortly after sign-in from an unfamiliar IP
technique: T1671
severity: High
tactics: [Persistence]
interval: P1D
lookback: P14D
parameters: []
deployable: true
-->

```kql
// Een consentgrant is pas verdacht als hij uit een sessie komt die zelf al
// afwijkt. Dit is de brug tussen T1204 (de klik) en deze techniek.
let baseline = 30d;
let recent   = 7d;
let window   = 30m;
let knownIPs =
    SigninLogs
    | where TimeGenerated between (ago(baseline) .. ago(recent))
    | where ResultType == "0"
    | distinct UserPrincipalName, IPAddress;
let suspiciousSignIns =
    SigninLogs
    | where TimeGenerated > ago(recent)
    | where ResultType == "0"
    | join kind=leftanti knownIPs on UserPrincipalName, IPAddress
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress,
              Country = tostring(LocationDetails.countryOrRegion), UserAgent;
AuditLogs
| where TimeGenerated > ago(recent)
| where OperationName in ("Consent to application", "Add delegated permission grant")
| where Result == "success"
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| join kind=inner suspiciousSignIns on UserPrincipalName
| where TimeGenerated between (SignInTime .. SignInTime + window)
| project ConsentTime = TimeGenerated, UserPrincipalName, AppName,
          SignInTime, IPAddress, Country, UserAgent
| order by ConsentTime desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents)

<!-- query
platform: defender-xdr
name: OAuth consent events seen through Defender for Cloud Apps
technique: T1671
severity: Medium
tactics: [Persistence]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->

```kql
// Entra-consentevents komen binnen onder Application "Office 365". De punt aan
// het eind van de ActionType-waarde staat in Microsofts eigen hunting-query
// ook; daarom filteren we met startswith.
let lookback = 30d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Office 365"
| where ActionType startswith "Consent to application"
     or ActionType startswith "Add delegated permission grant"
     or ActionType has "app role assignment"
// Microsofts gedocumenteerde manier om admin consent eruit te filteren.
| extend AdminConsent = tostring(RawEventData.ModifiedProperties[0].Name) == "ConsentContext.IsAdminConsent"
                        and tostring(RawEventData.ModifiedProperties[0].NewValue) == "True"
| extend spnID = tostring(RawEventData.Target[3].ID)
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, AdminConsent,
          spnID, IPAddress, CountryCode, Isp, UserAgent, IsAdminOperation, RawEventData
| order by Timestamp desc
```

De positie `ModifiedProperties[0]` en `Target[3]` komt uit Microsofts
gepubliceerde query. Dat zijn vaste indexen in een variabele structuur; als de
query niets teruggeeft terwijl je weet dat er consent is verleend, inspecteer
dan eerst `RawEventData` van één event en pas de indexen aan.

## KQL — app governance-alerts terugvinden

<!-- query
platform: defender-xdr
name: App governance alerts about OAuth apps and consent
technique: T1671
severity: Medium
tactics: [Persistence]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->

```kql
// Als app governance aan staat, komen de alerts in AlertInfo. Handig om vast te
// stellen of de tweede laag daadwerkelijk vuurt.
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource has "Cloud Apps" or DetectionSource has "App governance"
| where Title has_any ("OAuth", "consent", "app with", "App with")
| project Timestamp, Title, Severity, Category, ServiceSource, DetectionSource,
          AttackTechniques, AlertId
| order by Timestamp desc
```

De exacte waarden van `ServiceSource` en `DetectionSource` voor app
governance-alerts zijn **niet publiek gedocumenteerd**; draai
`AlertInfo | distinct ServiceSource, DetectionSource` om ze in je eigen tenant
vast te stellen en scherp de filters daarna aan.

## Waarom dit BEC is

Microsoft omschrijft de aanval en waarom hij de standaardreactie overleeft:
*"Normal remediation steps (for example, resetting passwords or requiring
multifactor authentication (MFA)) aren't effective against this type of attack,
because these apps are external to the organization."* De aanvaller heeft geen
account meer nodig — de app heeft *"account-level access to data"*.

Microsoft adviseert in dezelfde handleiding om in de auditlog te zoeken naar
*"questionable **Consent to application** activities"* en per hit te controleren
of `IsAdminConsent` op `True` staat: *"The value True indicates that someone
with Global Administrator access might have granted broad access to data."* Dat
is exact wat de eerste query hierboven doet, alleen dan doorlopend in plaats van
handmatig.

In de responderguidance bij de aanval op de eigen tenant (25 januari 2024)
beschrijft Microsoft de volledige keten: de actor maakte extra malafide
OAuth-applicaties aan, maakte een nieuw gebruikersaccount aan om daar consent
aan te geven, en gebruikte een gecompromitteerde legacy test-OAuth-app *"to
grant them the Office 365 Exchange Online full_access_as_app role, which allows
access to mailboxes"*.

MITRE geeft bij T1671 als mitigatie onder meer M1042: gebruikers verbieden zelf
integraties toe te voegen en in Entra ID *"Do not allow user consent"* afdwingen
— dat is maatregel 009 uit het advies, letterlijk.

## Referenties

- Microsoft, Detect and remediate illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- Microsoft, app governance threat detection alerts (alertnamen en severity): https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-anomaly-detection-alerts
- Microsoft, app governance aanzetten en licentievereisten: https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-get-started
- Microsoft, anomaly detection policies (welke legacy policies sinds juni 2025 uit staan): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, Entra audit log activity reference: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, View activity logs of application permissions (welke auditactiviteit bij welk scenario hoort): https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- Microsoft, hunting-query `CredentialsAddAfterAdminConsentedToApp[Nobelium]` (CloudAppEvents-patroon voor consent): https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Persistence/CredentialsAddAfterAdminConsentedToApp%5BNobelium%5D.md
- Microsoft, Midnight Blizzard: Guidance for responders on nation-state attack (25 jan 2024): https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- MITRE ATT&CK T1671: https://attack.mitre.org/techniques/T1671/
