# T1538 — Cloud Service Dashboard

| | |
|---|---|
| **MITRE-tactiek** | Discovery |
| **Whitepaper-fase** | 09. Discovery |
| **Whitepaper-maatregel** | 014 — Beperk toegang tot Microsoft Entra (prioriteit Midden, impact Laag, inspanning Laag) |
| **Verwante techniek** | [T1562.001](T1562.001-impair-defenses.md) — de drift-query hieronder hoort ook bij maatregel 013 |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `SENTINEL-RULE` — maar wees eerlijk: dit is hunting, geen alert
>
> Er is geen Defender-alert, en er valt hier ook nauwelijks iets te detecteren.
> Het lezen van de directory door een geauthenticeerde gebruiker is normaal
> gedrag dat geen auditrecord oplevert; alleen *wijzigingen* worden gelogd. Wat u
> wél kunt bouwen is een volumedetectie op Microsoft Graph-verkeer en een
> drift-regel op de instelling zelf. Behandel beide als hunting-queries, niet als
> alerts die een SOC-analist wakker maken. **Bouw hier geen dekking op die u
> elders nodig heeft** — de winst van maatregel 014 zit in preventie, niet in
> detectie, en zelfs die preventie is beperkt (zie hieronder).

## De maatregel die het advies aanbeveelt, is volgens Microsoft geen beveiligingsmaatregel

Het advies schrijft: *"Activeer de instelling Toegang tot Microsoft
Entra-beheerportal beperken (Restrict access to Microsoft Entra administration
portal) binnen de gebruikersinstellingen van Microsoft Entra ID."*

Microsoft zet daar in de eigen documentatie een expliciete waarschuwing bij:

> *"The **Restrict access to Microsoft Entra administration portal** setting
> limits access to a set of commonly visited admin center pages. It is **not a
> security measure**."*

En in de toelichting bij de instelling zelf:

> *"**What does it not do?** It **does not block** programmatic access to
> Microsoft Entra data via PowerShell, Microsoft Graph API, or other tools like
> Visual Studio. It **does not apply** to users with an administrative role,
> including custom roles. It **does not prevent** all access to the admin
> center. Many areas are still reachable through alternate paths."*
>
> *"**When should I not use this switch?** Do not rely on this setting as a
> security control. For stronger enforcement, use a Conditional Access policy
> targeting the Windows Azure Service Management API to block non-admin access
> to Azure management endpoints."*

Bron: https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
(geraadpleegd augustus 2026)

Dat is geen detail. Een aanvaller met een gecompromitteerd standaardaccount
heeft geen portaal nodig: één Graph-aanroep op `/v1.0/users` levert dezelfde
ledenlijst, en `/v1.0/directoryRoles` levert wie Global Admin is. De schakelaar
verandert daar niets aan. Wilt u de Discovery-fase daadwerkelijk raken, dan zijn
de effectieve knoppen: Conditional Access op de **Windows Azure Service
Management API** (Microsofts eigen advies), en — voor het écht afsluiten van
directory-leesrechten — de `authorizationPolicy`-eigenschap
`AllowedToReadOtherUsers` op `$false`, waarvan Microsoft zelf zegt: *"This
setting is meant for special circumstances, so setting the flag to `$false`
isn't recommended."*

## Is er een Defender-alert voor?

**Nee.** Er is geen standaard alert policy voor het bekijken van de directory,
het openen van het Entra-beheerportaal, of het opvragen van de gebruikers- en
rollenlijst. Dat is logisch: het zijn leesacties door een geauthenticeerde
gebruiker en Microsoft 365 logt lezen van de directory niet als auditgebeurtenis.

Wat wél gelogd wordt:

| Wat | Waar | Bruikbaar? |
|---|---|---|
| De aanmelding bij het beheerportaal | `SigninLogs` (Entra) | Ja, als proxy — zie query 1 |
| De Graph-aanroepen zelf | `MicrosoftGraphActivityLogs` (Sentinel) / `GraphAPIAuditEvents` (XDR) | Ja, dit is de enige echte zichtbaarheid — zie query 2 |
| Het lezen van de gebruikerslijst in het portaal | nergens | Nee |
| Het uitzetten van de portaalbeperking | `AuditLogs` (Entra) | Ja, als driftsignaal — zie query 3 |

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `SigninLogs` | Diagnostic setting op Microsoft Entra ID, categorie **SignInLogs**, naar de Log Analytics-workspace. |
| Microsoft Sentinel | `MicrosoftGraphActivityLogs` | Diagnostic setting op Microsoft Entra ID, categorie **MicrosoftGraphActivityLogs**. Deze staat standaard **uit** en is de meest onderschatte ontbrekende bron in dit hele advies. |
| Microsoft Sentinel | `AuditLogs` | Diagnostic setting op Microsoft Entra ID, categorie **AuditLogs**. Hangt samen met maatregel 013 (configuratiedrift). |
| Defender XDR advanced hunting | `GraphAPIAuditEvents` | Microsoft: *"Microsoft Entra ID API requests made to Microsoft Graph API for resources in the tenant"*. Beschikbaarheid per tenant verschilt; controleer de schemareferentie in uw eigen portaal. |

## KQL — Sentinel (SigninLogs): aanmelding bij de beheer-endpoints

```kql
// Niet-beheerders die zich aanmelden bij de Azure-/Entra-beheerlaag.
// "Windows Azure Service Management API" is de resource die Microsoft zelf
// noemt als doel voor een Conditional Access-policy op deze toegang; dat maakt
// hem de best gedocumenteerde ankerwaarde. De exacte AppDisplayName van het
// Entra-beheercentrum is NIET publiek gedocumenteerd -- vul die pas in nadat u
// in uw eigen tenant hebt gekeken wat er verschijnt.
let lookback = 7d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0                       // alleen geslaagde aanmeldingen
| where ResourceDisplayName has "Windows Azure Service Management API"
| summarize SignIns = count(),
            First = min(TimeGenerated),
            Last = max(TimeGenerated),
            IPs = make_set(IPAddress, 20),
            Countries = make_set(tostring(LocationDetails.countryOrRegion), 10),
            Apps = make_set(AppDisplayName, 10)
    by UserPrincipalName, UserId
| order by Last desc
```

Deze query alleen is ruis. Hij wordt bruikbaar als u hem beperkt tot gebruikers
zonder beheerrol, of tot gebruikers die dit nog niet eerder deden:

```kql
// Alleen gebruikers die dit in de 30 dagen ervoor niet deden.
let known = SigninLogs
    | where TimeGenerated between (ago(37d) .. ago(7d))
    | where ResourceDisplayName has "Windows Azure Service Management API"
    | distinct UserPrincipalName;
// ... plaats aan het eind van de query hierboven:
| where UserPrincipalName !in (known)
```

## KQL — Sentinel (MicrosoftGraphActivityLogs): de echte Discovery-detectie

```kql
// Enumeratie van gebruikers, groepen en rollen via Microsoft Graph.
// Dit is waar T1538 in een moderne tenant daadwerkelijk plaatsvindt: niet in
// het portaal, maar in een script. Vandaar dat de portaalbeperking uit
// maatregel 014 hier niets tegen doet.
let lookback = 7d;
let threshold = 200;                 // aantal directory-reads binnen het window
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| where ResponseStatusCode between (200 .. 299)
| where RequestUri has_any ("/users", "/groups", "/directoryRoles",
                            "/servicePrincipals", "/applications",
                            "/roleManagement", "/organization", "/contacts")
| extend Endpoint = tostring(split(replace_regex(RequestUri, @'https://[^/]+/(v1\.0|beta)/', ''), '?')[0])
| summarize Reads = count(),
            Endpoints = dcount(Endpoint),
            Examples = make_set(Endpoint, 15),
            IPs = make_set(IPAddress, 10),
            UserAgents = make_set(UserAgent, 10),
            First = min(TimeGenerated),
            Last = max(TimeGenerated)
    by UserId, AppId, bin(TimeGenerated, 1h)
| where Reads > threshold
| order by Reads desc
```

Let op de kolom `UserAgent`: legitieme enumeratie komt doorgaans van een bekende
SDK of van het portaal zelf; een kale `python-requests`, `curl` of een
Graph-PowerShell-agent op een gebruikersaccount dat daar geen rol in heeft, is
het interessante geval.

## KQL — Defender XDR advanced hunting (GraphAPIAuditEvents)

```kql
let lookback = 7d;
let threshold = 200;
GraphAPIAuditEvents
| where Timestamp > ago(lookback)
| where RequestMethod == "GET"
| where RequestUri has_any ("/users", "/groups", "/directoryRoles",
                            "/servicePrincipals", "/applications", "/roleManagement")
| summarize Reads = count(),
            Examples = make_set(RequestUri, 15),
            IPs = make_set(IpAddress, 10),
            First = min(Timestamp), Last = max(Timestamp)
    by AccountObjectId, ApplicationId, bin(Timestamp, 1h)
| where Reads > threshold
| order by Reads desc
```

## KQL — Sentinel (AuditLogs): drift op de instelling zelf

Het advies vraagt hier expliciet om: *"Monitor regelmatig op wijzigingen in de
toegangsinstellingen van het beheerportaal om te voorkomen dat deze beperking
onbedoeld wordt opgeheven (configuratiedrift)."*

```kql
// Wijziging aan het autorisatiebeleid of de tenant-brede instellingen.
// De schakelaar "Restrict access to Microsoft Entra administration portal"
// hoort in de authorizationPolicy thuis; WELKE activity Microsoft precies
// wegschrijft bij deze specifieke schakelaar is NIET publiek gedocumenteerd.
// Daarom staan beide kandidaat-activiteiten in het filter -- verifieer in uw
// eigen tenant welke van de twee verschijnt en versmal daarna.
let lookback = 30d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where (Category == "AuthorizationPolicy" and ActivityDisplayName == "Update authorization policy")
     or (Category == "DirectoryManagement"  and ActivityDisplayName == "Update company settings")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName),
                          tostring(InitiatedBy.app.displayName))
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Category, ActivityDisplayName, Actor, ActorIP,
          Result, TargetResources, AdditionalDetails, CorrelationId
| order by TimeGenerated desc
```

De categorie- en activiteitsnamen komen uit Microsofts eigen
audit-activiteitenreferentie; de koppeling van díé activiteit aan díé
schakelaar is de niet-geverifieerde stap.

## Waarom dit BEC is

Discovery is bij BEC geen doel op zich maar de voorbereiding op de
overtuigingsstap. Het advies beschrijft het scherp: *"Wanneer een aanvaller
toegang heeft tot een standaard gebruikersaccount, kan hij via het Entra-portaal
eenvoudig een lijst ophalen van alle medewerkers, hun specifieke rollen (zoals
wie de Global Admin of CFO is) en de gebruikte bedrijfsapplicaties. Deze
informatie is cruciaal voor het voorbereiden van zeer gerichte en
geloofwaardige vervolgstappen, zoals spearphishing of impersonatie van
sleutelfiguren."*

Concreet: de aanvaller zoekt uit wie tekenbevoegd is, wie de crediteurenadmini-
stratie doet en wie er met vakantie is. Dat is wat een intern spearphishing-
bericht (zie [T1534](T1534-internal-spearphishing.md)) geloofwaardig maakt.

Wees hier realistisch over de opbrengst van detectie. Het waarnemen van deze
fase is in Microsoft 365 grotendeels onmogelijk zonder
`MicrosoftGraphActivityLogs`, en zelfs dan detecteert u volume, geen intentie.
De investering hoort in dit geval bij de fases ervoor (Initial Access,
Credential Access) en erna (Lateral Movement), niet hier.

## Referenties

- Microsoft, standaard gebruikersrechten en de portaalbeperking: https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
- Microsoft, alert policies (ter controle dat er geen policy voor bestaat): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, MicrosoftGraphActivityLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs
- Microsoft, SigninLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, AuditLogs-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- Microsoft, Entra audit-activiteitenreferentie (AuthorizationPolicy / Update authorization policy): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, advanced hunting schematabellen (GraphAPIAuditEvents): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- MITRE ATT&CK T1538: https://attack.mitre.org/techniques/T1538/
