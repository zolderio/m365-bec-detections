# T1059 — Command and Scripting Interpreter

| | |
|---|---|
| **Naam in het advies** | Execution via Malicious Scripts |
| **Naam in MITRE ATT&CK** | Command and Scripting Interpreter |
| **MITRE-tactiek** | Execution (TA0002) |
| **Whitepaper-maatregel** | 008 — Blokkeren van riskante extensies (prioriteit Hoog) |
| **Verwante techniek** | [T1204](T1204-user-execution.md) — dezelfde maatregel, de mailkant in plaats van de endpointkant |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [teststatus](../teststatus.md) |

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE` — allebei nodig
>
> De twee ASR-regels die hier op zitten (`Block JavaScript or VBScript from
> launching downloaded executable content` en `Block execution of potentially
> obfuscated scripts`) genereren EDR-alerts en vereisen géén E5. Maar de eerste
> doet dat volgens Microsoft alleen als het cloud protection level van het
> apparaat op **High plus** of **Zero tolerance** staat, en dat is niet de
> standaard. Zet de ASR-regels dus aan — dat is de maatregel — maar reken niet
> op het alert als detectie, en leg er een eigen regel naast op de
> `DeviceEvents`-ASR-events plus de scriptinterpreters die vanuit Outlook of de
> browser starten. Let op de tweede beperking: ASR is Windows-endpointdetectie.
> Een BEC die zich volledig in de browser en de cloud afspeelt komt hier niet
> voorbij.

## Is er een Defender-alert voor?

**Deels, en met een conditie die in de praktijk vaak niet is ingevuld.**

Er is geen Purview alert policy voor scriptuitvoering. Wat er wel is, zijn
EDR-alerts uit de ASR-regels van Microsoft Defender for Endpoint.

| ASR-regel | GUID | EDR-alert | ActionType (advanced hunting) |
|---|---|---|---|
| `Block JavaScript or VBScript from launching downloaded executable content` | `d3e037e1-3eb8-44c8-a917-57927947596d` | Ja ¹ | `AsrScriptExecutableDownloadAudited` / `AsrScriptExecutableDownloadBlocked` |
| `Block execution of potentially obfuscated scripts` | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Ja | `AsrObfuscatedScriptAudited` / `AsrObfuscatedScriptBlocked` |
| `Block executable content from email client and webmail` | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Ja ¹ | `AsrExecutableEmailContentAudited` / `AsrExecutableEmailContentBlocked` |
| `Block Office communication application from creating child processes` | `26190899-1602-49e8-8b27-eb1d0a1ce869` | **Nee** | `AsrOfficeCommAppChildProcessAudited` / `AsrOfficeCommAppChildProcessBlocked` |

¹ Microsoft, letterlijk: *"EDR alerts are generated only when the cloud
protection level on the device is **High plus** or **Zero tolerance**."* Staat
cloud protection op een lager niveau, dan blokkeert de regel wel maar krijg je
geen alert. Het event komt nog steeds in `DeviceEvents`.

De vierde regel in de tabel is de interessantste voor BEC — hij blokkeert dat
Outlook een childproces start — en juist die levert **geen** EDR-alert. Dat is
precies het gat dat de Sentinel-rule hieronder dicht.

**Standaard-severity van deze EDR-alerts is niet publiek gedocumenteerd.** De
ASR-referentie noemt alleen of er een alert komt, niet met welke severity.

| | |
|---|---|
| **Licentie ASR-regels zelf** | ASR is een functie van Microsoft Defender Antivirus en werkt op elke Windows-editie. Centraal beheer, rapportage en alerting vereisen Microsoft Defender for Endpoint. |
| **Licentie ASR-rapport en device timeline** | Defender for Endpoint Plan 2 of Microsoft Defender for Business |
| **Licentie advanced hunting op ASR-events** | **Defender for Endpoint Plan 2** — Microsoft: *"This feature requires Microsoft Defender for Endpoint Plan 2."* |
| **Zonder Plan 2** | ASR-events staan alleen in het lokale Windows-eventlog (event ID 1121/1122, log *Microsoft-Windows-Windows Defender/Operational*). Centraliseren kan dan via Windows Event Forwarding. |

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Microsoft Sentinel | `DeviceEvents`, `DeviceProcessEvents` | Data connector **Microsoft Defender XDR** met advanced hunting event streaming aan. Onderliggend Defender for Endpoint op de endpoints. Ingestie van deze tabellen is betaald verkeer in Sentinel. |
| Defender XDR advanced hunting | `DeviceEvents`, `DeviceProcessEvents` | Defender for Endpoint **Plan 2**. Retentie 30 dagen. |

Twee verschillen tussen de twee platforms die je queries breken als je ze over
de schutting gooit:

- in Defender XDR heet de tijdkolom `Timestamp`, in Sentinel `TimeGenerated`;
- `AdditionalFields` is in Defender XDR van het type `string` en in Sentinel van
  het type `dynamic`. `extractjson()` op een dynamic-kolom werkt niet zoals je
  verwacht; gebruik in Sentinel de puntnotatie.

Deze detectie hangt **niet** aan maatregel 012 (Unified Audit Log), want dit is
endpointtelemetrie en geen M365-audittelemetrie.

## KQL — Defender XDR advanced hunting (DeviceEvents)

<!-- query
platform: defender-xdr
name: ASR rule audit or block on scripts and email-borne executable content
technique: T1059
severity: Medium
tactics: [Execution]
interval: P1D
lookback: P30D
parameters: []
deployable: false
-->
```kql
// Alle scriptgerelateerde ASR-events, Audit én Block. Audit staat er bewust bij:
// in de uitrolfase staan de regels op Audit en dan is dit de enige zichtbaarheid,
// en een Audit-event betekent dat de handeling wél is doorgegaan.
let lookback = 30d;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType in~ (
    "AsrScriptExecutableDownloadAudited",  "AsrScriptExecutableDownloadBlocked",
    "AsrObfuscatedScriptAudited",          "AsrObfuscatedScriptBlocked",
    "AsrExecutableEmailContentAudited",    "AsrExecutableEmailContentBlocked",
    "AsrOfficeCommAppChildProcessAudited", "AsrOfficeCommAppChildProcessBlocked")
// RuleId maakt achteraf hard welke regel vuurde; handig bij het tunen van
// uitzonderingen. AdditionalFields is hier een string, dus extractjson kan.
| extend RuleId = extractjson("$Ruleid", AdditionalFields, typeof(string))
| extend Mode = iff(ActionType endswith "Blocked", "Blocked", "Audit only")
| project Timestamp, DeviceName, ActionType, Mode, RuleId, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountUpn
| order by Timestamp desc
```

## KQL — Defender XDR advanced hunting (DeviceProcessEvents)

<!-- query
platform: defender-xdr
name: Script interpreter launched by a mail client or browser from a temporary folder
technique: T1059
severity: Medium
tactics: [Execution]
interval: PT1H
lookback: P1D
parameters: []
deployable: false
-->
```kql
// Het gat dat ASR niet meldt: een scriptinterpreter die start vanuit de mailclient
// of de browser. Dit is de uitvoering van de .html-, .js- of .vbs-bijlage uit
// maatregel 008 nadat die door de filters heen is gekomen.
let lookback = 7d;
let interpreters = dynamic(["wscript.exe","cscript.exe","mshta.exe","powershell.exe",
                            "pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe"]);
let mailAndBrowser = dynamic(["outlook.exe","olk.exe","msedge.exe","chrome.exe",
                              "firefox.exe","winword.exe","excel.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (interpreters)
| where InitiatingProcessFileName in~ (mailAndBrowser)
// Bijlagen die vanuit Outlook worden geopend, worden eerst uitgepakt naar de
// Content.Outlook-map onder INetCache. Een script dat daaruit of uit Downloads
// draait, is bijna nooit een bedrijfsproces.
| extend FromAttachmentOrDownload = ProcessCommandLine has_any (
    @"Content.Outlook", @"INetCache", @"\Downloads\", @"\Temp\")
| where FromAttachmentOrDownload
| project Timestamp, DeviceName, AccountUpn, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Timestamp desc
```

## KQL — Microsoft Sentinel (DeviceEvents)

<!-- query
platform: sentinel
name: ASR rule triggered on script or email-borne executable content
technique: T1059
severity: Medium
tactics: [Execution]
interval: PT1H
lookback: P1D
parameters: []
deployable: true
-->
```kql
// Zelfde detectie, Sentinel-varianten van de kolomnamen: TimeGenerated in plaats
// van Timestamp, en AdditionalFields is hier dynamic, dus puntnotatie in plaats
// van extractjson.
let lookback = 30d;
DeviceEvents
| where TimeGenerated > ago(lookback)
| where ActionType startswith "Asr"
| where ActionType has_any ("ScriptExecutable", "ObfuscatedScript",
                            "ExecutableEmailContent", "OfficeCommAppChildProcess")
| extend RuleId = tostring(AdditionalFields.Ruleid)
| extend Mode = iff(ActionType endswith "Blocked", "Blocked", "Audit only")
| project TimeGenerated, DeviceName, ActionType, Mode, RuleId, FileName, FolderPath,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountUpn
| order by TimeGenerated desc
```

De veldnaam binnen `AdditionalFields` is bij Microsoft `Ruleid` (kleine letter
d). Dat is overgenomen uit Microsofts eigen voorbeeldquery; of de kolom in de
Sentinel-variant exact zo heet, is **niet geverifieerd**. Draai bij twijfel
eerst `DeviceEvents | where ActionType startswith "Asr" | take 5` en kijk naar
de ruwe inhoud van `AdditionalFields`.

## Waarom dit BEC is

Bij BEC is het script zelden de payload en bijna altijd de verpakking van een
inlogpagina. Het NCSC/Cyclotron-advies zegt het bij maatregel 008 zo: *"Vooral
.html-bijlagen worden misbruikt om gebruikers te verleiden tot het invoeren van
inloggegevens op lokaal uitgevoerde, nagemaakte inlogpagina's. Omdat deze
pagina's niet op een externe webserver staan, worden ze vaak niet herkend door
standaard URL-scanners."* De detectiewaarde zit daarom niet in "malware
gevonden" maar in "een interpreter draaide iets dat uit een mailbijlage kwam" —
dat is het moment vóór de credential harvest, en het is het laatste moment
waarop je nog vóór de aanvaller bent.

MITRE plaatst T1059 onder Execution en noemt onder de sub-technieken expliciet
`T1059.005` (Visual Basic) en `T1059.007` (JavaScript), de twee talen die het
advies bij naam noemt.

## Referenties

- Microsoft, ASR rules reference (regelnamen, GUID's, ActionTypes, EDR-alertgedrag): https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- Microsoft, Monitor ASR rule activity (tabel `DeviceEvents`, licentie-eis Plan 2): https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-monitor
- Microsoft, Test your ASR rules deployment: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- Microsoft, DeviceEvents-schema (advanced hunting): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- Microsoft, DeviceProcessEvents-schema (advanced hunting): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- Microsoft, DeviceEvents in Azure Monitor (Sentinel-kolomtypen): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents
- MITRE ATT&CK T1059: https://attack.mitre.org/techniques/T1059/
