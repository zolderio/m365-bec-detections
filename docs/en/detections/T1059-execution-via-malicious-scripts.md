# T1059 — Command and Scripting Interpreter

| | |
|---|---|
| **Name in the advisory** | Execution via Malicious Scripts |
| **Name in MITRE ATT&CK** | Command and Scripting Interpreter |
| **MITRE tactic** | Execution (TA0002) |
| **Advisory measure** | 008 — Blocking risky file extensions (priority High) |
| **Related technique** | [T1204](T1204-user-execution.md) — the same measure, the mail side instead of the endpoint side |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE` — both are needed
>
> The two ASR rules that cover this (`Block JavaScript or VBScript from
> launching downloaded executable content` and `Block execution of potentially
> obfuscated scripts`) generate EDR alerts and do not require E5. But according
> to Microsoft the first one only does so if the cloud protection level of the
> device is set to **High plus** or **Zero tolerance**, and that is not the
> default. So enable the ASR rules — that is the measure — but do not rely on
> the alert as a detection, and place your own rule alongside it on the
> `DeviceEvents` ASR events plus the script interpreters that start from Outlook
> or the browser. Note the second limitation: ASR is Windows endpoint detection.
> A BEC that plays out entirely in the browser and the cloud will never show up
> here.

## Is there a Defender alert for this?

**Partly, and with a condition that in practice is often not met.**

There is no Purview alert policy for script execution. What does exist are
EDR alerts from the ASR rules of Microsoft Defender for Endpoint.

| ASR rule | GUID | EDR alert | ActionType (advanced hunting) |
|---|---|---|---|
| `Block JavaScript or VBScript from launching downloaded executable content` | `d3e037e1-3eb8-44c8-a917-57927947596d` | Yes ¹ | `AsrScriptExecutableDownloadAudited` / `AsrScriptExecutableDownloadBlocked` |
| `Block execution of potentially obfuscated scripts` | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` | Yes | `AsrObfuscatedScriptAudited` / `AsrObfuscatedScriptBlocked` |
| `Block executable content from email client and webmail` | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` | Yes ¹ | `AsrExecutableEmailContentAudited` / `AsrExecutableEmailContentBlocked` |
| `Block Office communication application from creating child processes` | `26190899-1602-49e8-8b27-eb1d0a1ce869` | **No** | `AsrOfficeCommAppChildProcessAudited` / `AsrOfficeCommAppChildProcessBlocked` |

¹ Microsoft, verbatim: *"EDR alerts are generated only when the cloud
protection level on the device is **High plus** or **Zero tolerance**."* If
cloud protection is set to a lower level, the rule still blocks but you get no
alert. The event still lands in `DeviceEvents`.

The fourth rule in the table is the most interesting one for BEC — it blocks
Outlook from starting a child process — and that is precisely the one that
produces **no** EDR alert. That is exactly the gap the Sentinel rule below
closes.

**The default severity of these EDR alerts is not publicly documented.** The
ASR reference only states whether an alert is generated, not with which
severity.

| | |
|---|---|
| **Licensing for the ASR rules themselves** | ASR is a feature of Microsoft Defender Antivirus and works on every Windows edition. Central management, reporting and alerting require Microsoft Defender for Endpoint. |
| **Licensing for the ASR report and device timeline** | Defender for Endpoint Plan 2 or Microsoft Defender for Business |
| **Licensing for advanced hunting on ASR events** | **Defender for Endpoint Plan 2** — Microsoft: *"This feature requires Microsoft Defender for Endpoint Plan 2."* |
| **Without Plan 2** | ASR events only appear in the local Windows event log (event ID 1121/1122, log *Microsoft-Windows-Windows Defender/Operational*). Centralising them is then possible through Windows Event Forwarding. |

## Required data source

| Platform | Table | What needs to be onboarded |
|---|---|---|
| Microsoft Sentinel | `DeviceEvents`, `DeviceProcessEvents` | Data connector **Microsoft Defender XDR** with advanced hunting event streaming enabled. Defender for Endpoint on the endpoints underneath. Ingesting these tables is billable traffic in Sentinel. |
| Defender XDR advanced hunting | `DeviceEvents`, `DeviceProcessEvents` | Defender for Endpoint **Plan 2**. Retention 30 days. |

Two differences between the two platforms that will break your queries if you
move them across unchanged:

- in Defender XDR the time column is called `Timestamp`, in Sentinel
  `TimeGenerated`;
- `AdditionalFields` is of type `string` in Defender XDR and of type `dynamic`
  in Sentinel. `extractjson()` on a dynamic column does not behave the way you
  expect; use dot notation in Sentinel.

This detection does **not** depend on measure 012 (Unified Audit Log), because
this is endpoint telemetry and not M365 audit telemetry.

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
// All script-related ASR events, both Audit and Block. Audit is included deliberately:
// during the rollout phase the rules are set to Audit and that is then the only visibility,
// and an Audit event means the action did go through.
let lookback = 30d;
DeviceEvents
| where Timestamp > ago(lookback)
| where ActionType in~ (
    "AsrScriptExecutableDownloadAudited",  "AsrScriptExecutableDownloadBlocked",
    "AsrObfuscatedScriptAudited",          "AsrObfuscatedScriptBlocked",
    "AsrExecutableEmailContentAudited",    "AsrExecutableEmailContentBlocked",
    "AsrOfficeCommAppChildProcessAudited", "AsrOfficeCommAppChildProcessBlocked")
// RuleId establishes after the fact which rule fired; useful when tuning
// exclusions. AdditionalFields is a string here, so extractjson works.
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
lookback: P7D
parameters: []
deployable: false
-->
```kql
// The gap ASR does not report: a script interpreter starting from the mail client
// or the browser. This is the execution of the .html, .js or .vbs attachment from
// measure 008 after it has made it past the filters.
let lookback = 7d;
let interpreters = dynamic(["wscript.exe","cscript.exe","mshta.exe","powershell.exe",
                            "pwsh.exe","cmd.exe","rundll32.exe","regsvr32.exe"]);
let mailAndBrowser = dynamic(["outlook.exe","olk.exe","msedge.exe","chrome.exe",
                              "firefox.exe","winword.exe","excel.exe"]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where FileName in~ (interpreters)
| where InitiatingProcessFileName in~ (mailAndBrowser)
// Attachments opened from Outlook are first extracted to the
// Content.Outlook folder under INetCache. A script running from there or from Downloads
// is almost never a business process.
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
// Same detection, Sentinel variants of the column names: TimeGenerated instead
// of Timestamp, and AdditionalFields is dynamic here, so dot notation instead
// of extractjson.
let lookback = 1d;
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

At Microsoft the field name inside `AdditionalFields` is `Ruleid` (lower-case
d). That is taken from Microsoft's own sample query; whether the column is
named exactly that in the Sentinel variant is **not verified**. When in doubt,
first run `DeviceEvents | where ActionType startswith "Asr" | take 5` and look
at the raw contents of `AdditionalFields`.

## Why this matters for BEC

In BEC the script is rarely the payload and almost always the wrapper around a
sign-in page. The NCSC/Cyclotron advisory puts it like this under measure 008:
*".html attachments in particular are abused to lure users into entering
credentials on locally executed, counterfeit sign-in pages. Because these pages
are not hosted on an external web server, they are often not recognised by
standard URL scanners."* The detection value therefore does not lie in "malware
found" but in "an interpreter ran something that came out of a mail attachment"
— that is the moment before the credential harvest, and it is the last moment
at which you are still ahead of the attacker.

MITRE places T1059 under Execution and explicitly names `T1059.005` (Visual
Basic) and `T1059.007` (JavaScript) among the sub-techniques, the two languages
the advisory names.

## References

- Microsoft, ASR rules reference (rule names, GUIDs, ActionTypes, EDR alert behaviour): https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- Microsoft, Monitor ASR rule activity (`DeviceEvents` table, Plan 2 licensing requirement): https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-monitor
- Microsoft, Test your ASR rules deployment: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
- Microsoft, DeviceEvents schema (advanced hunting): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- Microsoft, DeviceProcessEvents schema (advanced hunting): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- Microsoft, DeviceEvents in Azure Monitor (Sentinel column types): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/deviceevents
- MITRE ATT&CK T1059: https://attack.mitre.org/techniques/T1059/
