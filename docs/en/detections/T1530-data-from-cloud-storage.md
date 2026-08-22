# T1530 — Data from Cloud Storage

| | |
|---|---|
| **MITRE tactic** | Collection |
| **Advisory measures** | 016 — Blocking automatic email forwarding (priority High)<br>017 — Restricting Teams & SharePoint collaboration (priority Medium) |
| **Related techniques** | [T1114.002](T1114.002-remote-email-collection.md) — the same behaviour in the mailbox; [T1567](T1567-exfiltration-over-web-services.md) — getting it out |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> The only default alert policy that comes close,
> `Unusual volume of external file sharing`, is being **deprecated by Microsoft
> because of false positives** and additionally requires E5/G5 or Defender for
> Office 365 Plan 2. What else there is are the anomaly detections of Defender
> for Cloud Apps — those are not in E3 without an add-on and are built on
> volume, whereas a BEC attacker searches in a targeted way and in small
> numbers for one invoice or one contract. Build this yourself, on the
> searching and the accessing, not on the count.

## Is there a Defender alert for this?

**Formally yes, practically no longer.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Default severity** | **Medium** |
| **Licensing** | E5/G5 or Defender for Office 365 Plan 2 add-on |
| **Category** | Information governance |
| **Status** | **Being deprecated.** Microsoft states above the entire *Information governance alert policies* section: *"The alert policies in this section are in the process of being deprecated based on customer feedback as false positives. To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* This policy is the only one in that section. Verified on 22 Aug 2026, page with ms.date 2026-08-03. |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

What does remain in terms of off-the-shelf detection, and why it does not close
the gap:

| | |
|---|---|
| **Mechanism** | Defender for Cloud Apps, anomaly detections under *Unusual activities (by user)* |
| **Names** | `Unusual multiple file download activities`, `Unusual file share activities`, `Unusual file deletion activities` |
| **Status** | Active. These are **not** in the list of policies Microsoft switched off in June 2025 during the transition to the dynamic detection model. |
| **Licensing** | Requires Microsoft Defender for Cloud Apps. Default severity not publicly documented. |
| **Why it is not enough** | Volume-based, with a learning period of seven days. An attacker who opens five files to copy an invoice format stays below every threshold. |
| **Source** | https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy |

There is also a `Suspicious OAuth app file download activities` detection (an
app downloads multiple files from SharePoint or OneDrive in a way that is
unusual for the user). Useful alongside, not instead of, what follows below.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** with the SharePoint workload enabled. SharePoint and OneDrive events arrive in the same table, recognisable by `OfficeWorkload` and `RecordType` (`SharePoint`, `SharePointFileOperation`, `SharePointSharingOperation`). There is **no** separate `SharePointFileOperation` table in Log Analytics; that is a `RecordType` value. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps with the Microsoft 365 app connector and **Microsoft 365 activities** ticked. Retention 30 days. |

Dependent on measure 012 (UAL enabled). In addition:
`SearchQueryInitiatedSharePoint` is **not enabled by default** and has to be
switched on separately — see below.

## The most important event: what the attacker was looking for

The CISA playbook names `SearchQueryInitiatedSharePoint` as the event that lets
you read the attacker's intent: *"the audit record for a
SearchQueryInitiatedSharePoint event contains the actual text of the search
query and indicates the type of SharePoint site that the threat actor
searched."* The search terms ("factuur", "IBAN", "betaalinstructie") say more
about BEC than any download volume.

**Note the precondition:** CISA writes *"Users will also need to enable
SearchQueryInitiated logging for both Exchange and SharePoint since it is
disabled by default."* For Exchange that is
`Set-Mailbox <identity> -AuditOwner @{Add="SearchQueryInitiated"}`. If this is
not enabled, the query below returns nothing by definition.

## KQL — Sentinel (OfficeActivity)

```kql
// Search queries in SharePoint/OneDrive and Exchange side by side, including
// the search terms. Requires SearchQueryInitiated logging to be enabled
// (disabled by default).
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("SearchQueryInitiatedSharePoint", "SearchQueryInitiatedExchange", "SearchQueryPerformed")
| project TimeGenerated, UserId, Operation, OfficeWorkload, ClientIP, UserAgent,
          Site_Url, OfficeObjectId, ExtraProperties
| order by TimeGenerated desc
```

```kql
// Accessing and downloading files, kept separate from the searching so that
// you can correlate the two on user and time.
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

Narrowing on finance — this is the filter that turns "a file was opened" into a
BEC signal:

```kql
| extend File = tolower(strcat(SourceRelativeUrl, "/", SourceFileName))
| where File has_any ("factuur", "invoice", "iban", "betaling", "payment",
                         "creditor", "crediteur", "bankgegevens", "remittance",
                         "contract", "leverancier", "supplier")
```

And the session pivot, so that you tie searching and opening together:

```kql
// Users who both searched and opened files within 30 minutes,
// from the same IP address.
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

`UncommonForUser` and `LastSeenForUser` are the cheapest win here: Defender for
Cloud Apps enriches high-value events itself with which attributes are unusual
for that user. Microsoft does warn that events with low security value do not
go through that enrichment and then contain `""`, whereas `[]` means "enriched,
nothing anomalous" — so filter on
`isnotempty(UncommonForUser) and UncommonForUser != "[]"` and not on
`isnotempty()` alone.

## Why this matters for BEC

In BEC the document side is not a by-product but the preparation. The attacker
needs a real invoice format, a real contract number and a real supplier name to
make a payment request credible; those live in SharePoint and OneDrive, not in
the mailbox. The NCSC/Cyclotron advisory says so explicitly under measure 017:
*"In BEC, attackers target not only email but also collaboration platforms
where company documents, contracts, financial information and operational data
are shared."*

CISA's playbook places the detection logic alongside it: search queries in
SharePoint sit high in the Pyramid of Pain — an attacker changes IP address and
user agent effortlessly, but not what they are looking for. CISA therefore
explicitly advises correlating search queries with the accompanying file
operations: *"searched for a file on SharePoint, with accompanying FileAccessed,
FileCopied, or FileDeleted operations."*

## References

- Microsoft, alert policies (incl. the deprecation note under Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, anomaly detection policies in Defender for Cloud Apps: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, Office 365 Management Activity API schema (RecordType values, SharePoint schema): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- Microsoft, audit log activities: https://learn.microsoft.com/en-us/purview/audit-log-activities
- CISA, Microsoft Expanded Cloud Logs Implementation Playbook (updated May 2026): https://www.cisa.gov/sites/default/files/2026-07/MS%20Expanded%20Logging%20Playbook-Updated-May2026_Final%20approved_508%20Remediation%20Complete_published%20(1).pdf
- MITRE ATT&CK T1530: https://attack.mitre.org/techniques/T1530/
