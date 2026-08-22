# T1537 — Transfer Data to Cloud Account

| | |
|---|---|
| **MITRE tactic** | Exfiltration (ATT&CK); the advisory places the technique under Lateral Movement |
| **Advisory phase** | 10. Lateral Movement |
| **Advisory measure** | 015 — Internal and outbound phishing detection (priority Medium, impact High, effort Medium) |
| **Related techniques** | [T1534](T1534-internal-spearphishing.md) and [T1566.003](T1566.003-spearphishing-via-service.md) — same measure |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — the only alert is E5-only and is being deprecated
>
> The only default alert policy that appears to fire on this is `Unusual volume
> of external file sharing`, severity **Medium**, and it requires **E5/G5 or the
> Defender for Office 365 Plan 2 add-on**. On top of that it sits in the
> *Information governance alert policies* section, about which Microsoft writes:
> *"The alert policies in this section are in the process of being deprecated
> based on customer feedback as false positives."* You cannot build coverage on
> a deprecated E5 alert. Adjusting the severity does not solve this — the
> problem is the licence and the lifespan, not the level. Build your own rule on
> the sharing operations in the Unified Audit Log; those are in every licence
> with Exchange/SharePoint Online.

## Is there a Defender alert for this?

**Barely.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Default severity** | **Medium** |
| **Licensing** | **E5/G5 or the Defender for Office 365 Plan 2 add-on** |
| **What it is** | Microsoft: *"Generates an alert when an unusually large number of files in SharePoint or OneDrive are shared with users outside of your organization."* |
| **Limitation 1** | Fires on *volume*. In BEC it is often about one folder of invoices or one set of contracts — no unusual volume. |
| **Limitation 2** | Sits in the *Information governance alert policies* section, which Microsoft is deprecating because of false positives. Microsoft advises there itself: *"To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

**Defender for Cloud Apps.** The anomaly detections *Unusual file share
activities* and *Unusual multiple file download activities* are still in the list
of active *Unusual activities (by user)* policies and were **not** included in
the June 2025 clean-up. They do require Defender for Cloud Apps and a learning
period of seven days. Two adjacent policies were switched off and are often
still counted as coverage: *Suspicious file access activity (by user)* and
*Ransomware activity*. Of the first, Microsoft says it is *"disabled, migrated to
the new dynamic model and renamed to **Suspicious file access indicative of
lateral movement** and **Suspicious file access from untrusted ISP and user agent
with malicious IP indicator**"*.
Source: https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**, with the SharePoint workload enabled. Sharing events arrive as `RecordType` **SharePointSharingOperation** (14), file actions as **SharePointFileOperation** (6). Requires measure 012 (UAL enabled). |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps integration with **Microsoft 365 activities** enabled. Retention 30 days. |

## KQL — Sentinel (OfficeActivity): sharing to the outside

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
// Sharing operations in SharePoint and OneDrive where the recipient is outside
// the organisation. The operation names are taken literally from Microsoft's
// audit activities reference.
let lookback = 7d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
let ShareOperations = dynamic([
    "AnonymousLinkCreated",       // link without authentication: anyone who has it
    "SecureLinkCreated",          // secure sharing link
    "AddedToSecureLink",          // someone added to an existing sharing link
    "SharingInvitationCreated",   // invitation to someone outside the organisation
    "CompanyLinkCreated",         // organisation-wide link
    "SharingSet"]);
OfficeActivity
| where TimeGenerated > ago(lookback)
| where OfficeWorkload in~ ("SharePoint", "OneDrive")
| where Operation in~ (ShareOperations)
| extend Recipient = coalesce(TargetUserOrGroupName, UserSharedWith)
| extend RecipientDomain = tolower(tostring(split(Recipient, "@")[1]))
// Anonymous links have no recipient: those are external by definition.
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

## KQL — Sentinel: the pattern that matters in BEC

An individual external share is daily business in most organisations. What makes
it suspicious in BEC is the combination: a user who shares several files
externally in a short period to a domain the organisation has never shared with
before, or who first downloads in bulk and then shares.

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
// Burst: many external sharing actions by one user within an hour, to a
// domain that did not appear in the preceding 30 days.
let lookback = 7d;
let ownDomains = dynamic(["yourdomain.example", "yourseconddomain.example"]);   // <-- adjust
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
| where RecipientDomain !in (KnownDomains)          // new external domain
| summarize Actions = count(),
            Files = dcount(SourceFileName),
            FileList = make_set(SourceFileName, 25),
            Recipients = make_set(coalesce(TargetUserOrGroupName, UserSharedWith), 15),
            First = min(TimeGenerated), Last = max(TimeGenerated)
    by UserId, RecipientDomain, bin(TimeGenerated, 1h)
| where Files >= 3
| order by Files desc
```

And the bulk download that often precedes it:

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
// Unusually many downloaded files by a single account within an hour.
let lookback = 7d;
let threshold = 100;                 // calibrate to your own organisation
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

The `UncommonForUser` column is usable here as cheap tuning: Microsoft fills it
with those attributes of the event that are unusual for this user. An empty
string means the event was not enriched; `[]` means enriched without an anomaly.

## Why this matters for BEC

The advisory summarises T1537 as *"moving data between different cloud
resources"* and places it under Lateral Movement, together with internal
spearphishing and spearphishing via a cloud service. For a BEC context that is
the right placement, even though ATT&CK lists the technique under Exfiltration:
in BEC the purpose of the sharing is rarely the data itself, but reaching a next
victim or taking along the evidence that makes a fraudulent payment request
credible.

Two concrete BEC patterns these queries touch:

1. **The invoice set.** The attacker shares or downloads the folder with
   outstanding invoices and purchase orders. Those documents supply the amounts,
   the reference numbers and the house style that make the fraudulent payment
   request convincing. Low volume, high impact — exactly what
   `Unusual volume of external file sharing` misses.
2. **The shareable bait.** The attacker puts a document in their own OneDrive,
   creates an anonymous link for it and then shares that internally. See
   [T1566.003](T1566.003-spearphishing-via-service.md); the sharing action is
   visible in the same tables as above.

When assessing, watch for the combination with the other techniques in this
cluster. An external share that falls within the same hour as a new hiding rule
([T1564.008](T1564.008-email-hiding-rules.md)) or an intra-org fan-out
([T1534](T1534-internal-spearphishing.md)) is no longer an isolated event.

## References

- Microsoft, alert policies (including the deprecation note under Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, audit activities (SharePoint/OneDrive sharing operations): https://learn.microsoft.com/en-us/purview/audit-log-activities
- Microsoft, anomaly detection policies in Defender for Cloud Apps (which policies were switched off): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, Management Activity API schema (SharePointSharingOperation = 14, SharePointFileOperation = 6): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- MITRE ATT&CK T1537: https://attack.mitre.org/techniques/T1537/
