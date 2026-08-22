# T1567 — Exfiltration Over Web Services

| | |
|---|---|
| **MITRE tactic** | Exfiltration |
| **Advisory measure** | 018 — Access Reviews (priority Medium) |
| **Related techniques** | [T1530](T1530-data-from-cloud-storage.md) — the collection; [T1078](T1078-valid-accounts-guest-delegation.md) — the forgotten access that is abused here |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> The only default alert policy in this area,
> `Unusual volume of external file sharing`, is **Medium**, requires E5/G5 or
> Defender for Office 365 Plan 2, and is slated to disappear: Microsoft writes
> that the policies in that section are *"in the process of being deprecated
> based on customer feedback as false positives"*, with the advice to create a
> custom policy for it yourself. That is exactly what this file does. An
> additional argument: the policy measures volume, whereas in BEC a single
> anonymous link to a single folder of invoices is enough.

## Is there a Defender alert for this?

**Yes, but it is being phased out.**

| | |
|---|---|
| **Alert policy** | `Unusual volume of external file sharing` |
| **Description (Microsoft)** | *"Generates an alert when an unusually large number of files in SharePoint or OneDrive are shared with users outside of your organization."* |
| **Default severity** | **Medium** |
| **Licensing** | E5/G5 or Defender for Office 365 Plan 2 add-on |
| **Category** | Information governance |
| **Status** | **Being phased out because of false positives.** Above the section *Information governance alert policies* it says: *"The alert policies in this section are in the process of being deprecated based on customer feedback as false positives. To retain the functionality of these alert policies, you can create custom alert policies with the same settings."* This policy is the only one in that section. Verified 22 Aug 2026 on the page with ms.date 2026-08-03. |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

For the access reviews themselves (the core of measure 018) there is no alert
policy. The actions are, however, documented as Entra audit activities, under
the categories `Policy`, `UserManagement` and `DirectoryManagement`:
`Create access review`, `Update access review`, `Delete access review`,
`Access review ended`, `Apply decision`, `Approve decision`, `Deny decision`,
`Auto review`, `Auto apply review`, `Apply review`. With those you can measure
whether the measure is running at all — see the last query.

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**, SharePoint workload enabled. Sharing actions arrive with `RecordType` = `SharePointSharingOperation`; there is no separate `SharePointFileOperation` table in Log Analytics. Requires measure 012 (UAL enabled). |
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, category *AuditLogs*. For the access review activities. Access reviews themselves require **Microsoft Entra ID Governance** or Entra ID P2 — that is a precondition of measure 018, not a detection choice. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps, Microsoft 365 app connector with *Microsoft 365 activities*. Retention 30 days. |

## The sharing actions that matter

Microsoft documents a separate event for each way of sharing. For exfiltration
these are the cases you want to see, with the reason why:

| Operation | What Microsoft says about it | Why this is BEC-relevant |
|---|---|---|
| `AnonymousLinkCreated` | *"An anonymous link (also called an 'Anyone' link) is created for a resource. Because an anonymous link can be created and then copied, it's reasonable to assume that any document that has an anonymous link is shared with a target user."* | No recipient, no authentication, no revocation when an account is disabled. The cleanest exfiltration route SharePoint has. |
| `AnonymousLinkUsed` | *"This event is logged when an anonymous link is used to access a resource."* | Proof that the link was actually used, with the IP. |
| `SecureLinkCreated` + `AddedToSecureLink` | *"A user creates a 'specific people link'… The person that the resource is shared with is identified in the audit record for the AddedToSecureLink event."* The timestamps of both are close together. | The recipient only appears in the second event. Anyone filtering on `SecureLinkCreated` alone does not see who it was shared with. |
| `SharingInvitationCreated` / `SharingInvitationAccepted` | Invitation to an external address, and the moment it is redeemed. | The gap between those two events is the window in which you can still revoke. |

You recognise external recipients by `TargetUserOrGroupType`. Microsoft:
*"Identifies whether the target user or group is a Member, Guest,
SharePointGroup, SecurityGroup, or Partner"* — for a resource shared with
someone outside the organisation the value is **`Guest`**.

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
// Sharing outwards: anonymous links, specific-people links and invitations.
// AddedToSecureLink is explicitly included because SecureLinkCreated does not
// contain the recipient.
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

Sharpening it to genuinely external:

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
// (a) recipients outside the organisation only
| where TargetUserOrGroupType =~ "Guest"

// (b) or: anonymous links, regardless of recipient - by definition they have none
| where Operation in~ ("AnonymousLinkCreated", "AnonymousLinkUsed")

// (c) domain filter on the recipient, if there is an allowlist (measure 017)
| extend RecipientDomain = tolower(tostring(split(TargetUserOrGroupName, "@")[1]))
| where isnotempty(RecipientDomain)
| where RecipientDomain !in~ ("trustedpartner.example", "trustedcustomer.example")   // <-- adjust
```

The pattern that matters most in practice — a user creating several external
sharing links on financial documents within one hour:

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
let lookback = 7d;
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
| where Count >= 3          // <-- tune the threshold to your own baseline
| order by Count desc
```

## KQL — Sentinel (AuditLogs): is measure 018 actually running?

This query detects no attacker but the absence of the measure. With 018 that is
the point: forgotten access arises because nobody reviews it.

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
// Access reviews that have been created, ended, or whose decisions have been
// applied. If this returns nothing over 90 days, the measure exists on paper
// and not in the tenant.
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

## Why this matters for BEC

In BEC, exfiltration is rarely a large data dump; it is one folder of invoices
going out through an "Anyone" link, or a guest account belonging to a former
supplier that still has access. This is why the NCSC/Cyclotron advisory ties
T1567 explicitly to access reviews and not to a DLP measure: *"In BEC incidents
attackers frequently abuse 'forgotten' access, such as old guest accounts that
are no longer in use or unnecessarily broad permissions on folders containing
sensitive financial information."*

The anonymous link is the sharpest variant of this, because Microsoft itself
states that with such a link you must assume the document has been shared — the
link may have been copied without any recipient being registered anywhere.

## References

- Microsoft, alert policies (incl. deprecation of Information governance): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, sharing auditing in the audit log: https://learn.microsoft.com/en-us/purview/audit-log-sharing
- Microsoft, Entra audit log activity reference (Access reviews): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, Office 365 Management Activity API schema (SharePoint Sharing schema): https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- Microsoft, OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- MITRE ATT&CK T1567: https://attack.mitre.org/techniques/T1567/
