# T1078 — Valid Accounts (guest and delegated access to mail and SharePoint)

| | |
|---|---|
| **MITRE tactic** | Collection |
| **Advisory measures** | 016 — Blocking automatic email forwarding (priority High)<br>017 — Restricting Teams & SharePoint collaboration (priority Medium) |
| **Related techniques** | [T1114.002](T1114.002-remote-email-collection.md) — mailbox delegation; [T1530](T1530-data-from-cloud-storage.md) — what the guest then reads; [T1567](T1567-exfiltration-over-web-services.md) — cleaning up forgotten guest access |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — build your own analytic rule here
>
> No default alert policy for guest access exists at all. The four sections
> with default alert policies in the Defender portal (Information governance,
> Mail flow, Permissions, Threat management) contain none that fires on
> inviting a guest, on redeeming an invitation, or on a guest account that
> suddenly becomes active. The only policy in the Permissions category is
> `Elevation of Exchange admin privilege` (severity **Low**) and that one is
> about Exchange role groups. So this is entirely your own work.

## Is there a Defender alert for this?

**No, for none of the three entry points.**

| Entry point | Alert policy | Assessment |
|---|---|---|
| Guest account invited or redeemed | none | The Entra audit activities `Invite external user` and `Redeem external user invite` do exist, but there is no alert policy that fires on them. |
| Guest account accesses SharePoint or Teams | none | See [T1530](T1530-data-from-cloud-storage.md); the MDCA anomaly detections are volume-based. |
| Mailbox delegation granted | none | `Add-MailboxPermission` has no alert policy. See [T1114.002](T1114.002-remote-email-collection.md) for the delegation query. |

| | |
|---|---|
| **Alert policy (closest match)** | `Elevation of Exchange admin privilege` |
| **Default severity** | **Low** |
| **Licensing** | E1/F1/G1, E3/F3/G3 or E5/G5 |
| **Source** | https://learn.microsoft.com/en-us/defender-xdr/alert-policies |

Separately: the risk that a guest account can sign in without MFA or from an
unknown location belongs under measure 006 (conditional access policy) and 007
(monitoring of suspicious sign-in attempts), not under this detection. This
file is about what a valid guest or delegated account does afterwards.

## Required data source

| Platform | Table | What needs to be onboarded |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, category *AuditLogs*. Needed for invitations and the guest lifecycle. |
| Microsoft Sentinel | `SigninLogs` | Data connector **Microsoft Entra ID**, category *SignInLogs*. Contains the column `UserType` with the values `member` and `guest`, plus `CrossTenantAccessType` and `HomeTenantId`. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** (SharePoint and Exchange workload). For what the guest accesses; `TargetUserOrGroupType` is `Guest` here. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps, Microsoft 365 app connector with *Microsoft 365 activities*. Contains `IsExternalUser` and `IsImpersonated`. |
| Defender XDR advanced hunting | `EntraIdSignInEvents` | Requires **Microsoft Entra ID P2**. Contains `IsGuestUser` and `IsExternalUser`. Replaces `AADSignInEventsBeta` as of 19 Oct 2026. |

Without measure 012 (UAL enabled) the `OfficeActivity` queries do nothing.

## KQL — Sentinel (AuditLogs, SigninLogs, OfficeActivity)

```kql
// 1. Guest accounts being invited and redeemed. The documented
//    Entra audit activities sit under the UserManagement category.
let lookback = 30d;
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

```kql
// 2. Guest account signing in again after a longer silence. That is the pattern of
//    'forgotten access' from measure 018 and the pattern of a hijacked
//    guest account. UserType is documented with the values member and guest.
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

```kql
// 3. What the guest then does in SharePoint/OneDrive. For sharing actions
//    the recipient is in TargetUserOrGroupName and TargetUserOrGroupType is 'Guest';
//    for access actions you recognise the guest by #EXT# in the UPN.
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

```kql
// 4. Delegation on the mailbox — same logic, different workload.
//    An extended variant with parameter extraction is in T1114.002.
let lookback = 7d;
OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in~ ("Add-MailboxPermission", "Add-RecipientPermission", "UpdateFolderPermissions")
| project TimeGenerated, UserId, Operation, MailboxOwnerUPN,
          Parameters, ClientIP, ExternalAccess, ResultStatus
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (CloudAppEvents, EntraIdSignInEvents)

```kql
// Activity of external users across all connected workloads.
// IsExternalUser is a documented column of CloudAppEvents.
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

```kql
// Guest accounts accessing a resource they have not accessed before.
// EntraIdSignInEvents requires Entra ID P2; until 19 Oct 2026 this table is
// also still called AADSignInEventsBeta.
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

## Tightening on trusted domains

Measure 017 calls for an allowlist of trusted domains. As long as one exists,
the interesting case is a guest from outside that list. In queries 1 and 2,
replace the last filter line:

```kql
| extend GuestDomain = tolower(tostring(split(replace_string(Guest, "_", "@"), "@")[-1]))
| where GuestDomain !in~ ("trustedpartner.example", "trustedcustomer.example")   // <-- adjust
```

Note that guest UPNs in Entra take the form
`name_external.com#EXT#@owndomain.onmicrosoft.com`; the real domain is *before*
`#EXT#`, not after it. Test this extraction against your own data before using
it as a filter.

## Why this matters for BEC

A guest account is a valid account: it does not trip intrusion detection, it
does not appear on the employee list, and it does not disappear when someone
leaves the organisation. Under measure 017 the NCSC/Cyclotron advisory names
exactly these three entry points — *"guest accounts, misconfigured sharing
settings or anonymous links"* — and under measure 018 the consequence: *"In BEC
incidents attackers often abuse 'forgotten' access, such as old guest accounts
that are no longer in use."*

The same applies on the mail side with delegation: FullAccess or Send-As on a
mailbox survives a password change and an MFA reset of the victim, just as a
forwarding rule does. Anyone who, after an incident, only resets the password
and revokes the sessions leaves these two entry points open.

## References

- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, Entra audit log activity reference (Access reviews, Invited users): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, SigninLogs schema (column UserType): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, OfficeActivity schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- Microsoft, CloudAppEvents schema (IsExternalUser): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table
- Microsoft, EntraIdSignInEvents schema (IsGuestUser): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsigninevents-table
- Microsoft, sharing auditing in the audit log (TargetUserOrGroupType): https://learn.microsoft.com/en-us/purview/audit-log-sharing
- Microsoft, manage mailbox auditing (sign-in types Owner/Delegate/Admin): https://learn.microsoft.com/en-us/purview/audit-mailboxes
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
