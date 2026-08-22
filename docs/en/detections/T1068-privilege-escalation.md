# T1068 — Exploitation for Privilege Escalation

| | |
|---|---|
| **Name in the advisory** | Exploitation for Privilege Escalation — abusing configuration mistakes to obtain administrative rights |
| **Name in MITRE ATT&CK** | Exploitation for Privilege Escalation |
| **MITRE tactic** | Privilege Escalation (TA0004) |
| **Advisory measure** | 010 — Least privilege principle & PIM (priority Medium) |
| **Related technique** | [T1098.001](T1098.001-additional-cloud-credentials.md) — MITRE places that technique under Privilege Escalation as well |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

> **A difference in scope, stated deliberately.** MITRE describes T1068 as
> exploiting software vulnerabilities to obtain local or kernel-level
> privileges, with Containers, Linux, Windows and macOS as its platforms — no
> cloud or identity platform. The advisory uses the ID for something else:
> abuse of rights within the tenant through overly broad or permanent
> administrative roles. This detection follows the intent of the advisory
> (measure 010) and therefore the identity side. Anyone wanting to cover T1068
> in the MITRE sense ends up with endpoint detection and not with the tables
> below.

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE` — both are needed
>
> `Elevation of Exchange admin privilege` exists, does not require E5 and is
> included in E1/E3, so enable it and route it to a mailbox where somebody is
> watching. But it does not cover two things. First, it only covers Exchange
> Online: an assignment to an Entra directory role such as Global Administrator
> or Privileged Role Administrator falls outside it and has no alert policy.
> Second, the default severity is **Low**, and contrary to what is often
> assumed it cannot be raised: the settings of a default policy cannot be
> edited and `Set-ProtectionAlert` refuses default policies. A custom alert
> policy with `New-ProtectionAlert -Severity High` is the workaround. You build
> the Entra side in Sentinel on `AuditLogs`.

## Is there a Defender alert for this?

**For Exchange there is, for Entra there is not — and the PIM alert that comes
closest costs Entra ID P2.**

| | |
|---|---|
| **Alert policy** | `Elevation of Exchange admin privilege` |
| **Default severity** | **Low** |
| **Licensing** | E1/F1/G1, E3/F3/G3 or E5/G5 — no add-on required |
| **Category** | Permissions |
| **What it covers** | Microsoft: *"Generates an alert when someone is assigned administrative permissions in your Exchange Online organization. For example, when a user is added to the Organization Management role group in Exchange Online."* |
| **What it does not cover** | Assignments to Microsoft Entra directory roles. There is no default alert policy for those. |

### Raising the severity is not possible — this is the correction

Microsoft on the default alert policies: *"You can turn off these policies (or
back on again), set up a list of recipients to send email notifications to, and
set a daily notification limit. **The other settings for these policies can't be
edited.**"* And on the cmdlet: *"You can't use this cmdlet to edit default alert
policies. You can only modify alerts that you created using the
New-ProtectionAlert cmdlet."*

The workaround is a custom policy with `New-ProtectionAlert` and
`-Severity High`. Mind the licensing boundary: alert policies with a threshold
or based on "unusual activity" require E5/G5 or an add-on; with E1/F1/G1 or
E3/F3/G3 you can only create policies that fire every time the activity occurs.
For role changes that is exactly right — the volume is low. This route is **not
verified** against a tenant.

What you can do without any licence at all on the existing policy: enable email
notifications and set the recipients. That is measure 011 from the advisory
(forwarding security alerts) and it is the cheapest win here.

### What Entra itself provides: PIM alerts

Privileged Identity Management has its own alerts, with a severity that
Microsoft documents per alert:

| PIM alert | Severity |
|---|---|
| `Roles are being assigned outside of Privileged Identity Management` | **High** |
| `Potential stale accounts in a privileged role` | **Medium** |
| `Administrators aren't using their privileged roles` | **Low** |
| `Roles don't require multifactor authentication for activation` | **Low** |
| `There are too many Global Administrators` | **Low** |
| `Roles are being activated too frequently` | **Low** |
| `The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance` | **Low** |

The first one is the detection that belongs to measure 010: a role granted
outside PIM is either a process failure or an attacker. Microsoft: *"Privileged
role assignments made outside of Privileged Identity Management aren't properly
monitored and might indicate an active attack."* For this alert PIM sends email
to Privileged Role Administrators, Security Administrators and Global
Administrators, provided the alert is enabled in the alert settings.

| | |
|---|---|
| **Licensing for PIM** | Requires licences; see *Microsoft Entra ID Governance licensing fundamentals*. In practice Microsoft Entra ID P2 or Entra ID Governance — PIM even has a dedicated alert for this (`The organization doesn't have Microsoft Entra ID P2 or Microsoft Entra ID Governance`). |
| **Who may read PIM alerts** | Only Global Administrator, Privileged Role Administrator, Global Reader, Security Administrator and Security Reader. |

### Entra ID Protection

`Anomalous user activity` (user risk, offline, riskEventType
`anomalousUserActivity`, **Microsoft Entra ID P2**) is the only detection that
comes close here: *"This risk detection baselines normal administrative user
behavior in Microsoft Entra ID, and spots anomalous patterns of behavior like
suspicious changes to the directory."* It is a heuristic over administrator
behaviour, not an alert on a specific role assignment. Without P2 you only see
`Additional risk detected` without any details.

## Required data source

| Platform | Table | What needs to be onboarded |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, log category **AuditLogs** ticked in the diagnostic setting. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365** with the Exchange workload enabled, for the Exchange role groups. Requires an enabled Unified Audit Log — **advisory measure 012**. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps with the Microsoft 365 connector. Retention 30 days. |
| Defender XDR advanced hunting | `AlertInfo` | To establish whether `Elevation of Exchange admin privilege` actually fires. |

The Entra side does **not** depend on measure 012; the Exchange side
(`OfficeActivity`) does. If the UAL is off, the Exchange query returns nothing,
and that is not a detection problem but a logging problem.

## KQL — Sentinel (AuditLogs): assignment to an Entra directory role

```kql
// All role assignments, permanent and eligible. The PIM variants are included
// deliberately: if the organisation uses PIM, the distinction between "via PIM" and
// "outside of it" is exactly what you want to see.
let lookback = 30d;
let sensitiveRoles = dynamic([
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
// The target user and the role name sit in different elements of
// TargetResources; mv-expand prevents you from missing the role name through a fixed index.
| mv-expand Target = TargetResources
| extend TargetType = tostring(Target.type)
| extend TargetName = coalesce(tostring(Target.userPrincipalName), tostring(Target.displayName))
| extend RoleName   = tostring(parse_json(tostring(Target.modifiedProperties))[1].newValue)
| extend RoleName   = trim('"', tostring(RoleName))
| extend Sensitive  = RoleName in (sensitiveRoles)
// LoggedByService shows whether PIM made the assignment. If it did not, in a
// tenant that uses PIM, this is the "assigned outside of PIM" situation.
| project TimeGenerated, OperationName, Actor, ActorIP, TargetType, TargetName,
          RoleName, Sensitive, LoggedByService, CorrelationId
| order by TimeGenerated desc
```

The position of the role name within `modifiedProperties` differs per activity
type; index `[1]` above is the usual place for `Role.DisplayName` but is **not
verified**. Check it against one sample event and adjust, or leave the
extraction out and assess `Doel.modifiedProperties` manually.

## KQL — Sentinel: role assignment outside PIM

```kql
// The Sentinel counterpart of the PIM alert "Roles are being assigned outside of
// Privileged Identity Management". Usable in tenants that use PIM.
// According to the table documentation, LoggedByService contains values such as
// "Core Directory" and "Privileged Identity Management".
let lookback = 30d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where Category == "RoleManagement"
| where OperationName in ("Add member to role", "Add eligible member to role")
| where Result == "success"
| where LoggedByService !has "Privileged Identity Management"
| extend Actor   = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)
| mv-expand Target = TargetResources
| extend TargetName = coalesce(tostring(Target.userPrincipalName), tostring(Target.displayName))
| project TimeGenerated, OperationName, LoggedByService, Actor, ActorIP, TargetName,
          Target, CorrelationId
| order by TimeGenerated desc
```

First run `AuditLogs | where Category == "RoleManagement" | distinct
LoggedByService` to establish which values your tenant writes. The exact
spelling of the PIM value is **not verified**.

## KQL — Sentinel (OfficeActivity): Exchange role groups

```kql
// The Exchange side, which is where the Elevation of Exchange admin privilege alert sits.
// This is the query you use to check whether that alert is complete —
// and to build your own, higher-rated rule on top of it.
let lookback = 30d;
let criticalRoleGroups = dynamic([
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
| extend RoleGroup = extract(@"(?i)""Name""\s*:\s*""Identity""\s*,\s*""Value""\s*:\s*""([^""]+)""", 1, Params)
| extend Critical = RoleGroup in~ (criticalRoleGroups)
| project TimeGenerated, UserId, Operation, ClientIP, RoleGroup, Critical, Params,
          OriginatingServer
| order by TimeGenerated desc
```

Parsing `Parameters` is best effort: it is a JSON string whose ordering is not
guaranteed. That is why the `Params` field is also included in the output, so
that an analyst can always see the raw contents.

## KQL — Defender XDR advanced hunting: does the alert actually fire?

```kql
// Check whether the alert policy actually produces alerts and with which
// severity they arrive. A policy that is enabled but never fires is not
// coverage.
AlertInfo
| where Timestamp > ago(90d)
| where Title has "Exchange admin privilege"
| project Timestamp, Title, Severity, Category, ServiceSource, DetectionSource, AlertId
| order by Timestamp desc
```

```kql
// Role changes in CloudAppEvents, for tenants that have no Entra diagnostic
// setting pointing at Log Analytics. Entra audit events arrive under
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

The exact `ActionType` values for role changes in `CloudAppEvents` are **not
verified**; `has_any` is deliberately broad here. Take inventory with
`CloudAppEvents | where Application == "Office 365" | where ActionType has "role"
| distinct ActionType`.

## Why this matters for BEC

In BEC, privilege escalation is rarely a goal in itself and almost always the
run-up to reach: from one mailbox to every mailbox, or to switching off the
logging and the alerts (measures 011 and 013). The advisory phrases it like
this under measure 010: *"Overly broad or permanent administrative rights give
attackers the ability to change permissions, create new accounts or disable
security settings."*

The real-world variant is in Microsoft's responder guidance of 25 January 2024:
the actor used a compromised OAuth app to grant itself the role
`full_access_as_app` on Office 365 Exchange Online — *"which allows access to
mailboxes"*. That is privilege escalation without a user ever being added to a
role group, and it is the reason this detection should be read together with
[T1671](T1671-illicit-consent-grant.md) and
[T1098.001](T1098.001-additional-cloud-credentials.md): in Microsoft 365 the
road to more rights runs through an app just as often as through a role.

## References

- Microsoft, alert policies (`Elevation of Exchange admin privilege`, severity, licensing, and the fact that default policies cannot be edited): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, `Set-ProtectionAlert` (default policies not editable, `-Severity` values): https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-protectionalert
- Microsoft, PIM security alerts for Microsoft Entra roles (alert names and severity): https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts
- Microsoft, Entra audit log activity reference (RoleManagement activities and the PIM variants): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, what are risk detections (`Anomalous user activity`, P2): https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks
- Microsoft, AuditLogs table in Azure Monitor (column `LoggedByService`): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, Midnight Blizzard: Guidance for responders on nation-state attack (25 Jan 2024): https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- MITRE ATT&CK T1068: https://attack.mitre.org/techniques/T1068/
