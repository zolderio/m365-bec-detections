# T1538 — Cloud Service Dashboard

| | |
|---|---|
| **MITRE tactic** | Discovery |
| **Advisory phase** | 09. Discovery |
| **Advisory measure** | 014 — Restrict access to Microsoft Entra (priority Medium, impact Low, effort Low) |
| **Related technique** | [T1562.001](T1562.001-impair-defenses.md) — the drift query below also belongs to measure 013 |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

## Recommendation

> ### `SENTINEL-RULE` — but be honest: this is hunting, not alerting
>
> There is no Defender alert, and there is hardly anything to detect here
> either. Reading the directory by an authenticated user is normal behaviour
> that produces no audit record; only *changes* are logged. What you can build
> is a volume detection on Microsoft Graph traffic and a drift rule on the
> setting itself. Treat both as hunting queries, not as alerts that wake up a
> SOC analyst. **Do not build coverage here that you need elsewhere** — the gain
> from measure 014 lies in prevention, not in detection, and even that
> prevention is limited (see below).

## The measure the advisory recommends is, according to Microsoft, not a security measure

The advisory writes: *"Enable the setting Restrict access to Microsoft Entra
administration portal within the user settings of Microsoft Entra ID."*

Microsoft attaches an explicit warning to this in its own documentation:

> *"The **Restrict access to Microsoft Entra administration portal** setting
> limits access to a set of commonly visited admin center pages. It is **not a
> security measure**."*

And in the explanation of the setting itself:

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

Source: https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
(consulted August 2026)

That is not a detail. An attacker with a compromised standard account does not
need a portal: one Graph call to `/v1.0/users` produces the same member list,
and `/v1.0/directoryRoles` produces who the Global Admins are. The switch
changes nothing about that. If you want to genuinely affect the Discovery phase,
the effective controls are: Conditional Access on the **Windows Azure Service
Management API** (Microsoft's own advice), and — to actually close off directory
read rights — the `authorizationPolicy` property `AllowedToReadOtherUsers` set
to `$false`, of which Microsoft itself says: *"This setting is meant for special
circumstances, so setting the flag to `$false` isn't recommended."*

## Is there a Defender alert for this?

**No.** There is no default alert policy for viewing the directory, opening the
Entra admin portal, or retrieving the user and role list. That makes sense:
these are read actions by an authenticated user, and Microsoft 365 does not log
reading the directory as an audit event.

What is logged:

| What | Where | Usable? |
|---|---|---|
| The sign-in to the admin portal | `SigninLogs` (Entra) | Yes, as a proxy — see query 1 |
| The Graph calls themselves | `MicrosoftGraphActivityLogs` (Sentinel) / `GraphAPIAuditEvents` (XDR) | Yes, this is the only real visibility — see query 2 |
| Reading the user list in the portal | nowhere | No |
| Switching off the portal restriction | `AuditLogs` (Entra) | Yes, as a drift signal — see query 3 |

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `SigninLogs` | Diagnostic setting on Microsoft Entra ID, category **SignInLogs**, to the Log Analytics workspace. |
| Microsoft Sentinel | `MicrosoftGraphActivityLogs` | Diagnostic setting on Microsoft Entra ID, category **MicrosoftGraphActivityLogs**. This is **off** by default and is the most underestimated missing source in this whole advisory. |
| Microsoft Sentinel | `AuditLogs` | Diagnostic setting on Microsoft Entra ID, category **AuditLogs**. Related to measure 013 (configuration drift). |
| Defender XDR advanced hunting | `GraphAPIAuditEvents` | Microsoft: *"Microsoft Entra ID API requests made to Microsoft Graph API for resources in the tenant"*. Availability differs per tenant; check the schema reference in your own portal. |

## KQL — Sentinel (SigninLogs): sign-in to the administration endpoints

```kql
// Non-administrators signing in to the Azure/Entra management layer.
// "Windows Azure Service Management API" is the resource Microsoft itself
// names as the target for a Conditional Access policy on this access, which
// makes it the best-documented anchor value. The exact AppDisplayName of the
// Entra admin center is NOT publicly documented -- only fill that in after you
// have checked in your own tenant what appears.
let lookback = 7d;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0                       // successful sign-ins only
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

This query on its own is noise. It becomes usable if you limit it to users
without an administrative role, or to users who have not done this before:

```kql
// Only users who did not do this in the preceding 30 days.
let known = SigninLogs
    | where TimeGenerated between (ago(37d) .. ago(7d))
    | where ResourceDisplayName has "Windows Azure Service Management API"
    | distinct UserPrincipalName;
// ... place at the end of the query above:
| where UserPrincipalName !in (known)
```

## KQL — Sentinel (MicrosoftGraphActivityLogs): the real Discovery detection

```kql
// Enumeration of users, groups and roles via Microsoft Graph.
// This is where T1538 actually takes place in a modern tenant: not in the
// portal, but in a script. Which is why the portal restriction from measure
// 014 does nothing against it.
let lookback = 7d;
let threshold = 200;                 // number of directory reads within the window
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

Watch the `UserAgent` column: legitimate enumeration usually comes from a known
SDK or from the portal itself; a bare `python-requests`, `curl` or a
Graph PowerShell agent on a user account that has no role in that is the
interesting case.

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

## KQL — Sentinel (AuditLogs): drift on the setting itself

The advisory explicitly asks for this: *"Monitor regularly for changes to the
access settings of the administration portal in order to prevent this
restriction from being lifted unintentionally (configuration drift)."*

```kql
// Change to the authorization policy or the tenant-wide settings.
// The switch "Restrict access to Microsoft Entra administration portal"
// belongs in the authorizationPolicy; WHICH activity Microsoft exactly writes
// away for this specific switch is NOT publicly documented.
// That is why both candidate activities are in the filter -- verify in your
// own tenant which of the two appears and then narrow it down.
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

The category and activity names come from Microsoft's own audit activities
reference; linking *that* activity to *that* switch is the unverified step.

## Why this matters for BEC

In BEC, Discovery is not an end in itself but the preparation for the
persuasion step. The advisory describes it sharply: *"When an attacker has
access to a standard user account, they can easily retrieve, via the Entra
portal, a list of all employees, their specific roles (such as who is the Global
Admin or the CFO) and the business applications in use. This information is
crucial for preparing highly targeted and credible follow-up steps, such as
spearphishing or impersonation of key figures."*

Concretely: the attacker works out who has signing authority, who does accounts
payable and who is on holiday. That is what makes an internal spearphishing
message (see [T1534](T1534-internal-spearphishing.md)) credible.

Be realistic here about the return on detection. Observing this phase is largely
impossible in Microsoft 365 without `MicrosoftGraphActivityLogs`, and even then
you detect volume, not intent. In this case the investment belongs with the
phases before it (Initial Access, Credential Access) and after it (Lateral
Movement), not here.

## References

- Microsoft, default user permissions and the portal restriction: https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
- Microsoft, alert policies (to confirm that no policy exists for this): https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, MicrosoftGraphActivityLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs
- Microsoft, SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft, AuditLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs
- Microsoft, Entra audit activities reference (AuthorizationPolicy / Update authorization policy): https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, advanced hunting schema tables (GraphAPIAuditEvents): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
- MITRE ATT&CK T1538: https://attack.mitre.org/techniques/T1538/
