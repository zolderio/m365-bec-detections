# T1671 — Cloud Application Integration (Illicit Consent Grant)

| | |
|---|---|
| **Name in the advisory** | Illicit Consent Grant — tricking users into giving a malicious OAuth app access to mailboxes and data |
| **Name in MITRE ATT&CK** | Cloud Application Integration |
| **MITRE tactic** | Persistence (TA0003) |
| **Advisory measure** | 009 — Restrict or disable OAuth app consent (priority High) |
| **Related techniques** | [T1098.001](T1098.001-additional-cloud-credentials.md) — credentials on the app that received consent; [T1204](T1204-user-execution.md) — the click that precedes it |
| **Status of this detection** | KQL not executed against a production tenant — see [test status](../teststatus.md) |

> MITRE renamed T1671 to **Cloud Application Integration**; the advisory uses the
> older label *Illicit Consent Grant*. Same technique ID, same tactic
> (Persistence), no sub-techniques.

## Recommendation

> ### `DEFENDER-ALERT + SENTINEL-RULE` — both are needed
>
> For this technique, app governance is the best coverage Microsoft provides:
> more than ten alerts aimed specifically at malicious consent patterns, with
> mail permissions as a separate point of attention and severity Medium instead
> of Informational. Enable it if you have a Defender for Cloud Apps licence — it
> is not on by default and has to be activated manually. But it does not close
> the gap: there is no alert on the consent event itself, all app governance
> detections are behavioural heuristics that only fire after the fact, and under
> an MDA licence you have nothing at all — there is no Purview alert policy for
> `Consent to application`. The Entra audit log does record the consent fully and
> immediately. Build the rule on that and scope it to the scopes that matter.

## Is there a Defender alert for this?

**Not on the consent event. On the app's behaviour afterwards: yes, provided it
is licensed and switched on.**

### App governance (Defender for Cloud Apps)

The relevant alerts, with the severity documented by Microsoft:

| Alert | Severity | ATT&CK phase according to Microsoft |
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

Microsoft states explicitly that for the **Execution** phase there are *"no
alerts currently defined"*.

| | |
|---|---|
| **Licensing** | *"App governance is available to organizations with a valid Defender for Cloud Apps license."* Defender for Cloud Apps standalone or as part of a bundle. |
| **Regional restriction** | The billing address must be outside Singapore, Poland, Italy, Qatar, Israel, Spain, Mexico and Taiwan. |
| **Enabling it** | Manually, via **Settings > Cloud Apps > App governance > Use app governance**. Up to 10 hours' wait. Alerts only start flowing once both Defender for Cloud Apps and Microsoft Defender have been opened via their portal at least once. |

### Defender for Cloud Apps anomaly detection

`Suspicious OAuth app file download activities` still exists and is active. Note
what has **not** worked since June 2025: `Unusual ISP for an OAuth app` has been
turned off and absorbed into the dynamic model under the name
`OAuth application activity from an unknown ISP`. Do not include the old name in
a coverage overview any more.

### Purview alert policies

None. The list of default alert policies contains no policy for
`Consent to application`, and the severity of a default policy cannot be changed
in any case — Microsoft: *"The other settings for these policies can't be
edited."*

## Required data source

| Platform | Table | What must be onboarded |
|---|---|---|
| Microsoft Sentinel | `AuditLogs` | Data connector **Microsoft Entra ID**, log category **AuditLogs** ticked. |
| Microsoft Sentinel | `SigninLogs` | Same connector, separate log category. Needed for correlation with the session in which consent was given. |
| Defender XDR advanced hunting | `CloudAppEvents` | Defender for Cloud Apps with the Microsoft 365 connector (**Settings > Cloud apps > App connectors**, tick *Microsoft 365 activities*). Retention 30 days. |

Does **not** depend on measure 012 (UAL) for the Sentinel route; the
`CloudAppEvents` route does lean on the Microsoft 365 connector of Defender for
Cloud Apps.

## The audit activities (exact, and what we could not verify)

From the Entra audit reference, category **ApplicationManagement**, service
**Core Directory**:

| Activity | What it means |
|---|---|
| `Consent to application` | A user or admin grants consent. According to Microsoft: *"User grants consent to an application"*. |
| `Add delegated permission grant` | Delegated access is granted. Microsoft: *"Granting delegated access to an app"*. |
| `Add app role assignment to service principal` | App-only access (application permissions). In the Entra documentation also written as *"Add app role assignment to the service principal"*. |
| `Add service principal` | The service principal is created in the tenant — the first time a multi-tenant app lands. |
| `Add app role assignment to group` | Role assignment to a group (categories GroupManagement and UserManagement). |
| `Grant contextual consent to application` | Category GroupManagement. |

**Not verified: `Add app role assignment grant to user`.** That string does not
appear in the current Entra audit reference. What is there is
`Remove app role assignment from user` (UserManagement) and
`Add app role assignment to group` (UserManagement) — the "add" counterpart for
a user is missing from that table. The variant with "grant" is widely used in
the field and will occur in many tenants, but we do not record it as fact. The
queries below therefore filter with `has "app role assignment"` instead of on an
exact string, so that both spellings are caught.

## KQL — Sentinel (AuditLogs): consent with risky scopes

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
// Consent and permission grants, with the mail scopes pulled out. The scopes are
// in modifiedProperties; exactly which property that is differs per activity,
// so we serialise the whole thing and search it as text. That is cruder than
// a parsed lookup, but it does not break when Microsoft changes the order.
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
// IsAdminConsent distinguishes "one user consented for themselves" from
// "the whole tenant has been opened up". Microsoft also points to this field in
// the remediation guidance for illicit consent grants.
| extend AdminConsent  = Props has "ConsentContext.IsAdminConsent" and Props has "True"
// extract_all pulls all scope-like strings out of the property blob; the
// intersection with the list above keeps only the scopes that matter.
| extend MatchedScopes = set_intersect(
        riskScopes,
        extract_all(@"([A-Za-z]+\.[A-Za-z\.]+|full_access_as_app)", Props))
| where AdminConsent or array_length(MatchedScopes) > 0
| project TimeGenerated, OperationName, Actor, ActorIP, AppName, AppObjectId,
          AdminConsent, MatchedScopes, Props, CorrelationId
| order by TimeGenerated desc
```

Simpler and more robust if you do not trust the scope extraction:

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

## KQL — Sentinel: consent shortly after a sign-in from an unknown IP

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
// A consent grant is only suspicious if it comes from a session that is itself
// already anomalous. This is the bridge between T1204 (the click) and this technique.
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
// Entra consent events arrive under Application "Office 365". The full stop at
// the end of the ActionType value is present in Microsoft's own hunting query
// as well; that is why we filter with startswith.
let lookback = 30d;
CloudAppEvents
| where Timestamp > ago(lookback)
| where Application == "Office 365"
| where ActionType startswith "Consent to application"
     or ActionType startswith "Add delegated permission grant"
     or ActionType has "app role assignment"
// Microsoft's documented way of filtering out admin consent.
| extend AdminConsent = tostring(RawEventData.ModifiedProperties[0].Name) == "ConsentContext.IsAdminConsent"
                        and tostring(RawEventData.ModifiedProperties[0].NewValue) == "True"
| extend spnID = tostring(RawEventData.Target[3].ID)
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, AdminConsent,
          spnID, IPAddress, CountryCode, Isp, UserAgent, IsAdminOperation, RawEventData
| order by Timestamp desc
```

The positions `ModifiedProperties[0]` and `Target[3]` come from Microsoft's
published query. Those are fixed indexes into a variable structure; if the query
returns nothing while you know consent has been granted, first inspect
`RawEventData` of a single event and adjust the indexes.

## KQL — finding app governance alerts

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
// If app governance is on, the alerts land in AlertInfo. Useful for establishing
// whether the second layer actually fires.
AlertInfo
| where Timestamp > ago(30d)
| where ServiceSource has "Cloud Apps" or DetectionSource has "App governance"
| where Title has_any ("OAuth", "consent", "app with", "App with")
| project Timestamp, Title, Severity, Category, ServiceSource, DetectionSource,
          AttackTechniques, AlertId
| order by Timestamp desc
```

The exact values of `ServiceSource` and `DetectionSource` for app governance
alerts are **not publicly documented**; run
`AlertInfo | distinct ServiceSource, DetectionSource` to establish them in your
own tenant and then tighten the filters.

## Why this matters for BEC

Microsoft describes the attack and why it survives the standard response:
*"Normal remediation steps (for example, resetting passwords or requiring
multifactor authentication (MFA)) aren't effective against this type of attack,
because these apps are external to the organization."* The attacker no longer
needs an account — the app has *"account-level access to data"*.

In the same guidance Microsoft advises searching the audit log for
*"questionable **Consent to application** activities"* and checking per hit
whether `IsAdminConsent` is set to `True`: *"The value True indicates that
someone with Global Administrator access might have granted broad access to
data."* That is exactly what the first query above does, only continuously
instead of manually.

In the responder guidance on the attack against its own tenant (25 January
2024) Microsoft describes the full chain: the actor created additional malicious
OAuth applications, created a new user account to grant consent with, and used a
compromised legacy test OAuth app *"to grant them the Office 365 Exchange Online
full_access_as_app role, which allows access to mailboxes"*.

For T1671, MITRE lists mitigations including M1042: prohibiting users from
adding integrations themselves and enforcing *"Do not allow user consent"* in
Entra ID — which is measure 009 from the advisory, literally.

## References

- Microsoft, Detect and remediate illicit consent grants: https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- Microsoft, app governance threat detection alerts (alert names and severity): https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-anomaly-detection-alerts
- Microsoft, enabling app governance and licence requirements: https://learn.microsoft.com/en-us/defender-cloud-apps/app-governance-get-started
- Microsoft, anomaly detection policies (which legacy policies have been off since June 2025): https://learn.microsoft.com/en-us/defender-cloud-apps/anomaly-detection-policy
- Microsoft, Entra audit log activity reference: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
- Microsoft, View activity logs of application permissions (which audit activity belongs to which scenario): https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs
- Microsoft, hunting query `CredentialsAddAfterAdminConsentedToApp[Nobelium]` (CloudAppEvents pattern for consent): https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Persistence/CredentialsAddAfterAdminConsentedToApp%5BNobelium%5D.md
- Microsoft, Midnight Blizzard: Guidance for responders on nation-state attack (25 Jan 2024): https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
- Microsoft, AlertInfo schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- MITRE ATT&CK T1671: https://attack.mitre.org/techniques/T1671/
