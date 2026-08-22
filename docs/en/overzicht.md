# Severity and detection overview

All techniques from the NCSC/Cyclotron BEC advisory, sorted by how much Defender
already does for you. At the top is what you can handle with an alert, at the
bottom what you have to build yourself.

| Technique | Name | Measure | Recommended detection |
|---|---|---|---|
| [T1059](detections/T1059-execution-via-malicious-scripts.md) | Command and Scripting Interpreter | 008 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1068](detections/T1068-privilege-escalation.md) | Exploitation for Privilege Escalation | 010 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1534](detections/T1534-internal-spearphishing.md) | Internal Spearphishing | 015 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1539](detections/T1539-steal-web-session-cookie.md) | Steal Web Session Cookie | 004, 005 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1566.002](detections/T1566.002-spearphishing-link.md) | Spearphishing Link | 004, 005 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1566.003](detections/T1566.003-spearphishing-via-service.md) | Phishing: Spearphishing via Service | 015 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1656](detections/T1656-impersonation.md) | Impersonation | 019 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1657](detections/T1657-financial-theft.md) | Financial Theft | 019 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1671](detections/T1671-illicit-consent-grant.md) | Cloud Application Integration (Illicit Consent Grant) | 009 | `DEFENDER-ALERT + SENTINEL-RULE` |
| [T1078](detections/T1078-valid-accounts-guest-delegation.md) | Valid Accounts (guest and delegated access to mail and SharePoint) | 016, 017 | `SENTINEL-RULE` |
| [T1078.004](detections/T1078.004-cloud-accounts.md) | Valid Accounts: Cloud Accounts | 006, 007 | `SENTINEL-RULE` |
| [T1098.001](detections/T1098.001-additional-cloud-credentials.md) | Account Manipulation: Additional Cloud Credentials | 009 | `SENTINEL-RULE` |
| [T1110.003](detections/T1110.003-password-spraying.md) | Password Spraying | 004, 005 | `SENTINEL-RULE` |
| [T1114.002](detections/T1114.002-remote-email-collection.md) | Remote Email Collection | 016, 017 | `SENTINEL-RULE` |
| [T1114.003](detections/T1114.003-email-forwarding-rule.md) | Email Forwarding Rule | 016 | `SENTINEL-RULE` |
| [T1204](detections/T1204-user-execution.md) | User Execution | 008 | `SENTINEL-RULE` |
| [T1530](detections/T1530-data-from-cloud-storage.md) | Data from Cloud Storage | 016, 017 | `SENTINEL-RULE` |
| [T1537](detections/T1537-transfer-data-to-cloud-account.md) | Transfer Data to Cloud Account | 015 | `SENTINEL-RULE` |
| [T1538](detections/T1538-cloud-service-dashboard.md) | Cloud Service Dashboard | 014 | `SENTINEL-RULE` |
| [T1556.006](detections/T1556.006-mfa-modification.md) | Modify Authentication Process: Multi-Factor Authentication | 009 | `SENTINEL-RULE` |
| [T1557](detections/T1557-adversary-in-the-middle.md) | Adversary-in-the-Middle | 004, 005 | `SENTINEL-RULE` |
| [T1562.001](detections/T1562.001-impair-defenses.md) | Impair Defenses: Disable or Modify Tools | 011, 012, 013 | `SENTINEL-RULE` |
| [T1564.008](detections/T1564.008-email-hiding-rules.md) | Email Hiding Rules | 011, 012, 013 | `SENTINEL-RULE` |
| [T1567](detections/T1567-exfiltration-over-web-services.md) | Exfiltration Over Web Services | 018 | `SENTINEL-RULE` |
| [T1598](detections/T1598-phishing-for-information.md) | Phishing for Information | 001 | `SENTINEL-RULE` |
| [T1621](detections/T1621-mfa-request-generation.md) | Multi-Factor Authentication Request Generation | 004, 005 | `SENTINEL-RULE` |
| [T1672](detections/T1672-email-spoofing.md) | E-mail Spoofing | 002, 003 | `SENTINEL-RULE` |

## Distribution

| Recommendation | Count |
|---|---|
| `DEFENDER-ALERT + SENTINEL-RULE` | 9 |
| `SENTINEL-RULE` | 18 |

27 techniques in total.

**For not a single technique in this advisory is a Defender alert sufficient on its own.**
For nine techniques there is a usable alert that you should enable, but it leaves
a gap that matters in practice — usually because the alert does not cover some of
the ways the action can be carried out, or because it requires an E5 or add-on
licence that the audience of this advisory, SMEs, does not have. For the other
eighteen there is nothing to lean on.
