# Severity- en detectie-overzicht

Alle technieken uit het NCSC/Cyclotron BEC-advies, gesorteerd op hoeveel Defender
zelf al voor je doet. Bovenaan staat wat je met een alert afkunt, onderaan wat je
zelf moet bouwen.

| Techniek | Naam | Maatregel | Aanbevolen detectie |
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
| [T1078](detections/T1078-valid-accounts-guest-delegation.md) | Valid Accounts (gast- en delegatietoegang tot mail en SharePoint) | 016, 017 | `SENTINEL-RULE` |
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

## Verdeling

| Aanbeveling | Aantal |
|---|---|
| `DEFENDER-ALERT + SENTINEL-RULE` | 9 |
| `SENTINEL-RULE` | 18 |

Totaal 27 technieken.

**Voor geen enkele techniek in dit advies is een Defender-alert alleen toereikend.**
Bij negen technieken is er een bruikbaar alert dat je moet aanzetten, maar het laat
een gat dat er in de praktijk toe doet — meestal doordat het alert een deel van de
uitvoeringswijzen niet dekt, of doordat het een E5- of add-on-licentie vereist die
de doelgroep van dit advies, het mkb, niet heeft. Bij de overige achttien is er
niets om op te leunen.

