# T1657 — Financial Theft

| | |
|---|---|
| **MITRE-tactiek** | Impact |
| **Whitepaper-maatregel** | 019 — Administratieve verificatie van betalingen (prioriteit Hoog) |
| **Verwante techniek** | [T1656](T1656-impersonation.md) — het middel; dit bestand gaat over de uitkomst |
| **Status van deze detectie** | KQL niet uitgevoerd tegen een productie-tenant — zie [TESTING.md](../TESTING.md) |

## Aanbeveling

> ### `DEFENDER-ALERT + SENTINEL-RULE` — met een eerlijke kanttekening
>
> **Er is geen query die een frauduleuze betaling detecteert.** De handeling
> vindt plaats in het bankpakket of het ERP-systeem, niet in Microsoft 365; in
> de auditlogs van de tenant staat hooguit de mail die erom vroeg. Het enige
> echte technische vangnet dat Microsoft levert is het BEC-scenario van Defender
> XDR **attack disruption**, dat een aanval vanuit een gecompromitteerd account
> automatisch onderbreekt — zet dat aan als je de licentie hebt. Omdat dat een
> E5-klasse abonnement vereist én pas vuurt bij een gecompromitteerd account,
> hoort er een eigen rule naast die de disruptie-incidenten naar de plek brengt
> waar iemand kijkt en die het voortraject zichtbaar maakt.
>
> Maatregel 019 is en blijft **procedureel**: vier ogen, telefonische verificatie
> van bankwijzigingen via een bekend nummer, geen uitzonderingen voor de
> directie. Het advies zegt dat zelf: dit is *"de laatste 'vangrail'"*. Bouw hier
> geen detectie die dat gevoel van dekking geeft, want die dekking is er niet.

## Is er een Defender-alert voor?

**Geen alert policy. Wel één XDR-mechanisme.**

Geen van de vier secties met default alert policies (Information governance,
Mail flow, Permissions, Threat management) bevat een policy over betalingen,
factuurfraude of financiële diefstal. Dat is geen omissie: Microsoft 365 ziet de
betaling niet.

Wat er wel is:

| | |
|---|---|
| **Mechanisme** | Microsoft Defender XDR — **automatic attack disruption**, scenario BEC-fraude |
| **Wat het is** | Geen alert policy maar een incident-niveau-capaciteit die signalen uit endpoint, identiteit, e-mail en SaaS-apps correleert en de aanval automatisch onderbreekt. Microsoft noemt als voorbeeld van een incidenttitel via de API letterlijk: *"BEC financial fraud attack launched from a compromised account (attack disruption)"*. |
| **Standaard severity** | Niet publiek gedocumenteerd per scenario. Incidenten krijgen in de portal de tag *Attack Disruption* en een gele banner. |
| **Betrouwbaarheidsdrempel** | Microsoft: *"For containment actions, Defender maintains a confidence level of 99% or higher based on real production data."* |
| **Responsacties** | Onder meer *Disable user* (Defender for Identity), *Contain user* en *Contain device* (Defender for Endpoint), *Revoke user session* en *Suspend user in Entra* (Microsoft Entra ID). Alle acties zijn terug te draaien door het securityteam. |
| **Bron** | https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption |

### Licentievereisten van attack disruption — exact

Microsoft eist één van de volgende abonnementen:

- Microsoft 365 E5 of A5
- Microsoft 365 E3 met de **Microsoft Defender Suite**-add-on
- Microsoft 365 E3 met de **Enterprise Mobility + Security E5**-add-on
- Microsoft 365 A3 met de Microsoft 365 A5 Security-add-on
- Windows 10 Enterprise E5/A5 of Windows 11 Enterprise E5/A5
- Enterprise Mobility + Security (EMS) E5 of A5
- Office 365 E5 of A5
- Microsoft Defender for Endpoint (Plan 2)
- Microsoft Defender for Identity
- Microsoft Defender for Cloud Apps
- Defender for Office 365 (Plan 2)
- Microsoft Defender for Business

**Belangrijker dan de licentie is de uitrol.** Microsoft: *"if a Microsoft
Defender for Cloud Apps signal is used in a certain detection, then this product
is required to detect the relevant specific attack scenario."* Voor het
BEC-scenario betekent dat concreet drie randvoorwaarden:

1. **Defender for Cloud Apps** met een correct geconfigureerde
   Microsoft 365-connector. Microsoft is daar ongewoon stellig over: *"all
   checkboxes must be selected, including the option to enable Microsoft Entra
   ID apps"*, anders volgt gedeeltelijke functionaliteit of het falen van
   disruptie-flows.
2. **Mailboxen in Exchange Online** (niet on-premises).
3. **Mailbox audit logging** met minimaal deze events:
   `MailItemsAccessed`, `UpdateInboxRules`, `MoveToDeletedItems`, `SoftDelete`,
   `HardDelete`.

Punt 3 is de directe koppeling met [T1114.002](T1114.002-remote-email-collection.md)
en maatregel 012: zonder die audit-events werkt ook het duurste vangnet niet.

Bron: https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption

## Benodigde databron

| Platform | Tabel | Wat er onboard moet zijn |
|---|---|---|
| Defender XDR advanced hunting | `AlertInfo` / `AlertEvidence` | Alerts uit Defender for Endpoint, Office 365, Cloud Apps, Identity en aangesloten Sentinel-workspaces. Koppelen op `AlertId`. |
| Microsoft Sentinel | `SecurityAlert` | Data connector **Microsoft Defender XDR**. Bevat `AlertName`, `AlertSeverity`, `ProviderName`, `Tactics`, `Techniques`, `Entities`. |
| Microsoft Sentinel | `OfficeActivity` | Data connector **Microsoft 365**. Voor het voortraject in de mailbox. Vereist maatregel 012 (UAL aan). |
| Defender XDR advanced hunting | `EmailEvents` | Defender for Office 365. Voor uitgaande mail vanuit het gecompromitteerde account. |

## KQL — Sentinel (SecurityAlert): breng het disruptie-incident naar buiten

```kql
// Attack-disruption-incidenten en aanverwante alerts uit de Defender-stack.
// Microsoft voegt via de API de string "(attack disruption)" toe aan de titel
// van incidenten die automatisch zijn onderbroken. Filter daar niet uitsluitend
// op: de losse alerts binnen zo'n incident dragen die string niet.
let lookback = 30d;
SecurityAlert
| where TimeGenerated > ago(lookback)
| where AlertName has_any ("attack disruption", "business email", "BEC",
                           "compromised account", "financial fraud")
       or Techniques has_any ("T1657", "T1656")
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName,
          Description, CompromisedEntity, Tactics, Techniques, Entities,
          Status, IsIncident, AlertLink
| order by TimeGenerated desc
```

## KQL — Defender XDR advanced hunting (AlertInfo / AlertEvidence)

```kql
// Alerts die aan financiële diefstal of impersonatie hangen, met de betrokken
// accounts erbij. Titels zijn bewust niet hardgecodeerd: Microsoft publiceert
// geen volledige lijst van alerttitels per disruptiescenario.
let lookback = 30d;
AlertInfo
| where Timestamp > ago(lookback)
| where AttackTechniques has_any ("T1657", "T1656")
       or Title has_any ("business email", "BEC", "financial fraud", "attack disruption")
| join kind=leftouter (
    AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType =~ "User"
    | summarize Accounts = make_set(AccountUpn, 20) by AlertId
) on AlertId
| project Timestamp, AlertId, Title, Category, Severity, ServiceSource,
          DetectionSource, AttackTechniques, Accounts
| order by Timestamp desc
```

## KQL — het voortraject: wat je wél kunt zien

Dit detecteert de diefstal niet. Het detecteert de combinatie die er in bijna
elk BEC-dossier aan voorafgaat: een account dat zowel de inbox manipuleert als
naar buiten begint te mailen. Behandel dit als hunting, niet als alert.

```kql
// Sentinel — accounts die binnen 24 uur zowel een inboxregel aanmaakten of
// wijzigden, als mail verstuurden of mailboxrechten weggaven.
let lookback = 7d;
let regels = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    | project RegelTijd = TimeGenerated, UserId, RegelIP = ClientIP, Parameters;
let verzenden = OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation in~ ("Send", "SendAs", "SendOnBehalf",
                           "Add-MailboxPermission", "Add-RecipientPermission")
    | project ActieTijd = TimeGenerated, UserId, Operation, ActieIP = ClientIP;
regels
| join kind=inner verzenden on UserId
| where ActieTijd between (RegelTijd - 24h .. RegelTijd + 24h)
| summarize Acties = make_set(Operation, 10), Aantal = count(),
            IPs = make_set(ActieIP, 5), Regel = any(Parameters)
        by UserId, bin(RegelTijd, 1d)
| order by Aantal desc
```

```kql
// Defender XDR — uitgaande mail met betaalgerelateerde onderwerpen vanuit een
// account waarvoor in dezelfde periode een alert openstaat.
let lookback = 7d;
let verdachte_accounts = AlertEvidence
    | where Timestamp > ago(lookback)
    | where EntityType =~ "User"
    | where isnotempty(AccountUpn)
    | distinct AccountUpn;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection in ("Outbound", "Intra-org")
| where SenderFromAddress in~ (verdachte_accounts)
| where Subject has_any ("factuur", "invoice", "betaling", "payment", "iban",
                         "rekeningnummer", "bank details", "remittance",
                         "spoedbetaling", "urgent payment")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject,
          RecipientDomain, DeliveryAction, ThreatTypes, NetworkMessageId
| order by Timestamp desc
```

## Wat je hier niet moet bouwen

Drie dingen die er aantrekkelijk uitzien en die in de praktijk kosten zonder
opbrengst:

- **Een regex op IBAN-nummers in mailonderwerpen of -inhoud.** De inhoud van
  berichten staat niet in `EmailEvents`, en een DLP-regel op IBAN levert in een
  financiële afdeling vrijwel uitsluitend legitieme treffers.
- **Een drempel op "spoed"-woorden.** Onhaalbaar lage signaal-ruisverhouding, en
  triviaal te omzeilen door de aanvaller die de bestaande thread overneemt.
- **Een alert op de betaling zelf.** Die staat in het bankpakket of ERP-systeem.
  Wil je daar detectie op, dan hoort die daar thuis en niet in de M365-tenant.

## Waarom dit BEC is

Dit ís BEC — de rest van de kill chain bestaat om hier te komen. Het
NCSC/Cyclotron-advies formuleert het als de laatste vangrail: *"Zelfs als een
aanvaller via impersonatie (T1656) een technisch perfecte vervalste factuur
aanbiedt, kan een procedurele controle de transactie op het laatste moment
stoppen."* De maatregelen die het advies noemt zijn dan ook allemaal
niet-technisch: vier ogen op elke betaling, telefonische validatie van
bankwijzigingen en spoedbetalingen via een bekend en vertrouwd nummer, een
protocol waar ook voor de directie geen uitzondering op mogelijk is, en het
stimuleren dat de tweede goedkeurder vragen stelt.

De schaal waarop dit misgaat, uit de FBI IC3 Annual Report 2025:

| Jaar | BEC-meldingen | Gerapporteerde schade |
|---|---|---|
| 2025 | 24.768 | $3.046.598.558 |
| 2024 | 21.442 | $2.770.151.146 |
| 2023 | 21.489 | $2.946.830.270 |

De FBI definieert BEC daarbij expliciet als *"a scam targeting businesses or
individuals working with suppliers and/or businesses regularly performing wire
transfer payments"* — de doelgroep van maatregel 019, niet van een SIEM-regel.

## Referenties

- Microsoft, automatic attack disruption (incl. de BEC-incidenttitel): https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption
- Microsoft, attack disruption configureren (licenties, vereiste mailbox-audit-events, MDCA-connector): https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption
- Microsoft, alert policies: https://learn.microsoft.com/en-us/defender-xdr/alert-policies
- Microsoft, AlertInfo-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table
- Microsoft, AlertEvidence-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table
- Microsoft, EmailEvents-schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table
- Microsoft, SecurityAlert-schema (Sentinel): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityalert
- Microsoft, OfficeActivity-schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- FBI IC3 Annual Report 2025: https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf
- MITRE ATT&CK T1657: https://attack.mitre.org/techniques/T1657/
</content>
</invoke>
