# Metadata bij de queryblokken

Elk KQL-blok in `docs/nl/` en `docs/en/` heeft direct erboven een HTML-comment
met machine-leesbare metadata. Die is onzichtbaar op de site en dient om de
queries automatisch te kunnen verwerken: een ARM-template genereren voor een
"Deploy to Azure"-knop, of ze in bulk uitvoeren voor een testronde.

## Formaat

```
<!-- query
platform: sentinel
name: Inbox rule with a forward or redirect action
technique: T1114.003
severity: Medium
tactics: [Collection]
interval: PT1H
lookback: P7D
parameters: [ownDomains]
deployable: true
-->
```

De comment staat **identiek in beide taalversies**. Ook `name` is Engels: het
wordt de naam van de regel in de Azure-portal, en die is niet vertaald.

## Velden

| Veld | Waarden | Toelichting |
|---|---|---|
| `platform` | `sentinel` \| `defender-xdr` | Bepaalt waar de query thuishoort. Alleen `sentinel` kan een scheduled analytics rule worden. |
| `name` | vrije tekst, Engels | Wordt de regelnaam. Beschrijf het gedrag, niet de techniek: "Inbox rule with a forward or redirect action", niet "T1114.003 detection". |
| `technique` | `T####[.###]` | De ATT&CK-techniek van het bestand waarin het blok staat. |
| `severity` | `Informational` \| `Low` \| `Medium` \| `High` | Wat de regel zou moeten hebben — niet wat Microsoft eraan geeft. Dat is het hele punt van deze repo. |
| `tactics` | lijst | Sentinel-tactieknamen (`Collection`, `Persistence`, `CredentialAccess`, `DefenseEvasion`, `InitialAccess`, `PrivilegeEscalation`, `Discovery`, `LateralMovement`, `Exfiltration`, `Impact`, `Execution`, `Reconnaissance`, `ResourceDevelopment`). |
| `interval` | ISO 8601 duration | Hoe vaak de regel draait, bijvoorbeeld `PT1H` of `P1D`. Kies iets dat past bij de latency van de databron; auditlogs zijn niet realtime. |
| `lookback` | ISO 8601 duration | Het venster waarover de query kijkt. Moet minstens gelijk zijn aan `interval`, meestal ruimer. |
| `parameters` | lijst of `[]` | Namen van `let`-variabelen die de gebruiker moet invullen vóór gebruik, zoals `ownDomains`. Worden parameters in een ARM-template. |
| `deployable` | `true` \| `false` | `false` voor verkennende of diagnostische queries die geen alertregel horen te worden: inventarisaties, "vuurt het alert eigenlijk?"-checks, en alles op `defender-xdr`. |

## Waarom `deployable` bestaat

Niet elke query in deze repo is een detectieregel. Sommige zijn bedoeld om
eenmalig te kijken hoe iets er in jouw tenant uitziet, of om vast te stellen of
een Microsoft-alert überhaupt afgaat. Die als scheduled rule activeren levert
ruis op — precies waar deze repo tegen waarschuwt.
