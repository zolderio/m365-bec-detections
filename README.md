# Detectie bij het NCSC/Cyclotron BEC-advies

Werkende detectie-logica bij de 19 maatregelen uit **"Business E-mail Compromise
(BEC) — Technisch advies"** (NCSC, Cyclotron, april 2026). Per MITRE
ATT&CK-techniek uit dat advies staat hier:

- of Microsoft er een **standaard alert** voor levert — met de exacte
  policynaam, de standaard-severity en het benodigde licentieniveau;
- en zo niet (of als de alert te laag of te smal is): **KQL** voor Microsoft
  Sentinel en voor Defender XDR advanced hunting, met de tabel en de data
  connector die daarvoor onboard moet zijn.

Het advies zelf beschrijft *welke* maatregel je moet nemen. Deze repo beschrijft
hoe je ziet dat het misgaat.

## Waarom dit nodig is

Van de technieken in het advies levert een aanzienlijk deel geen alert op, of
een alert op het laagste niveau. Twee voorbeelden uit Microsofts eigen
documentatie: het aanmaken van een doorstuurregel is `Informational`, en het
starten of exporteren van een eDiscovery-zoekopdracht over alle mailboxen is
dat ook. Zie [SEVERITY-OVERZICHT.md](SEVERITY-OVERZICHT.md).

## Structuur

```
detections/<TECHNIEK-ID>-<naam>.md    één bestand per ATT&CK-techniek
SEVERITY-OVERZICHT.md                 alle technieken in één tabel
TESTING.md                            teststatus per query
```

Elk detectiebestand heeft dezelfde opbouw: metadata, "Is er een Defender-alert
voor?", benodigde databron, KQL per platform, waarom het BEC is, referenties.

## Status van de queries

**De queries in deze repo zijn niet uitgevoerd tegen een productie-tenant.** Ze
zijn gebouwd op tabel- en kolomnamen uit de Microsoft-documentatie en op
gepubliceerde hunting-queries. Per query staat in [TESTING.md](TESTING.md) of
hij is getest en waartegen. Neem niets over in productie zonder het zelf te
draaien.

## Verantwoording

Severities en policynamen komen uit Microsoft Learn en zijn gedateerd, omdat
Microsoft ze wijzigt: in juni 2025 zijn bijvoorbeeld verschillende Defender for
Cloud Apps-anomaliepolicies uitgezet die in veel detectie-inventarissen nog als
dekking staan. Waar een severity niet publiek gedocumenteerd is, staat dat er
zo bij — er wordt niet gegokt.

## Licentie

<!-- TODO Erik: licentiekeuze, MIT ligt voor de hand -->
