# Detectie bij het NCSC/Cyclotron BEC-advies

Detectie-logica bij de 19 maatregelen uit **"Business E-mail Compromise
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
dat ook. Zie [overzicht](overzicht.md).

## Welke detectie moet je kiezen?

Elk detectiebestand opent met een **Aanbeveling** met één van deze labels. De
vuistregel: *dekt Defender de handeling volledig zonder E5, dan Defender; zo
niet, dan een eigen Sentinel-rule.*

| Label | Wanneer | Wat je doet |
|---|---|---|
| `DEFENDER-ALERT` | Er is een standaard alert policy, hij dekt de handeling volledig, en hij zit in E1/E3 zonder add-on. | Alert aanzetten, severity zo nodig ophogen, doorzetten naar de plek waar iemand kijkt. |
| `SENTINEL-RULE` | Er is geen alert, of het alert dekt de handeling maar gedeeltelijk, of het vereist E5 / een add-on-licentie. | Eigen analytic rule op de KQL in dit bestand. |
| `DEFENDER-ALERT + SENTINEL-RULE` | Het alert is nuttig als vangnet, maar laat een gat dat er in de praktijk toe doet. | Beide: alert aan, KQL voor het gat. |

Twee dingen tellen mee in "volledig": dekt het alert álle manieren waarop de
handeling wordt uitgevoerd (bijvoorbeeld ook vanuit de desktopclient), en is de
standaard-severity zo dat er iemand naar kijkt. Een `Informational` alert dat
in een dashboard verdwijnt is geen detectie.

### Kun je de severity van een ingebouwde policy ophogen?

Daarover is Microsofts eigen documentatie tegenstrijdig, en dat is relevant
genoeg om hier vast te leggen. Op dezelfde pagina staat:

> "On the Alert policies page, the names of these built-in policies are in bold
> and the policy type is defined as **System**. These policies are turned on by
> default. You can turn off these policies (or back on again), set up a list of
> recipients to send email notifications to, and set a daily notification limit.
> **The other settings for these policies can't be edited.**"

En verderop, zonder onderscheid tussen System- en zelfgemaakte policies, een
instructie *"Change the severity level for an alert policy"* die je via **Edit**
in het Defender-portaal naar het severity-dropdownmenu leidt.

Ga in deze repo uit van de eerste passage: neem aan dat de severity van een
**System**-policy niet aanpasbaar is, en behandel een te lage severity dus als
een reden om alsnog een eigen detectie te bouwen. De betrouwbare route naar een
eigen severity is een eigen policy via `New-ProtectionAlert -Severity High`;
`Set-ProtectionAlert` werkt volgens Microsoft niet op default policies.
Wie dit in zijn eigen tenant anders ziet werken: dat horen we graag, dan passen
we het aan.

Bron: https://learn.microsoft.com/en-us/defender-xdr/alert-policies

## Wat de inventarisatie oplevert

Voor **geen enkele** van de 27 technieken uit het advies is een Defender-alert
alleen toereikend. Bij negen technieken is er een bruikbaar alert dat je moet
aanzetten, maar laat het een gat dat er in de praktijk toe doet: het dekt niet
alle uitvoeringswijzen, of het vereist een E5- of add-on-licentie die het mkb —
de doelgroep van dit advies — niet heeft. Bij de overige achttien is er niets om
op te leunen. Zie [overzicht](overzicht.md).

## Structuur

```
detections/<TECHNIEK-ID>-<naam>.md    één bestand per ATT&CK-techniek
overzicht.md                          alle technieken in één tabel
teststatus.md                         teststatus per query
```

Elk detectiebestand heeft dezelfde opbouw: metadata, "Is er een Defender-alert
voor?", benodigde databron, KQL per platform, waarom het BEC is, referenties.

## Status van de queries

**De queries in deze repo zijn niet uitgevoerd tegen een productie-tenant.** Ze
zijn gebouwd op tabel- en kolomnamen uit de Microsoft-documentatie en op
gepubliceerde hunting-queries. Per query staat in [teststatus](teststatus.md) of
hij is getest en waartegen. Neem niets over in productie zonder het zelf te
draaien.

## Verantwoording

Severities en policynamen komen uit Microsoft Learn en zijn gedateerd, omdat
Microsoft ze wijzigt: in juni 2025 zijn bijvoorbeeld verschillende Defender for
Cloud Apps-anomaliepolicies uitgezet die in veel detectie-inventarissen nog als
dekking staan. Waar een severity niet publiek gedocumenteerd is, staat dat er
zo bij — er wordt niet gegokt.

## Bijdragen

Verbeteringen zijn welkom, en het meest bruikbaar is een teststatus van iemand
die een query in een echte tenant heeft gedraaid. Zie
[bijdragen](bijdragen.md).

## Licentie

[MIT](https://github.com/zolderio/m365-bec-detections/blob/main/LICENSE). Vrij te gebruiken, aan te passen en commercieel in te zetten,
mits de copyrightvermelding meegaat.
