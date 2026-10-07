# BEC-detecties voor Microsoft 365

[English](README.md) · **Nederlands**

Detectie-logica bij de 19 maatregelen uit **"Business E-mail Compromise (BEC) —
Technisch advies"** (NCSC, Cyclotron, april 2026). Per MITRE ATT&CK-techniek uit
dat advies: levert Microsoft er een standaard alert voor, en zo niet, welke KQL
en welke databron heb je nodig.

**Documentatiesite:** `docs/nl/` (Nederlands) en `docs/en/` (English).
Begin bij [het overzicht](docs/nl/overzicht.md) — alle 27 technieken in één
tabel, met per techniek de aanbevolen detectie.

## Kernbevinding

Voor **geen enkele** van de 27 technieken is een Defender-alert alleen
toereikend. Bij negen is er een bruikbaar alert dat je moet aanzetten, maar laat
het een gat dat er in de praktijk toe doet: het dekt niet alle uitvoeringswijzen,
of het vereist een E5- of add-on-licentie die het mkb — de doelgroep van dit
advies — niet heeft. Bij de overige achttien is er niets om op te leunen.

## Status van de queries

De queries zijn **niet uitgevoerd tegen een productie-tenant**. Ze zijn gebouwd
op tabel- en kolomnamen uit de Microsoft-documentatie en op gepubliceerde
hunting-queries. Zie [de teststatus](docs/nl/teststatus.md) per techniek. Neem
niets over in productie zonder het zelf te draaien.

## Bijdragen

Welkom, en het meest bruikbaar is een teststatus van iemand die een query écht
heeft gedraaid. Zie [CONTRIBUTING](docs/nl/bijdragen.md).

## De site lokaal bouwen

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r requirements.txt
.venv-docs/bin/mkdocs serve
```

## Licentie

[MIT](LICENSE). Vrij te gebruiken, aan te passen en commercieel in te zetten,
mits de copyrightvermelding meegaat.
