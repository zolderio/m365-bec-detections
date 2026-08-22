# Bijdragen

Verbeteringen zijn welkom, en er is één soort bijdrage die we het meest kunnen
gebruiken: **iemand die een query in een echte tenant heeft gedraaid.**

## Wat we graag ontvangen

- **Een teststatus.** Heb je een query uitgevoerd, meld dan of hij draaide en of
  de verwachte events terugkwamen. Werk de regel in [TESTING.md](TESTING.md)
  bij, met de datum en waartegen je hebt getest.
- **Correcties op feiten.** Een alertnaam die niet meer bestaat, een severity die
  Microsoft heeft gewijzigd, een tabel of kolom die anders heet. Voeg de bron
  toe waaruit dat blijkt; we nemen niets over zonder verwijzing.
- **Een betere query.** Minder valse positieven, of dekking van een
  uitvoeringswijze die we missen. Leg in de pull request uit welk geval de
  huidige query mist.
- **Een ontbrekende techniek.** Het advies telt 27 technieken; ziet iemand een
  BEC-relevante handeling die er niet in staat, dan horen we dat graag.

## Werkwijze

1. Open een issue of stuur direct een pull request.
2. Houd het formaat van de bestaande bestanden aan: metadata, aanbeveling met
   label, benodigde databron, KQL per platform, waarom het BEC is, referenties.
3. Onderbouw met een bron. Kun je iets niet verifiëren, schrijf dan "niet
   publiek gedocumenteerd" in plaats van een aanname. Dat is hier geen zwakte
   maar het uitgangspunt.
4. Verzin nooit een alertnaam, severity, tabelnaam of kolomnaam.

## Licentie van bijdragen

Wat je bijdraagt valt onder dezelfde [MIT-licentie](LICENSE) als de rest van de
repo.
