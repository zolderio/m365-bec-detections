# Teststatus

Elke query heeft één van deze statussen:

| Status | Betekenis |
|---|---|
| `ongetest` | Gebouwd op gedocumenteerde tabel- en kolomnamen, niet uitgevoerd. |
| `syntax-ok` | Uitgevoerd in een omgeving zonder relevante data: query draait, geen resultaten. |
| `bevestigd` | Uitgevoerd tegen echte data en de verwachte events kwamen terug. |

Doel vóór publicatie: elke query minimaal `syntax-ok`, en de queries bij de
maatregelen met prioriteit Hoog op `bevestigd`.

De repo telt **122 queryblokken**. Elk blok heeft machine-leesbare metadata —
zie [QUERY-METADATA](https://github.com/zolderio/m365-bec-detections/blob/main/QUERY-METADATA.md).
Daarvan zijn er **56 gemarkeerd als `deployable`**: zelfstandige queries die als
scheduled analytics rule zinvol zijn. De overige 66 zijn advanced-hunting-queries,
losse filterfragmenten of eenmalige inventarisaties, en horen niet als regel in
een tenant.

| Techniek | Sentinel-query | XDR-query | Getest tegen | Datum |
|---|---|---|---|---|
| T1059 | ongetest | ongetest | — | — |
| T1068 | ongetest | ongetest | — | — |
| T1078 | ongetest | ongetest | — | — |
| T1078.004 | ongetest | ongetest | — | — |
| T1098.001 | ongetest | ongetest | — | — |
| T1110.003 | ongetest | ongetest | — | — |
| T1114.002 | ongetest | ongetest | — | — |
| T1114.003 | ongetest | ongetest | — | — |
| T1204 | ongetest | ongetest | — | — |
| T1530 | ongetest | ongetest | — | — |
| T1534 | ongetest | ongetest | — | — |
| T1537 | ongetest | ongetest | — | — |
| T1538 | ongetest | ongetest | — | — |
| T1539 | ongetest | ongetest | — | — |
| T1556.006 | ongetest | ongetest | — | — |
| T1557 | ongetest | ongetest | — | — |
| T1562.001 | ongetest | ongetest | — | — |
| T1564.008 | ongetest | ongetest | — | — |
| T1566.002 | ongetest | ongetest | — | — |
| T1566.003 | ongetest | ongetest | — | — |
| T1567 | ongetest | ongetest | — | — |
| T1598 | ongetest | ongetest | — | — |
| T1621 | ongetest | ongetest | — | — |
| T1656 | ongetest | ongetest | — | — |
| T1657 | ongetest | ongetest | — | — |
| T1671 | ongetest | ongetest | — | — |
| T1672 | ongetest | ongetest | — | — |
