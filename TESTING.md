# Teststatus

Elke query heeft één van deze statussen:

| Status | Betekenis |
|---|---|
| `ongetest` | Gebouwd op gedocumenteerde tabel- en kolomnamen, niet uitgevoerd. |
| `syntax-ok` | Uitgevoerd in een omgeving zonder relevante data: query draait, geen resultaten. |
| `bevestigd` | Uitgevoerd tegen echte data en de verwachte events kwamen terug. |

Doel vóór publicatie: elke query minimaal `syntax-ok`, en de queries bij de
maatregelen met prioriteit Hoog op `bevestigd`.

| Techniek | Sentinel-query | XDR-query | Getest tegen | Datum |
|---|---|---|---|---|
| T1114.003 | ongetest | ongetest | — | — |
