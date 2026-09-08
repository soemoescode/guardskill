# GUARDSKILL — ACCEPTATIEPOORT v0.4.0

### Onafhankelijke Security & Code Quality Reviewer · vastgesteld 8 september 2026
### Scope-besluit van Sam: alle 17 bevindingen van review 01 dicht, detectie blijft op git-niveau

---

## 0. WAT DIT DOCUMENT IS

Dit is de definitie van klaar voor de versie die gepubliceerd mag worden. Geen aanbevelingen — **toetsbare voorwaarden**. Elke voorwaarde is óf machinaal te controleren, óf te verifiëren tegen een met naam genoemd artefact. Een voorwaarde die ik niet kan nalopen zonder de bouwer te vertrouwen, hoort hier niet in en staat er dus niet in.

**Werkwijze.**

1. De Operator levert de dispositietabel (per bevinding-ID: nu fixen / volgende versie / restrisico met reden) en tagt de staat waarop die tabel slaat.
2. De Operator bouwt tegen deze poort.
3. Wanneer alle poorten dicht zijn, tagt de Operator `v0.4.0-rc1` en meldt dat.
4. Ik draai ronde 2 tegen die tag — het protocol in §8 staat hier zodat de Operator het zelf vooraf kan draaien en er geen verrassingen zijn.
5. Publiceren blijft een handeling van Sam, en gebeurt pas na een groene ronde 2.

**Twee harde faalregels, over alle poorten heen:**

- **Een test die op ubuntu wordt geskipt, is een gate-fail.** Skips zijn alleen toegestaan op windows/macos, met een zichtbare `t.skip()`-reden. `return` in plaats van `t.skip()` is een fail — dat is F-16, en die faalmodus is in deze sessie twee keer voorgekomen.
- **Een claim zonder test is een gate-fail.** Elke bewering in README, SECURITY.md, SKILL.md en CHANGELOG die over gedrag gaat, verwijst naar de testnaam die hem bewijst (§5). Geen test → claim eruit.

---

## 1. POORT A — DE NEGEN BEWEZEN AANVALLEN

Elke regel: de bevinding is dicht wanneer de genoemde test slaagt **en** de negatieve tegenhanger nog steeds slaagt. Zonder die tegenhanger is een fix een nieuwe valse positief.

| ID | Voorwaarde | Positieve test | Negatieve tegenhanger |
|---|---|---|---|
| F-01 | `include.path` en `includeIf.*.path` worden gevolgd binnen de boom; bevindingen uit het geïncludeerde bestand krijgen hun eigen severity; de include-keten staat in `location` | `F-01` (fsmonitor via include → critical, CLI exit 1) | een include naar een bestand met alleen `[user] email` levert niets boven medium |
| F-01b | Een include die naar buiten de boom of naar een onleesbaar pad wijst → **high** plus status `INCOMPLETE`, nooit medium | `F-01b` | een include naar een eigen `~/.gitconfig`-achtig pad blijft één finding, geen findingregen |
| F-02 | `git` staat niet meer in `safeCommandPrefixes`; elke `git`-invocatie met `-c`, `--config-env`, `--exec-path`, `-p` of `--paginate` in een filter/textconv/driver → high of critical | `F-02` (5 sleutels geparametriseerd) | `F-02b` — de echte git-lfs-waarden blijven stil |
| F-03 | `pager.<cmd>`, `gpg.program` / `gpg.<fmt>.program`, `remote.<n>.uploadPack` / `receivePack`, `core.askPass`, `core.alternateRefsCommand`, `trailer.<t>.command` gedekt; `init.templateDir` minimaal medium | `F-03` (7 gevallen, `missed` moet leeg zijn) | `pager.log = less`, `gpg.program = gpg2`, `remote.origin.uploadPack = git-upload-pack` blijven stil |
| F-04 | Een alias die begint met `-c`, `--config-env`, `--exec-path`, `-p`, `--paginate` of `-C` → high, náást de bestaande bang-regel | `F-04` | `alias.lg = log --oneline --graph` blijft stil (zit al in `F-04`) |
| F-05 | Hookscripts worden meegenomen als ze een symlink zijn; een hook-symlink naar buiten de boom → critical met de tekst dat het doel niet is geïnspecteerd, en het doel wordt **niet** gelezen | `F-05` | een symlink naar een husky-script binnen de boom blijft informatief |
| F-06 | Zie §2.1 — apart uitgewerkt, want dit is een gedragswijziging | `F-06` | een gewone `.git` in een schone repo levert niets nieuws op |
| F-07 | Vier eindstatussen in tekst, JSON (`status`) én exitcode; CLI-standaarddiepte gelijk aan de bibliotheek én aan de helptekst | `F-07a`, `F-07b`, `F-07c` | een schone repo geeft nog steeds exit 0 en `status: "CLEAN"` |
| F-08 | Geen `process.exit()` op enig pad dat naar stdout heeft geschreven; `process.exitCode` zetten en normaal eindigen | `F-08`, verzwaard (§3.4) | — |
| F-09 | Configbestanden bereikt via een symlink worden geweigerd en gerapporteerd (high plus `INCOMPLETE`), niet gelezen. Geldt voor `config`, `config.worktree`, `worktrees/*/config.worktree`, `modules/**/config`, `.gitmodules` en het `.git`-bestand | `F-09` (inhoud van buiten de boom mag in geen enkel uitvoerkanaal voorkomen) | een repo zonder symlinks levert geen extra findings |
| F-10 | Zie §2.2 — apart uitgewerkt, want hier zit de botsing met test 22 | `F-10a`–`F-10d` | test 22 blijft groen zonder afzwakking |
| F-11 | `location`, `title` en `explanation` gaan door `sanitise()` in beide formatters; de ruwe waarde bestaat alleen in de JSON-uitvoer, met escape-tekens geëscaped | `F-11`, uitgebreid met een vijandige **subsectienaam** naast de mapnaam | een gewone mapnaam met een spatie of een accent wordt niet verminkt |
| F-12 | `loadRules()` valideert: verplichte velden, severity uit de vier toegestane waarden, bekende `matchType`, elk pattern compileerbaar. Faalt met `ERROR` (exit 2) die het regel-id noemt. Regexes worden één keer gecompileerd | `F-12` | de meegeleverde `rules/git-exec-keys.json` doorstaat de validatie |
| F-13 | Geen placeholder in `package.json`; `homepage`, `repository.url`, `bugs.url` wijzen naar `soemoescode/guardskill` | `F-13` | — |

**Toegevoegde voorwaarde bij F-03.** De zeven sleutels zijn wat ík heb gevonden. De poort eist niet dat de lijst volledig is, maar dat de *volledigheid controleerbaar* is: zie §3.1.

---

## 2. DE TWEE GEDRAGSWIJZIGINGEN, EXPLICIET

### 2.1 F-06 — case-ongevoelige matching zonder schrijfactie

De Operator wijst er terecht op dat de gangbare probe een bestand schrijft en daarmee de lees-alleen-garantie sloopt. Hun inode-variant lost dat op, maar hangt aan `stat().ino`, en dat is juist op Windows het minst betrouwbare veld — een probe die daar niet kan beslissen en dan "case-sensitief" concludeert, is een fail-open op precies het platform waar de bevinding vandaan komt.

**Voorwaarde: de probe gebruikt geen inode en geen schrijfactie.**

1. Neem een naam die `readdir` op de gescande root heeft opgeleverd en die minstens één letter bevat.
2. Draai de casing van die naam om. Staat de omgedraaide variant zélf in de `readdir`-lijst, pak dan een volgende kandidaat.
3. `stat` de omgedraaide variant. Slaagt hij → **case-ongevoelig**. Faalt hij met `ENOENT` → **case-sensitief**.
4. Geen enkele kandidaat beslisbaar → **neem case-ongevoelig aan.** Dat is de veilige kant: het levert méér meldingen, nooit minder.

**Voorwaarde: de melding is platformeerlijk.** Op een case-ongevoelig volume is `.GIT/config` gelijk aan `.git/config` en erft de bevinding de gewone severity. Op een case-sensitief volume is een map die `.GIT` heet géén git-directory voor git daar, en luidt de bevinding **medium**: "deze map is op dit bestandssysteem geen git-directory, maar wel op Windows en macOS — als deze boom is aangeleverd of wordt gedeeld, wordt hij daar wel toegepast." Dezelfde normalisatie geldt voor het `.git`-bestand en voor `.gitmodules`, en trailing spaces en punten worden getrimd (Windows negeert die in padnamen).

**Voorwaarde: dit staat in de documentatie**, niet alleen in de code — README onder "What it checks", en in `SECURITY.md` bij de traversal-eigenschappen.

**Tests:** `F-06`; plus één test die de probe zelf toetst op de repo-eigen boom, en één die de medium-variant afdwingt op een case-sensitief volume. De probe-test mag op geen enkel platform geskipt worden.

### 2.2 F-10 — escalatie in plaats van een nieuw vast niveau

De platte downgrade botst met test 22, en de goedkope weg naar groen zou de CVE-detectie stiller maken. De poort dwingt de grens in twee richtingen af:

| Situatie | Severity | Test |
|---|---|---|
| Bare repo of ongeregistreerde geneste `.git` **met** een uitvoerende sleutel in zijn eigen config | **critical** | test 22 (bestaand, ongewijzigd) |
| Bare repo of ongeregistreerde geneste `.git` **zonder** uitvoerende sleutel | **medium** | `F-10a` |
| Filter/textconv/driver die een kaal, via PATH oplosbaar commando is zonder shell-metateken en zonder pad | **low of medium** | `F-10b` |
| Zelfde sleutel met een pad, een metateken, `/tmp`, of een download | **high of critical** | bestaande vulnerable fixtures |
| Submodule geregistreerd in de `.gitmodules` van het subproject dat hem bezit | **geen finding** | `F-10c` |
| Toegestane credential helper met argumenten die de opslag verleggen (`store --file=...`) | **high** | `F-10d` |

**Voorwaarde: de escalatie is één functie**, niet per regel gedupliceerd, en de fixtureset bevat vanaf nu ook: git-lfs-achtige ingecheckte `*.git`-fixtures, sops, nbstripout, `clean = cat`, en een geneste `.gitmodules`.

**Voorwaarde: test 22 wordt niet aangepast.** Verandert die assertie toch, dan is dat een besluit met een opgeschreven reden in de dispositietabel — geen commit-boodschap.

---

## 3. POORT B — TESTINFRASTRUCTUUR

Dit is het deel dat in het plan van de Operator ontbrak, en het is het deel dat bepaalt of er een ronde 3 nodig is.

### 3.1 Dekkingstest tegen een ingecheckte sleutellijst

`rules/git-exec-keys-inventory.md` (nieuw) somt elke git-configuratiesleutel op die een commando kan uitvoeren, met per sleutel: de bron (`git-config`-documentatie, sectieverwijzing), de git-versie waartegen is gecontroleerd, en de status — `covered` (met regel-id) of `out-of-scope` (met reden). Een test faalt wanneer een sleutel in de inventaris `covered` heet zonder dat er een regel met dat id bestaat, of wanneer er een regel bestaat die niet in de inventaris staat. Zo wordt een gat zichtbaar in plaats van vergeten, en is F-03 niet "de zeven die de reviewer vond" maar een gecontroleerde lijst.

### 3.2 Gouden tabel voor de parser

`test/fixtures/gitconfig-golden.json`: per casus de ruwe configtekst en de uitvoer van `git config --file X --list`, **één keer offline gegenereerd** en ingecheckt, met in de kop van het bestand de git-versie, de datum en het genereercommando. De suite vergelijkt de parser daartegen. Geen `child_process` in `src/` en geen git-aanroep in de test.

**Grens die de Operator zelf aandroeg, en die de poort overneemt:** `git config --file` weigert een malformed config, dus de robuustheidscases hebben geen orakel. De kop van het bestand benoemt dat expliciet: de tabel dekt de configs die git accepteert; voor de rest is "wij vallen naar de veilige kant" een bewering die met eigen tests wordt onderbouwd, niet met git.

Minimaal 23 gevallen (de differentiële set uit review 01), waarvan de bekende afwijkingen — gedeeltelijke quoting, `\t`- en `\n`-escapes, `#` of `;` zonder voorafgaande witruimte, CRLF-continuatie — óf gelijkgetrokken zijn met git, óf per stuk als bewuste afwijking gedocumenteerd staan met de reden dat ze naar de veilige kant vallen.

### 3.3 Echte-wereld-corpustest

Drie tot vijf publieke repositories, **vastgezet op commit-SHA**. Niet klonen in de test: de relevante bestanden (configs, `.gitmodules`, hooks, ingecheckte `*.git`-fixtures) worden gereduceerd meegeleverd als fixture, met per repository de herkomst, de SHA, de licentie en de verwachte uitkomst in een `PROVENANCE.md`. Verplicht in de set: `git-lfs/git-lfs` (leverde 8 criticals in review 01), plus minimaal één husky-project, één monorepo met submodules en één data-science-repo met notebook-filters.

**Voorwaarde: de test draait offline en wordt nergens geskipt.** Een corpustest die stil overslaat als het netwerk ontbreekt, is F-16 in een nieuwe jas.

**Acceptatiecriterium:** geen enkele repository in de set levert een `critical`, en geen enkele levert een `high` die niet in `PROVENANCE.md` als verwacht en verklaard staat.

### 3.4 Verzwaarde F-08-test

De regressietest schrijft naar stdout via een pipe, met een uitvoer boven 1 MB, en assert dat `JSON.parse` slaagt én dat de lengte overeenkomt met dezelfde scan naar een bestand. Hij draait in de CI-matrix op ubuntu en macos (waar de bug zich manifesteert) en op windows (waar hij zich niet manifesteert) — dat verschil is precies de reden dat één machine geen bewijs is. Aanvullend een statische controle: `process.exit(` komt niet voor op een pad dat naar stdout heeft geschreven.

### 3.5 Prestatiebudget

De gemeten baseline uit review 01 wordt een grens: 8.721 directories binnen 2 seconden, geheugen onder 200 MB, afgedwongen op de bestaande brede-boomfixture. Meten, niet aannemen — en een fix die de scan tien keer langzamer maakt, is geen fix.

---

## 4. POORT C — HET CONTRACT

Vanaf deze versie is de uitvoer iets waar anderen op bouwen (CI, de MSP-white-label, de latere gehoste laag). Het contract wordt hier vastgelegd en getest.

**Exitcodes.** `0` = CLEAN · `1` = FINDINGS op of boven `--fail-on` · `2` = ERROR (pad bestaat niet, geen leesrechten, ongeldige rules, ongeldige argumenten) · `3` = INCOMPLETE (afgekapte walk, geweigerde symlink, niet-gevolgde include). `INCOMPLETE` faalt altijd, tenzij `--allow-incomplete` wordt meegegeven; `--fail-on` gaat alleen over severity, nooit over volledigheid. Eén test per code, via `spawn` op `src/cli.js`.

**JSON.** Verplichte velden: `tool`, `version`, `schemaVersion` (nieuw, begint op `1`), `path`, `status` (`CLEAN` / `FINDINGS` / `INCOMPLETE` / `ERROR`), `scanned`, `reason`, `targetCount`, `dirsVisited`, `truncated`, `incompleteReasons` (nieuw, array), `summary`, `findings`. Per finding: `ruleId`, `severity`, `title`, `explanation`, `remediation`, `location`, `evidence`. Een test valideert de vorm van de uitvoer tegen dit schema, op fixtures die alle vier de statussen opleveren.

**CLI.** `--max-depth` standaard gelijk aan de bibliotheek (24) én aan de helptekst; een test vergelijkt de helptekst met de daadwerkelijke default. Onbekende opties en een tweede positioneel argument geven `ERROR` in plaats van stil de laatste te nemen.

**Waarom 0.4.0 en niet 1.0.0.** De confidence-as komt later en verandert dan de vorm van `findings`. Een `1.0.0` publiceren en het schema daarna omgooien is precies het soort belofte dat je niet terugdraait. `schemaVersion: 1` legt nu vast waar consumers op mogen bouwen; `1.0.0` is voor de versie waarin dat schema bevroren is.

---

## 5. POORT D — CLAIMS-PARITEIT

`SECURITY.md` krijgt onderaan een tabel: **claim → testnaam**. Elke gedragsbewering in README, SECURITY.md, SKILL.md en de landingspagina staat erin, of verdwijnt uit de tekst. Concreet af te rekenen met de zes claims uit F-15:

- "It does not modify anything, ever." → wordt: het project dat wordt geïnspecteerd wordt nooit gewijzigd; het enige bestand dat wordt geschreven is het rapport dat je met `--out` vraagt. Zelfde formulering in de helptekst.
- "It does not follow symlinks." → wordt: de directory-walk volgt geen symlinks, en configbestanden die via een symlink worden bereikt, worden geweigerd en gerapporteerd. Test: `F-09`.
- "An incomplete walk never reads as a clean result." → mag blijven staan zodra exitcode én JSON-status dat waarmaken. Test: `F-07b`.
- "The default traversal depth is 24." → mag pas terug in de CHANGELOG als de CLI dat ook doet. Test: `F-07a`.
- "29 realistische schone repositories" → wordt: het genoemde aantal fixtures plús de corpustest, met de corpus benoemd. Test: §3.3.
- **"Dekt de GitSpawn-klasse en CVE-2026-45033"** → dit is de belangrijkste. Zolang de inventaris uit §3.1 sleutels op `out-of-scope` heeft staan, somt de scope-tekst op wat het nakijkt in plaats van een klasse te claimen. Gat dichten of claim verkleinen; het gat laten staan met de brede claim erboven is het enige dat niet terug te draaien is.

Aanvullend: `SECURITY.md` benoemt de restrisico's die de dispositietabel als geaccepteerd markeert. Een geaccepteerd restrisico dat niet in de publieke documentatie staat, is een gate-fail — dan is het geen accepteren maar verzwijgen.

---

## 6. POORT E — RELEASE-MECHANIEK

- **CI groen op de volle matrix**: ubuntu, macos, windows × Node 18, 20, 22. Nul geskipte tests op ubuntu.
- **Actions vastgezet op commit-SHA** (`actions/checkout`, `actions/setup-node`), met de tag als comment erachter.
- **Aparte `release.yml`** die alleen op een tag draait, `npm publish --provenance` doet via OIDC, en nooit door `pull_request` wordt getriggerd. De testworkflow houdt `permissions: contents: read` en krijgt geen secrets.
- **`package.json`** zonder placeholder, met kloppende `repository.url` — ook een voorwaarde voor provenance-verificatie.
- **CHANGELOG chronologisch**, met per bevinding-ID één regel die zegt wat er is veranderd, en zonder claims die de code niet waarmaakt.
- **Tag `v0.4.0-rc1`** op de staat die ter review wordt aangeboden. Geen review meer op een levende werkboom.
- **De publieke README mag geen installatieregel bevatten die faalt.** Zolang npm 404 geeft: de clone-variant in de README, of publiceren. Dit staat nu al fout op een publieke repository (F-14) en hoort niet te wachten tot de rest klaar is.
- **Zelfscan blijft in de CI** en moet exit 0 geven op de eigen repository met `--exclude test/fixtures` — inclusief de nieuwe corpusfixtures, dus die uitsluiting mogelijk uitbreiden. Een securitytool die op zijn eigen repository afgaat, is een slecht visitekaartje.

---

## 7. WAT EXPLICIET NIET IN DEZE VERSIE ZIT

Vastgelegd zodat het een besluit is en geen vergeetpunt:

1. **De confidence-as als apart veld** in JSON, CLI en rapport. Reden: raakt schema, vlaggen en alle tests tegelijk; de severity-herijking uit §2.2 haalt de schade weg zonder die operatie. Gaat naar v0.5.0. `schemaVersion: 1` maakt de latere toevoeging zichtbaar voor consumers.
2. **De volgende detectieklasse** — `.claude/settings.json`, `.vscode/tasks.json`, MCP-serverdefinities, npm-lifecycle-scripts. Reden: eigen onderzoekstraject met eigen bronnen en fixtures. Blijft in de README staan als "does not do this yet", en dat is een claim die dan ook waar blijft.
3. **Property-based generatie** bovenop de gouden tabel. De 23 vaste gevallen zijn de ondergrens voor deze versie; generatie is v0.5.0.

---

## 8. VERIFICATIEPROTOCOL RONDE 2

Wat ik draai tegen `v0.4.0-rc1`, in deze volgorde. De Operator kan dit vooraf zelf draaien; dan zijn er geen verrassingen.

1. `git fetch --tags && git checkout v0.4.0-rc1 && git status --porcelain` — leeg, anders stop ik.
2. Schone kopie buiten de repository, `npm test` — 27 bestaande plus 20 review-01-tests plus de nieuwe, alles groen, nul skips op ubuntu.
3. De negen bewezen aanvallen uit review 01 opnieuw, met echte git: include-payload, `git`-prefix in een filter, `pager.log`, `gpg.program`, `remote.uploadPack`, alias met `-c`, symlink-hook, `.GIT`-map, gesymlinkte config. Elk moet nu een finding **en** de juiste exitcode geven.
4. De drie valse positieven opnieuw: git-lfs vers gekloond, de sops/jupyter/`cat`-config, de geneste `.gitmodules`. Nul criticals, geen high buiten wat `PROVENANCE.md` verklaart.
5. Exitcode-matrix: CLEAN, FINDINGS, INCOMPLETE, ERROR — vier gevallen, vier codes.
6. `--json` door een pipe boven 1 MB, op Linux.
7. Nieuwe aanvalspoging: ik val v0.4.0 aan zoals ik v0.3.0 heb aangevallen. Ik weet niet vooraf wat ik zoek; dat is het punt. Verwacht minimaal één nieuwe bevinding — een wijziging die vijf gedragingen verandert, introduceert er statistisch iets bij.
8. Claims-pariteit: elke claim in de vier documenten tegen de tabel en tegen de testnaam.
9. Dispositietabel doorlopen: klopt elke "restrisico met reden", en staat elk geaccepteerd risico ook in de publieke documentatie?
10. `package.json`, CI-workflows, tag, CHANGELOG.

**Uitkomst van ronde 2** is per bevinding: `GESLOTEN` (fix plus test bevestigd), `GEDEELTELIJK` (fix werkt, test te zwak — F-08 in ronde 1 was dit), `OPEN`, of `GEACCEPTEERD RESTRISICO` (met de reden van de Operator, door mij getoetst). Publiceren mag bij nul `OPEN` en nul `GEDEELTELIJK`.

---

*Vastgesteld tegen commit `413be99` (v0.3.0) en de dispositie van review 01. Scope-besluit van Sam op 8 september 2026: alle 17 bevindingen dicht, detectie blijft op git-niveau, confidence-as en de volgende detectieklasse naar v0.5.0.*
