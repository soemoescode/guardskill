# GUARDSKILL — ONAFHANKELIJKE SECURITY & CODE QUALITY REVIEW

### Review 1 · v0.3.0 · commit `413be99` · 8 september 2026

---

## 1. REVIEWBASELINE

| | |
|---|---|
| Repository | `github.com/soemoescode/guardskill` (publiek, README live) |
| Branch / commit | `main` / `413be99` — werkboom schoon, `origin/main` identiek |
| Packageversie | 0.3.0 (`package.json`) |
| Reviewomgeving A | Windows-machine `hp-sam`, `C:\Users\Sam Prins\repos\guardskill`, Node 22.23.2, npm 10.9.8 |
| Reviewomgeving B | Linux-container, Node 22.22.2, **git 2.43.0** — hier zijn alle exploits uitgevoerd |
| Aanwezig | volledige broncode, 4 testbestanden, fixture-generator, rules-JSON, CI-workflow, README/SKILL/SECURITY/CHANGELOG/CONTRIBUTING, landingspagina |
| Ontbrekend | lockfile (geen dependencies — akkoord), linter/typecheck, release-workflow, npm-publicatie |
| npm-status | `registry.npmjs.org/guardskill` → **404**: het pakket bestaat niet |

**Procesblokkade tijdens deze review.** Tussen 19:55 en 19:58 wijzigde de werkboom twee keer onder mijn handen (0.2.0 → 0.3.0, `discovery.js` van 89 naar 152 regels). Ik heb daarom gepind op één snapshot en die naar de container gehaald; de bestandshashes van die snapshot zijn identiek aan `413be99`. **Aanbeveling: tag elke reviewbare staat (`git tag v0.3.0`) en review nooit een levende werkboom** — anders is geen enkele bevinding reproduceerbaar toe te wijzen.

### Reproductie van de geclaimde baseline

| Claim van de Operator | Uitkomst |
|---|---|
| 27 tests groen | **GEREPRODUCEERD** — 27/27 pass, in beide omgevingen, uit een schone kopie |
| Nul runtime-dependencies | **GEREPRODUCEERD** — geen `child_process`, `net`, `http`, `fetch` of URL in `src/` |
| Geen netwerk, geen telemetrie | **GEREPRODUCEERD** (statisch; geen egress mogelijk vanuit de code) |
| CVE-2026-45033: `@github/copilot` ≤1.0.42, gefixt in 1.0.43, CVSS 8.5, bare-repo-discovery + `core.fsmonitor` | **GEVERIFIEERD** tegen GitHub Advisory GHSA-9ccr-r5hg-74gf (primaire bron) — de README beschrijft de CVE correct |
| Testsuite draaibaar op de Windows-machine zelf | **NIET TESTBAAR** — `pretest` faalt daar met `EPERM: unlink` op de fixture-map (omgevingsbeperking van mijn sessie, geen productfout) |

Een groene suite bewijst hier precies wat hij bewijst: de 27 geschreven gevallen kloppen. Hieronder staan negen werkende aanvallen die de suite niet dekt, en drie legitieme situaties die hij onterecht afkeurt.

---

## 2. AANVALSOPPERVLAK (samengevat)

Invoer: een directoryboom die volledig door de aanvaller wordt bepaald (mapnamen, bestandsnamen, symlinks, configinhoud, hookscripts) plus CLI-argumenten van de gebruiker.
Leesoperaties: `readdir`, `stat`, `readFile` op `*/config`, `config.worktree`, `worktrees/*/config.worktree`, `modules/**/config`, `.gitmodules`, `hooks/*` (eerste 4096 bytes).
Schrijfoperaties: uitsluitend `--out <file>` (buiten de scan-logica).
Procesuitvoer: geen.
Trust boundaries: (a) configwaarde → rapport/terminal, (b) padnaam → rapport/terminal, (c) symlink → gelezen bestand, (d) rules-JSON → regex-compilatie en severity-logica, (e) exitcode → CI-beslissing.

Grenzen (a), (b), (c) en (e) lekken. Zie F-08, F-09, F-11, F-12.

---

## 3. BEVINDINGEN

### Finding 01: `include.path` wordt gemeld maar niet gevolgd — de primaire aanval passeert de standaard-CI
**Severity:** Critical · **Confidence:** High · **Categorie:** Security / False negative

Git lost `include.path` op en past de geïncludeerde configuratie toe. GuardSkill meldt de include zelf als **medium** en leest het doelbestand nooit. De standaarddrempel is `high` en de README's eigen CI-recept is `npx guardskill . --fail-on high` → **exitcode 0**.

Reproductie (volledig uitgevoerd, git 2.43.0):
```bash
git init repo && cd repo
mkdir notes
printf '[core]\n\tfsmonitor = /pad/payload.sh\n' > notes/build-flags.txt
printf '[include]\n\tpath = ../notes/build-flags.txt\n' >> .git/config
git config core.fsmonitor      # -> /pad/payload.sh   (git past het toe)
git status                     # -> payload UITGEVOERD (bewezen met een marker-bestand)
npx guardskill .               # -> 0 critical, 0 high, 1 medium; EXIT=0
```
De payload staat in een bestand dat op een gewoon tekstbestand in de werkboom lijkt. Dit is exact de GitSpawn/CVE-vector, en de scanner die daarvoor bestaat laat hem door.

**Fix:** volg `include.path` en `includeIf.*.path` recursief wanneer het doel binnen de gescande boom ligt (met een cyclusdetectie en een diepte-cap van bijv. 10) en rapporteer de bevindingen van het geïncludeerde bestand op hun eigen severity, met vermelding van de include-keten in `location`. Wijst de include naar buiten de boom of naar een niet-leesbaar pad: severity **high** met de tekst "kan niet worden geverifieerd", nooit medium.

**Verificatietest:** fixture `vulnerable/include-payload` waarvan de include een `core.fsmonitor` bevat; assert `findings.some(f => f.ruleId === 'core-fsmonitor')` **en** `exitCode === 1` bij de standaarddrempel. Plus een fixture `include-outside-tree` die `high` moet opleveren en niet gelezen mag worden.

---

### Finding 02: `safeCommandPrefixes` bevat het kale prefix `git`, en git kan elk commando uitvoeren
**Severity:** Critical · **Confidence:** High · **Categorie:** Security / False negative

`rules/git-exec-keys.json` → `safeCommandPrefixes: [..., "git", ...]`. `startsWithSafePrefix()` laat elke waarde door die met `git ` begint. Git kan zelf een willekeurig commando starten (`-c alias.x=!cmd`, `-c core.pager=cmd`, `-c diff.external=cmd`). De waarde bevat geen shell-metateken, dus `SHELL_META` grijpt niet in, en het eerste woord (`git`) is een kaal commando, dus `isBareCommand` grijpt niet in.

Reproductie (payload werd daadwerkelijk uitgevoerd door `git add`):
```bash
printf '[filter "lfs2"]\n\tclean = git -c alias.zz=!/pad/payload.sh zz\n' >> .git/config
printf '*.dat filter=lfs2\n' > .gitattributes
echo data > a.dat && git add a.dat     # -> payload UITGEVOERD
npx guardskill .                        # -> 0 findings, EXIT=0
```
Geldt identiek voor `filter.*.smudge`, `filter.*.process`, `diff.*.textconv` en `merge.*.driver` (alle vier gebruiken `exec-unless-known-command`).

**Fix:** verwijder `git` uit `safeCommandPrefixes`. Vervang de prefix-allowlist door een allowlist op exacte, volledige waarden (`git-lfs clean -- %f`, `git-lfs smudge -- %f`, `git-lfs filter-process`, `git-crypt clean`, …) óf houd het prefix `git` aan maar markeer elke `git`-invocatie met `-c`, `--config-env`, `--exec-path` of `-p` als **critical**.

**Verificatietest:** `adversarial.test.js` → `filter.x.clean = git -c alias.z=!/tmp/p.sh z` moet minimaal `high` opleveren; parametriseer over clean/smudge/process/textconv/driver. Voeg tegelijk een negatieve test toe met de echte git-lfs-waarden, die stil moet blijven.

---

### Finding 03: zeven uitvoerende git-sleutels ontbreken in de ruleset
**Severity:** High · **Confidence:** High (drie van de zeven exploits uitgevoerd) · **Categorie:** Security / Coverage

Een config met negen plausibele sleutels levert **"No findings", exit 0**:

| Sleutel | Wanneer git het uitvoert | Uitvoering bewezen |
|---|---|---|
| `pager.<subcommando>` (bv. `pager.log`, `pager.diff`) | bij `git log` / `git diff` op een terminal | **JA** — payload uitgevoerd |
| `gpg.program` / `gpg.<fmt>.program` | bij commit-signing en `--show-signature` | **JA** — payload uitgevoerd (`PWNED --status-fd=2 -bsau …`) |
| `remote.<n>.uploadPack` / `receivePack` | bij `git fetch` / `git push` op een lokaal pad | **JA** — payload uitgevoerd bij `git fetch` |
| `core.askPass` | bij elke credential-prompt | nee (prompt-pad niet bereikt in deze omgeving) — gedocumenteerd in git-config |
| `core.alternateRefsCommand` | bij het adverteren van tips uit een alternate | nee — gedocumenteerd in git-config |
| `trailer.<token>.command` | bij `git commit` / `interpret-trailers` | nee — gedocumenteerd in git-config |
| `init.templateDir` | kopieert hooks in nieuwe repositories | nee — indirect |

`pager.<cmd>` is het pijnlijkste geval: de README noemt `core.pager` expliciet onder "Direct execution keys", en dit is dezelfde sleutel met een subsectie.

**Fix:** voeg toe aan `rules`: `pager` + `anyKey` (matchType `exec-unless-safe-pager`), `gpg`/`gpg.*` `program` (`exec-unless-known-command`, allowlist `gpg`, `gpg2`, `gpgsm`, `ssh-keygen`), `remote.*` `uploadpack`/`receivepack` (`exec-always`), `core.askpass` (`exec-always`), `core.alternaterefscommand` (`exec-always`), `trailer.*` `command` (`exec-always`), `init.templatedir` (`always-flag`, medium).

**Verificatietest:** één vulnerable fixture per sleutel, plus de bestaande assertie "elke vulnerable fixture wordt door zijn eigen regel gevangen". Voeg daarnaast een *dekkingstest* toe die de sleutellijst in `rules` vergelijkt met een in de repo opgenomen lijst van uitvoerende git-sleutels, zodat een gat zichtbaar wordt in plaats van vergeten.

---

### Finding 04: alias-regel vuurt alleen op `!`, maar een alias zonder `!` voert ook code uit
**Severity:** High · **Confidence:** High · **Categorie:** Security / False negative

`matchType: shell-alias` → `value.trim().startsWith('!')`. Een alias die naar git zelf doorschakelt heeft dat teken niet nodig:
```bash
printf '[alias]\n\tst = -c core.pager=/pad/payload.sh log\n' >> .git/config
git st            # in een terminal: payload UITGEVOERD
npx guardskill .  # -> 0 findings, EXIT=0
```
(Uitgevoerd onder een pty; zonder terminal draait de pager niet — de ontwikkelaar zit wél in een terminal.)

**Fix:** behandel elke `alias.*`-waarde die begint met `-c`, `--config-env`, `--exec-path`, `-p`, `--paginate` of `-C` als high, naast de bestaande `!`-regel. Overige aliassen blijven ongemeld.

**Verificatietest:** twee gevallen in de evasion-suite: `alias.st = -c core.pager=/tmp/p.sh log` (moet high zijn) en `alias.lg = log --oneline --graph` (moet stil blijven).

---

### Finding 05: hookscripts die een symlink zijn worden overgeslagen; git voert ze uit
**Severity:** High · **Confidence:** High · **Categorie:** Security / False negative

`scanHooks()` en `inspectHooksDir()` filteren op `!e.isFile()`, wat `false` is voor een symlink. Een tar of zip draagt symlinks probleemloos mee.
```bash
ln -s /pad/payload.sh .git/hooks/pre-commit
git commit --allow-empty -m x   # -> hook UITGEVOERD (bewezen)
npx guardskill .                # -> "No findings"
```
Hetzelfde script als gewoon bestand → **CRITICAL**. De detectie hangt dus af van een eigenschap die de aanvaller kiest.

**Fix:** neem ook symlinks mee (`e.isFile() || e.isSymbolicLink()`), lees ze met een expliciete grootte-cap en meld een hook-symlink die buiten de gescande boom wijst als **critical** met de tekst dat het doel niet is geïnspecteerd. Lees het doel nooit buiten de boom.

**Verificatietest:** fixture met een symlink-hook, geskipt op platformen waar de symlink niet gemaakt kan worden — maar dan met `t.skip()`, niet met een lege `catch` (zie F-16).

---

### Finding 06: `.git` wordt case-sensitief vergeleken; op Windows en macOS is `.GIT` onzichtbaar
**Severity:** High · **Confidence:** High · **Categorie:** Security / False negative (platform)

`discovery.js` vergelijkt `entry.name === '.git'`. Op een case-insensitief bestandssysteem vindt git een map die `.GIT`, `.Git` of `.git ` heet wél.

Verificatie in twee delen, beide uitgevoerd:
1. Op de machine van Sam zelf: `test -f README.MD` → waar, en `test -d .GIT` → waar. **Het bestandssysteem waar deze repositories staan is case-insensitief.**
2. In de container: een boom met `vendor/pkg/.GIT/config` met `core.fsmonitor` erin → GuardSkill: `{} [] targets 1`, **geen enkele bevinding**.

Windows en macOS staan beide in de CI-matrix en in de doelgroep (Claude Code, Cursor, Copilot CLI). Dit is dus geen theoretisch geval.

**Fix:** vergelijk mapnamen genormaliseerd (`entry.name.toLowerCase() === '.git'`) en trim trailing spaces/punten; hetzelfde voor de `.git`-bestandsvariant en voor `.gitmodules`. Overweeg om bij een genormaliseerde-maar-niet-exacte match extra severity te geven: een map die `.GIT` heet is op zichzelf al een signaal.

**Verificatietest:** fixture `vulnerable/uppercase-git-dir` met `.GIT/config`; test draait op alle drie de CI-platformen (op Linux dekt hij het genormaliseerde pad, op Windows/macOS het echte git-gedrag).

---

### Finding 07: onvolledige scan, niet-bestaand pad en "niets gevonden" leveren alle drie exitcode 0
**Severity:** High · **Confidence:** High · **Categorie:** Reliability / Fail-open

Drie afzonderlijke problemen met dezelfde consequentie: de CI wordt groen terwijl er niets is bewezen.

**(a) CLI-standaarddiepte is nog 8, niet 24.** `discovery.js` heeft `maxDepth ?? 24`, maar `cli.js` geeft altijd `maxDepth: 8` mee en de helptekst zegt 8. De CHANGELOG van 0.3.0 stelt: *"The default traversal depth was 8, shallow enough to miss a repository inside `node_modules`. It is now 24."* Voor `npx guardskill .` — het enige oppervlak dat gebruikers hebben — is dat **onjuist**.
```
bare repo met core.fsmonitor op diepte 10
npx guardskill repo                  -> "No findings in the part of the tree that was walked", EXIT=0
npx guardskill repo --max-depth 24   -> 2 critical, EXIT=1
scan() zonder maxDepth (bibliotheek) -> 2 critical
```
**(b) Een onvolledige scan geeft exitcode 0.** De tekstuitvoer zegt correct "This is not a clean result", maar de exitcode en de JSON-`summary` zeggen "schoon". De test `a truncated walk is never reported as a clean result` assert alleen op de *tekst*; exitcode en statusveld worden niet getest. Claim dus **gedeeltelijk bevestigd**.
**(c) Een niet-bestaand pad geeft exitcode 0.** `npx guardskill ./typo` → "Not scanned: no git repository or git directory found under this path", **EXIT=0**. Een verkeerd pad in een pipeline is niet te onderscheiden van een schone scan. Hetzelfde geldt voor het scannen van een subdirectory van een repository: geen opwaartse zoektocht, dus "Not scanned" en exit 0 terwijl de bovenliggende `.git/config` vijandig kan zijn.

**Fix:** vier eindstatussen zoals het reviewkader vereist, in tekst, JSON (`status`-veld) én exitcode:
`CLEAN` = 0 · `FINDINGS` = 1 · `INCOMPLETE` = 3 (truncated, of een niet-geïnspecteerde include/symlink) · `ERROR` = 2 (pad bestaat niet, geen leesrechten, rules ongeldig). Zet de CLI-standaarddiepte op 24 en maak de helptekst gelijk aan de code. Laat `--fail-on` alleen over severity gaan, niet over volledigheid; `INCOMPLETE` faalt altijd tenzij `--allow-incomplete` wordt meegegeven.

**Verificatietest:** drie exitcode-tests via `spawn` op `src/cli.js` (niet op `scan()`, want de bug zit in de CLI): diepte-10-payload met de standaardopties → exit ≠ 0; niet-bestaand pad → exit 2; schone repo → exit 0. Plus een assertie dat de helptekst dezelfde default noemt als `parseArgs`.

---

### Finding 08: `--json` wordt bij 64 KB afgekapt zodra de uitvoer door een pipe gaat
**Severity:** High · **Confidence:** High · **Categorie:** Reliability

`main()` eindigt met `process.exit(code)` direct na `console.log`. Naar een pipe is stdout asynchroon, dus het proces stopt vóórdat de buffer leeg is.
```
guardskill --json > bestand   -> 4.306.018 bytes, geldige JSON
guardskill --json | wc -c     ->    65.536 bytes
guardskill --json | jq        -> "Unterminated string" — ongeldige JSON, exitcode ongewijzigd
```
Grens ligt op 64 KB, ruwweg 165 findings — haalbaar in een monorepo met veel geneste git-directories, en precies het pad dat de README aanbeveelt (`--json` in CI) en dat de geplande "GuardSkill Team"-laag zou consumeren. Het faalt stil: de consumer krijgt kapotte JSON, niet een foutmelding.

**Fix:** zet `process.exitCode = code` en laat het proces normaal eindigen; of schrijf met `await new Promise(r => process.stdout.write(text, r))` vóór de exit. Verwijder `process.exit()` uit het succespad volledig.

**Verificatietest:** `spawn` de CLI met `--json` op een fixture die > 200 findings oplevert, pipe de stdout, en assert `JSON.parse(stdout)` slaagt en `stdout.length > 65536`.

---

### Finding 09: een gesymlinkte `config` wordt buiten de gescande boom gelezen — in strijd met het eigen dreigingsmodel
**Severity:** Medium-High · **Confidence:** High · **Categorie:** Security (tool zelf)

`SECURITY.md` stelt: *"**It does not follow symlinks.** Directory traversal skips symbolic links, so a link inside a hostile repository cannot walk the scanner out of its target"* en sluit af met *"If you find a way to make GuardSkill … escape its target directory, that is a vulnerability in this tool and we want to hear about it."*

De directory-walk volgt inderdaad geen symlinks. `existsSync()` en `readFile()` doen dat wél:
```bash
mkdir -p repo/.git
ln -s /pad/buiten/de/boom/private.gitconfig repo/.git/config
npx guardskill repo    # leest en parseert het bestand buiten de boom, en print de inhoud als evidence
```
Een afgeleverde map kan GuardSkill dus elk bestand laten lezen dat de gebruiker kan lezen (`~/.gitconfig`, en met `--out` komen de matchende regels ook in een bestand terecht). De schade is begrensd — alleen regels die als git-config parseren en op een regel matchen komen in het rapport — maar het is per hun eigen definitie een kwetsbaarheid. Geldt ook voor `config.worktree`, `modules/**/config`, `.gitmodules` en het `.git`-bestand.

**Fix:** open configbestanden met `lstat` en weiger elk pad waarvan een component een symlink is; of open met `fs.open(path, fs.constants.O_NOFOLLOW)` op POSIX en verifieer op Windows via `realpath` dat het resultaat binnen `root` valt. Meld een geweigerde symlink als bevinding (**high**: "config is een symlink naar buiten de boom en is niet geïnspecteerd") — nooit stil overslaan, dat zou F-07 opnieuw introduceren.

**Verificatietest:** fixture met `.git/config` als symlink naar een bestand buiten de boom; assert dat de inhoud níet in enige `evidence` voorkomt en dat er een `high`-bevinding met status `INCOMPLETE` uit komt.

---

### Finding 10: valse positieven die het gedocumenteerde CI-recept breken — en een echt risico dat stil blijft
**Severity:** Medium-High · **Confidence:** High · **Categorie:** Correctness / Adoptie

De README zegt: *"A security tool that cries wolf gets uninstalled"* en onderbouwt dat met 29 schone fixtures. Die 29 zijn synthetisch en dekken de meest voorkomende legitieme toepassing van juist de regels met de meeste dekking niet.

**(a) Eén echte repository, acht criticals.** Een verse `git clone --depth 1` van `github.com/git-lfs/git-lfs` — het project dat in de eigen allowlist staat:
```
8 × CRITICAL bare-repo-in-tree  ->  git/githistory/fixtures/*.git   EXIT=1
```
Dat zijn ingecheckte testfixtures met een schone config. GuardSkill heeft ze gescand (`targets: 9`) en er geen uitvoerende sleutel in gevonden, maar rapporteert de structuur alleen al als critical met het advies *"Do not open this project with a coding agent"*. Dit is de eerste echte repository die ik heb gescand.

**(b) Legitieme filterconfiguraties, zeven highs.** git-lfs (allowlisted, stil) samen met vier alledaagse patronen:
```
HIGH  filter.nopfilter.clean  = cat
HIGH  filter.nopfilter.smudge = cat
HIGH  filter.sops.clean       = sops --encrypt /dev/stdin
HIGH  filter.sops.smudge      = sops --decrypt /dev/stdin
HIGH  filter.strip-notebook.clean = jupyter nbconvert --clear-output --stdin --stdout
HIGH  diff.jupyternotebook.textconv = jupyter nbconvert --to script --stdout
```
Elke sops- of notebook-repository faalt dus op `--fail-on high`.

**(c) Een geneste `.gitmodules` wordt niet gelezen.** `submodulePaths` komt alleen uit `.gitmodules` in de scan-root. Een repository met een subproject dat zelf submodules registreert:
```
HIGH  sub/.git             (verdedigbaar)
HIGH  sub/vendor/lib/.git  (correct geregistreerde submodule -> valse positief)
```

**(d) En omgekeerd:** in dezelfde config bleef `credential.helper = store --file=/tmp/git-credentials` **volledig stil**. `store` staat op de known-lijst en alleen het eerste woord wordt bekeken, dus argumenten worden nooit gelezen. Dat schrijft inloggegevens in platte tekst naar een voor iedereen leesbaar pad. Dezelfde blindheid geldt voor argumenten van toegestane editors en pagers.

**Fix:** scheid **severity** van **confidence** (het reviewkader vraagt dit expliciet) en laat `--fail-on` op confidence meewegen:
- structuur zonder uitvoerende sleutel (bare/nested git dir met schone config) → `medium`, confidence `low`, en escaleer naar `critical` zodra diezelfde config wél een uitvoerende sleutel heeft;
- een filter/textconv/driver die een kaal, via PATH opgelost commando is zonder shell-metateken → `low/medium`, confidence `low`; met een pad naar `/tmp`, een metateken of een download → `high/critical`, confidence `high`;
- inspecteer de argumenten van toegestane helpers/editors/pagers: `credential.helper = store --file=<pad>` → `high`;
- lees `.gitmodules` van elk gevonden repository, niet alleen van de root, en vergelijk paden relatief aan dat repository.
- Neem in de fixtureset op: git-lfs zelf (of een fixture met ingecheckte `*.git`-fixtures), sops, nbstripout, `clean = cat`, een geneste `.gitmodules`.

**Verificatietest:** een echte-wereld-corpustest (§7 van het reviewkader) die drie tot vijf vastgezette commits van bekende publieke repositories scant en assert dat geen enkele een `critical` oplevert; herkomst en verwachte uitkomst in de repo vastleggen. Plus de vijf genoemde clean-fixtures met dezelfde "niets boven informatief"-assertie.

---

### Finding 11: `location` wordt niet gesaneerd — een mapnaam kan het rapport herschrijven
**Severity:** Medium · **Confidence:** High · **Categorie:** Security (tool zelf) / Report integrity

`sanitise()` wordt op `evidence` toegepast, niet op `location`. `location` bevat bij structurele bevindingen `target.relPath` — een door de aanvaller gekozen mapnaam.

Reproductie met een map die `vendor` heet, gevolgd door `ESC [ 2K CR` en de tekst `No findings. Nothing was changed`:
```
[HIGH] vendor^[[2K^MNo findings. Nothing was changed/.git - Nested .git directory ...
  found  nested git directory at vendorM-oM-?M-=[2K No findings...   <- evidence WEL gesaneerd
```
In de terminal wist `^[[2K^M` de regel en schrijft de aanvallerstekst eroverheen. In het Markdown-rapport belanden de ruwe controletekens in het bestand. Met cursorbewegingen is een compleet vals "No findings"-scherm te construeren. Dit is precies de eigenschap die `SECURITY.md` claimt ("The report cannot be rewritten by its subject") — de fix van 0.3.0 dekte alleen configwaarden, niet paden.

**Fix:** haal `location`, `f.title` en `f.explanation` in de formatters door `sanitise()` in plaats van bij de bron; sla de ruwe waarde alleen op in de JSON-uitvoer (die geen terminal is) en escape daar `\u001b`.

**Verificatietest:** breid de bestaande test *"a hostile value cannot rewrite the report it appears in"* uit met een vijandige **mapnaam**, en assert `!/\u001b|\r/.test(formatText(result))` én hetzelfde voor `formatMarkdown`.

---

### Finding 12: een onbekende severity in de rules-JSON zet de exitcode vast op 1
**Severity:** Medium · **Confidence:** High · **Categorie:** Correctness

`loadRules()` valideert niets. `SEVERITIES.indexOf(f.severity)` geeft `-1` voor elke severity buiten de vier bekende, en `-1 <= threshold` is altijd waar:
```
rules-JSON met één regel op severity "info", scan met --fail-on critical:
[undefined] .git/config:2 - informational note
0 critical, 0 high, 0 medium, 0 low.
EXIT=1
```
De README nodigt gebruikers uit de rules aan te passen ("New detection rules go in `rules/git-exec-keys.json`"), en de roadmap belooft wekelijkse regelupdates. Eén typefout (`"High"`, `"info"`) breekt dus stil elke pipeline, met een `[undefined]`-label en een samenvatting die de bevinding niet toont. Een ongeldige regex in `remoteExecIndicators` valt via `new RegExp()` in dezelfde categorie: exit 2 met een cryptische melding.

**Fix:** valideer de ruleset bij het laden — verplichte velden, severity uit de vier toegestane waarden, `matchType` uit de bekende set, elke pattern-string compileerbaar — en faal met een duidelijke `ERROR` (exit 2) die het regel-id noemt. Compileer regexes één keer bij het laden in plaats van per aanroep.

**Verificatietest:** `loadRules` op een ruleset met een onbekende severity, een onbekende `matchType` en een kapotte regex moet drie keer een specifieke fout gooien; plus een test dat de meegeleverde `rules/git-exec-keys.json` de validatie doorstaat.

---

### Finding 13: `REPLACE_OWNER` staat nog in `package.json` van een publieke repository
**Severity:** Medium · **Confidence:** High · **Categorie:** Release-integriteit

`homepage`, `repository.url` en `bugs.url` bevatten alle drie nog `REPLACE_OWNER`, in commit `413be99` — terwijl commit `c68d50c` de boodschap *"Point package metadata at the published repository"* draagt. Gevolgen: de npm-pagina linkt naar 404's, GitHub koppelt het pakket niet aan de repository, en `npm publish --provenance` vereist dat `repository.url` overeenkomt met de bouwende repository.

**Fix:** zet alle drie op `soemoescode/guardskill` en voeg een release-check toe die faalt als `package.json` een placeholder bevat.

**Verificatietest:** één test die `JSON.stringify(pkg)` op `/REPLACE_|<jouw|TODO/` controleert.

---

### Finding 14: de publieke README schrijft een installatiecommando voor dat niet werkt
**Severity:** Medium (blokkerend voor de launch) · **Confidence:** High · **Categorie:** Documentatie / Claims

`github.com/soemoescode/guardskill` is publiek en de README is volledig zichtbaar (0 sterren), met `npx guardskill .` als eerste regel na de titel. `registry.npmjs.org/guardskill` geeft **404** — het pakket is niet gepubliceerd. Elke bezoeker die de repo nu vindt, krijgt een fout op de enige gedocumenteerde installatieroute. Dat is ook de aanname (A1) die Gate 1 moet meten: die meting is nu niet geldig.

**Fix:** publiceer op npm (stap 2 van de launch kit) of vervang de installatieregel tijdelijk door `git clone … && node src/cli.js .`. Doe stap 2 niet vóór F-01, F-02 en F-07 gefixt zijn: een securitytool die zijn eigen primaire vector doorlaat, is één Hacker-News-reactie van een permanente reputatieschade.

---

### Finding 15: absolute claims in README en SECURITY.md die de code niet waarmaakt
**Severity:** Low-Medium · **Confidence:** High · **Categorie:** Documentatie / Claims

| Claim | Werkelijkheid |
|---|---|
| "It does not modify anything, ever." (README) | `--out report.md` schrijft in de gescande map — de README gebruikt dat commando zelf als voorbeeld. `SECURITY.md` formuleert het correct ("The single exception is the `--out` file"); de README niet. |
| "It does not follow symlinks." (SECURITY.md) | Waar voor de directory-walk, onwaar voor configbestanden — zie F-09. |
| "An incomplete walk never reads as a clean result." (README) | Waar voor de tekstuitvoer, onwaar voor exitcode en JSON — zie F-07b. |
| "The default traversal depth … is now 24." (CHANGELOG 0.3.0) | Onwaar voor de CLI — zie F-07a. |
| "the build fails if any of them produces a finding above informational" (README, over 29 schone repositories) | Waar voor die 29; de corpus mist de gevallen uit F-10. |
| "GuardSkill only reads." (helptekst) | Zelfde nuance als de README-claim. |

**Fix:** vervang elke absolute formulering door een exacte, toetsbare scope. Voorbeeld: *"It never modifies the project it inspects. The only file it writes is the report you ask for with `--out`."* En: *"Directory traversal does not follow symlinks; config files reached through a symlink are refused and reported."* Neem geen claim op die niet door een test wordt gedekt — en omgekeerd: laat elke claim in `SECURITY.md` naar de testnaam verwijzen die hem bewijst.

---

### Finding 16: de symlink-test kan onopgemerkt leeg slagen
**Severity:** Low-Medium · **Confidence:** High · **Categorie:** Testkwaliteit

```js
try { await symlink(..., 'dir'); } catch { /* already there */ }
```
Op Windows vereist `symlink` verhoogde rechten of Developer Mode en faalt met `EPERM`. Die fout wordt weggeslikt, waarna de assertie "geen target begint met `link`" **triviaal slaagt** — er is immers geen symlink. De CHANGELOG van 0.3.0 zegt dat de test zich nu "skipt waar het platform geen symlink kan maken", maar de code skipt niet, hij zwijgt. Op `windows-latest` in de CI-matrix is de symlink-garantie dus vermoedelijk nooit getest, terwijl juist Windows het platform is waar de meeste doelgroepgebruikers zitten.

Ik heb dit ook zelf gezien: in een kopie van de werkboom viel deze test om (`scanner followed a symlink`) omdat er een echte map op de plaats van de symlink stond. Dat was een omgevingsartefact van mijn snapshot, geen productfout — maar het toont dat de test zowel vals-groen als vals-rood kan zijn.

**Fix:** vang de fout expliciet af en roep `t.skip('symlinks not permitted on this platform')` aan, zodat de CI-uitvoer zichtbaar maakt dat de garantie op dat platform niet is getest. Verwijder de map altijd vóór de test (`rm -rf`), niet erna.

**Verificatietest:** deze test is de test. Aanvullend: laat de suite falen wanneer meer dan één test wordt geskipt op Linux.

---

### Finding 17: kleinere punten
**Severity:** Low / Informational · **Confidence:** High

1. **Dode skip-regel.** `ALWAYS_SKIP` bevat `'node_modules/.cache'`, maar de check is `ALWAYS_SKIP.has(entry.name)` en `entry.name` is altijd één padsegment. Deze entry doet niets; `.terraform`, `.venv` en `__pycache__` werken wel. `node_modules` wordt volledig doorlopen — dat is verdedigbaar (bare repos verstoppen zich daar), maar maak het expliciet.
2. **Parser wijkt af van git op onschadelijke punten.** Differentiële test tegen `git config --file X --list` (23 gevallen): git en GuardSkill zijn het eens op 16, en wijken af op gedeeltelijke quoting (`"cur"l x` → git `curl x`, GuardSkill houdt de quotes), escape-sequenties (`\t`/`\n` worden door git echte tekens, door GuardSkill de letter), en `#`/`;` zonder voorafgaande witruimte (git kapt af, GuardSkill niet). **Alle afwijkingen vallen naar de veilige kant** — de detectie blijft vuren — maar de `evidence`-regel toont niet de waarde die git gebruikt, en dat is precies waar de gebruiker zijn beslissing op baseert. Overweeg de git-genormaliseerde waarde in `evidence` te zetten, met de ruwe regel eronder.
3. **Windows-payloads in `remoteExecIndicators`.** De patronen dekken `curl|sh`, `base64 -d`, `nc -e`, `eval $(`, `curl -o` en `python -c`. Er staat niets in voor PowerShell (`iwr … | iex`, `Invoke-Expression`, `-EncodedCommand`), `certutil -urlcache`, `bitsadmin` of `mshta`. Zulke hooks worden nog steeds `active-hook` (high), maar niet `critical` — een severity-misclassificatie, geen miss.
4. **GitHub Actions niet op commit-SHA vastgezet.** `actions/checkout@v4` en `actions/setup-node@v4` zijn tags. Met `permissions: contents: read` en zonder secrets is het risico laag, maar zet ze vast vóór er ooit een publish-workflow met een token bij komt.
5. **Geen release-workflow.** Publiceren gebeurt nu handmatig van een laptop: geen npm provenance, geen scheiding tussen build en publish, geen reproduceerbare release. Bouw een `release.yml` die op een tag draait, `npm publish --provenance` doet via OIDC, en die nooit door `pull_request` wordt getriggerd.
6. **Geen linter en geen typecheck.** Bij 700 regels is dat te overzien, maar `--fail-on`-logica en severity-tabellen zijn precies het soort code waar een `switch`-exhaustiveness-check (of JSDoc + `tsc --checkJs`) F-12 had gevonden.
7. **CHANGELOG staat niet chronologisch** (0.3.0 tussen 0.2.0 en 0.2.1).
8. **Prestaties zijn in orde — gemeten, niet aangenomen.** 8.721 directories: 0,58 s, geen meetbaar verschil tussen diepte 8 en 24. De `queue.shift()` op een array is O(n²) in theorie maar niet meetbaar onder de `maxEntries`-cap van 20.000. Geen bevinding; wél de kanttekening dat `isBareRepo()` drie `existsSync`-aanroepen per directory doet en dus lineair meeschaalt met de boom.

---

## 4. SECOND OPINION OP DE CLAIMS VAN DE OPERATOR

| Claim | Uitkomst | Bewijs |
|---|---|---|
| "22 kwetsbare fixtures worden alle 22 gedetecteerd, elk door zijn eigen regel" | **BEVESTIGD** | 27/27 tests groen, twee omgevingen, schone kopie |
| "29 schone fixtures leveren niets boven informatief op" | **BEVESTIGD voor die 29** — maar de corpus is niet representatief | F-10: git-lfs 8 criticals, sops/jupyter/`cat` 7 highs |
| "Nul dependencies, geen netwerk, geen telemetrie" | **BEVESTIGD** | statische controle van `src/` |
| "Een onvolledige walk leest nooit als een schoon resultaat" | **GEDEELTELIJK BEVESTIGD** | tekst wel, exitcode en JSON niet (F-07b) |
| "Standaarddiepte is nu 24" | **WEERLEGD voor de CLI** | F-07a, exitcodes gemeten |
| "Het rapport kan niet worden herschreven door zijn onderwerp" | **WEERLEGD** | F-11, mapnaam met ANSI-escapes |
| "Volgt geen symlinks" | **WEERLEGD voor configbestanden** | F-09, bestand buiten de boom gelezen |
| "Dekt de GitSpawn-klasse en CVE-2026-45033" | **GEDEELTELIJK BEVESTIGD** | de directe `.git/config`-vector en de bare-repo-vector: ja; via `include`, `.GIT`, symlink-hook, `pager.<cmd>`, `gpg.program`, `remote.uploadPack` en het `git`-prefix: nee (F-01 t/m F-06) |
| "CVE-2026-45033: CVSS 8.5, gefixt in 1.0.43" | **BEVESTIGD** | GitHub Advisory GHSA-9ccr-r5hg-74gf |
| "De symlink-test skipt zich waar het platform geen symlink kan maken" | **WEERLEGD** | F-16, lege `catch` in plaats van `t.skip()` |

---

## 5. WAT GOED IS

Dit hoort in een eerlijke review, omdat het bepaalt waar je *niet* aan hoeft te werken.

- De architectuur is schoon gescheiden: discovery, parser, regels, evaluatie en presentatie zijn afzonderlijk testbaar, en dat is waarom de negen bevindingen hierboven met kleine, lokale wijzigingen te repareren zijn.
- De keuze voor nul dependencies is voor een lokale securityscanner de juiste, en is consequent doorgevoerd.
- De regelconfiguratie in JSON met bronvermelding, en de eis dat elke regel een fixture aan beide kanten heeft, is precies de discipline die dit soort tools nodig heeft.
- De evasion- en robustness-suites zijn echt werk, geen vinkje: `config.worktree`, `.git/modules`, het `.git`-bestand, de basename-allowlist-bypass en de hooks-directory-naamtruc zijn allemaal reële aanvallen die door zelfaanval zijn gevonden.
- Er is nergens `child_process`, `exec` of netwerkcode in `src/`. De belangrijkste categorie van "de scanner is zelf het risico" is bij de bron uitgesloten.
- De redenering in de code-commentaren legt *waarom* vast, niet *wat* — en die commentaren waren voor deze review vaak het snelste pad naar de aanname die ik moest aanvallen.

---

## 6. PRIORITEIT

**Blokkeert npm-publicatie (doen vóór stap 2 van de launch kit):**
F-01 include volgen · F-02 `git`-prefix uit de allowlist · F-07 vier eindstatussen + CLI-diepte 24 · F-08 stdout niet afkappen · F-13 `REPLACE_OWNER`

**Blokkeert een geloofwaardige Show HN (een reviewer vindt deze binnen een uur):**
F-03 ontbrekende sleutels · F-04 alias zonder `!` · F-05 symlink-hooks · F-06 `.GIT` op Windows/macOS · F-09 symlink-config · F-11 `location` saneren · F-15 claims exact maken

**Bepaalt of het na twee weken nog geïnstalleerd is:**
F-10 severity/confidence scheiden + echte-wereld-corpus · F-12 rules valideren · F-16 skip in plaats van zwijgen

**Daarna:** F-14 (npm publiceren), F-17 (release-workflow met provenance, SHA-pinning, linter, Windows-payloadpatronen).

---

## 7. WAT NIET IS GETEST

- **`core.askPass`, `core.alternateRefsCommand`, `trailer.<token>.command`, `init.templateDir`**: als ontbrekende regel vastgesteld op basis van de git-documentatie, uitvoering niet gereproduceerd in deze omgeving.
- **Windows- en macOS-gedrag**: alle exploits zijn uitgevoerd op Linux met git 2.43.0. De case-insensitiviteit van F-06 is wel op de Windows-machine zelf bevestigd, het productgedrag daar niet.
- **Node 18 en 20**: de suite is alleen op Node 22 gedraaid. `package.json` claimt `>=18` en de CI-matrix dekt 18/20/22 — de CHANGELOG van 0.2.1 laat zien dat daar eerder een echt verschil zat.
- **De testsuite op de machine van Sam**: `pretest` faalt daar in mijn sessie op `EPERM: unlink`; een omgevingsbeperking, geen productfout.
- **Fuzzing van de parser met gegenereerde invoer**: ik heb 23 handgeschreven gevallen differentieel tegen `git config --file` gelegd. Een property-based test die configs genereert en de uitkomst met git vergelijkt, is de logische volgende stap en zou als vaste test in de suite moeten staan — git is hier de enige geldige orakel.
- **De landingspagina (`docs/index.html`)**: buiten scope van deze ronde.

---

*Review uitgevoerd op commit `413be99`. Alle in dit rapport geciteerde uitvoer is werkelijk uitgevoerd; waar een aanval niet is gereproduceerd, staat dat er expliciet bij. Bronnen: de repository zelf, `git config` (git 2.43.0) als referentie-implementatie, [git-config documentatie](https://git-scm.com/docs/git-config), [GitHub Advisory GHSA-9ccr-r5hg-74gf](https://github.com/advisories/GHSA-9ccr-r5hg-74gf), [npm registry](https://registry.npmjs.org/guardskill) (404), [github.com/soemoescode/guardskill](https://github.com/soemoescode/guardskill). Geraadpleegd 8 september 2026.*
