# urunc fuzzing — findings, targets, and oracle design

Status as of 2026-09-16. Verified against `upstream/main` @ `334595e`.

This file is the catalogue `tests/fuzzing/known/known.go` refers to when it says a
violation is "already catalogued in FUZZING_FINDINGS.md".

**Who this is for:** an engineer or agent picking up this work cold. It assumes no
memory of how any of it was derived. Every finding below records the actual call
path that was traced, so claims can be rechecked rather than taken on faith.

---

## 0. Where everything lives, and what state it is in

Read this first if you are cross-checking. It records what exists, where, and —
importantly — **which claims were verified by running code versus only by reading
it**.

### 0.1 Two worktrees, one repository

Both are worktrees of the same clone (`origin` = `git@github.com:pocopepe/urunc.git`,
`upstream` = `https://github.com/urunc-dev/urunc.git`).

| Path | Branch | Purpose |
|---|---|---|
| `/home/pocopepe/contrib/urunc` | `852-fuzzing-phase1-report` | Phase 1 report deliverable (`PHASE1_REPORT.tex` / `.pdf`) |
| `/home/pocopepe/contrib/urunc-fuzz` | `feat/315-fuzzing-harnesses` | all fuzz harnesses, this document |

### 0.2 Branch state (as recorded)

- **`852-fuzzing-phase1-report`** — cut fresh from `upstream/main` @ `334595e`,
  tracking `upstream/main`. Contains `PHASE1_REPORT.pdf` + `.tex`, staged.
- **`feat/315-fuzzing-harnesses`** — **rebased onto `upstream/main` (2026-09-17)**,
  HEAD `f9cdb32` (the same commit content as the old `ddc1d2b`, replayed onto the
  new base — zero conflicts, verified via `comm -12` on file lists before rebasing).
  Backup of the pre-rebase tip: `backup/fuzz-prerebase-20260917` (an earlier
  `backup/fuzz-prerebase-20260907` also exists, from a prior rebase).

  > **Correction worth recording:** this branch was described mid-project as "67
  > commits stale" against local `main`, then corrected to "9 commits behind
  > `upstream/main`". Now current with `upstream/main` — 0 commits behind.

  The 9 commits that landed include **FreeBSD guest support** (`c5eb1cd`), adding
  `unikernels/freebsd.go` + upstream's own `freebsd_test.go`. `FuzzBuildUrunitConfig`
  was NOT extended to it (freebsd's own `buildUrunitConfig` copy is exercised by
  upstream's `TestFreeBSDBuildUrunitConfig` instead, a plain unit test, not a fuzz
  target — consistent with this project's post-correction stance that guest-type
  content correctness belongs in unit tests, not fuzzing). Three targeted unit-test
  additions closed the 3 mutation survivors upstream's own test didn't reach:
  `TestFreeBSDInitNetworkOptional`, `TestFreeBSDInitCmdLineOptional`,
  `TestFreeBSDBuildUrunitConfigNoEnv`.

  **A stash-related pitfall, for the record:** the pre-rebase stash contained 5
  files that were `git add`-staged-as-new then deleted from disk without staging
  the deletion (status `AD`) — `cmd/urunc/{cli,logforward}_fuzz_test.go` and
  `pkg/unikontainers/{configsource,decode,setupdev}_fuzz_test.go`, the W6-retired
  targets. `git stash pop` resurrected all 5 as staged-added files, silently
  undoing the retirement. Caught by re-checking `git status` immediately after the
  pop rather than assuming it round-tripped cleanly; fixed by re-deleting and
  properly staging the deletion this time. If stashing across a rebase again,
  check for this class of file first.

### 0.3 Commit policy in force

**Nothing in this project is committed or pushed.** Standing instruction for the
duration: `git add` only — no `git commit`, no `git push`, no upstream issue or PR
comments. Everything below is therefore *staged, uncommitted* working-tree state. A
cross-checker will see it in `git status`, not in `git log`.

### 0.4 Files added or changed in the most recent pass

| File | State | What it is |
|---|---|---|
| `tests/fuzzing/FUZZING_FINDINGS.md` | added, staged | this document; also resolves the dangling reference at `known/known.go:69`, which cited this filename before the file existed |
| `pkg/unikontainers/hooks_conformance_test.go` | added, staged | targets for F4/F5: `FuzzHookArgvConstruction`, `TestHookArgvZeroIsPath`, `TestHookExecutionOrderIsNotPreserved` |
| `pkg/unikontainers/hypervisors/execcmd_differential_fuzz_test.go` | added, staged | targets for F0/F1: `FuzzBuildExecCmdMemoryAgreement`, `FuzzBuildExecCmdCommandAgreement` — the §5.1 cross-backend differential |

Pre-existing suite (all staged, from earlier passes): 27 fuzz targets across 18
`*_fuzz_test.go` files, `tests/fuzzing/known/known.go`, 5 `.dict` files,
`tests/fuzzing/oss_fuzz_build.sh`, `.clusterfuzzlite/`, `Makefile` changes.
Corpora live in untracked `testdata/` directories.

### 0.5 Verification status — run vs. read

Claims in this document are one of two kinds. Do not conflate them.

**Verified by executing code:**
- F4 and F5 reproduce — `TestHookExecutionOrderIsNotPreserved` and
  `TestHookArgvZeroIsPath` both pass, meaning both symptoms are live (assertions are
  inverted; see §8).
- `FuzzHookArgvConstruction` — 343k executions at ~17k/sec, green.
- `go build ./...`, `go vet ./...` clean; all five packages
  (`pkg/unikontainers`, `.../hypervisors`, `.../initrd`, `.../unikernels`,
  `cmd/urunc`) pass `go test`.
- The 27-target campaign: 60s each, `GOMAXPROCS=4`, ~28 min, zero failures beyond one
  harness false positive (fixed, §6.5).
- Mutation-testing numbers in §7.

**Established by reading code and the upstream tracker (not executed):**
- Every retired finding in §3 — each died by tracing a call path, not by running a
  repro. The reasoning is recorded so it can be re-derived or challenged.
- F2 and F3 mechanisms — read from current `upstream/main`; each is exercised by an
  existing target (`FuzzBuildUrunitConfig`/`finding-3` and
  `FuzzUruncConfigMapRoundTrip`/`finding-5` respectively), but the *consequence*
  described for each was reasoned, not observed.
- All upstream issue states (`#818`, `#983`, `#1010`, `#797`, `#700`, …) — read via
  `gh` at time of writing. Re-check before acting; issues move.

**F1 and F0 are now measured, not argued.** `FuzzBuildExecCmdMemoryAgreement` and
`FuzzBuildExecCmdCommandAgreement` (§4, Tier 1) were added and their oracles verified
to actually fire:

- memory, 1 GiB OCI limit: qemu / cloud-hypervisor / spt / hvt each request
  1,125,122,048 bytes — **+51,380,224 over the limit**;
- command line, empty vs set: `qemu`/`cloud-hypervisor` delta 0 (always emit the
  pair), `spt`/`hvt` delta 1 (omit when empty), `hyperlight` never reads `Command`.

Both are suppressed via `known.Expected`, so the suite stays green while the findings
remain tracked. Verified the oracles are live rather than vacuously passing — the
distinction §6 rule 4 exists to catch.

### 0.6 Stranded work to be aware of

`362633d` on `backup/fuzz-prerebase-20260907` is a correct, complete fix for F0
(`#818`) that was never upstreamed. Its `qemu_test.go` hunk predates `0a0e809` and
`76142c5`, so it cannot be cherry-picked cleanly — see §2/F0 for the four edits
required to re-apply it by hand against current code.

---

## 1. The rule that decides what counts as a bug

This project went through one full cycle of over-claiming and correction. The
corrective is a single test, applied to every candidate finding:

> **If every input were 100% trusted and well-formed, would this bug still fire?**

- **YES** → in scope. The bug lives in urunc's own logic: it contradicts itself,
  loses data it wrote, or mishandles a value that is perfectly legal and ordinary.
- **NO** → out of scope. The bug only exists because some input was malformed,
  hostile, or violated a contract. urunc trusts containerd and trusts the OCI spec.
  Findings that require breaking that trust are not this project's target.

This is deliberately stricter than "is it attacker-reachable". It rejects entire
classes that look like security findings but depend on an adversary that the trust
model says does not exist.

**Why this rule and not a severity ranking:** severity arguments are unfalsifiable
and burn reviewer goodwill. "Does this fire on legal input" is a yes/no question
that can be settled by reading code, and a maintainer can verify the answer in
minutes.

### Corollary for target design

Under this rule, the productive search space is **not** malformed input. It is the
*under-exercised corners of the legal input space*: empty strings, embedded
newlines, zero values, identifiers containing separator characters, values that are
legal per the OCI spec but that no test has ever supplied. Targets should be aimed
there. Targets that manufacture malformed input are, under this model, aimed at
nothing.

### 1.1 Input surface map

Every place data enters urunc, what validates it today, and whether targets point
there. Derived by enumerating actual reads (`git grep` for spec field accesses,
annotation keys, env lookups, file loads) rather than from the docs.

| # | Surface | Enters at | Validated by | Target coverage |
|---|---|---|---|---|
| S1 | `spec.Annotations` (13 `com.urunc.*` keys) | `getConfigFromSpec` `annotations.go:180` | `validate()` + `validateValues()` + `allowedPathRe` | good — and the validation is *new* (`81d15ab`); it closed several old findings |
| S2 | `urunc.json` in image rootfs | `getConfigFromJSON` `annotations.go:225` | same as S1, plus `decode()` | good |
| S3 | `spec.Process.Args` | `unikontainers.go:531` | **none** | **F1** — under-covered, Tier-1 target |
| S4 | `spec.Process.Env` | `unikontainers.go:532` | **none** | **F2** — under-covered, Tier-1 target |
| S5 | `spec.Process.User.UID/GID`, `.Cwd` | `unikontainers.go:535-538` | none (passed through to guest config) | low risk — same actor sets them directly |
| S6 | `spec.Hooks.*` (5 lifecycle lists) | `unikontainers.go:1017` | **none** | **F4, F5** — was entirely uncovered before this pass |
| S7 | `spec.Mounts[]` | `filterBindMounts` `shared_fs.go:121` | `SecureJoin` on destination | partial — non-bind types silently dropped (`TODO`, known) |
| S8 | `spec.Linux.Resources.Memory.Limit` | `monitorMemoryBytes` `unikontainers.go:476` | clamped `> 0` | **F0** — covered by `FuzzBytesToStringMB` |
| S9 | `/etc/urunc/config.toml` (+ `URUNC_CONFIG_FILE` override) | `ResolveUruncConfigPath` `urunc_config.go:35` | TOML parse only | **F3** — covered by round-trip targets |
| S10 | `state.json` on reload | `Get()` `unikontainers.go:157` | only `annotType != ""` | covered by `FuzzStatePersistenceRoundTrip`; see note below |
| S11 | `/proc/self/mountinfo` | `getMountInfo` `block.go:131` | kernel-supplied | `#867` upstream, Tier 3 |
| S12 | containerd content store (manifest/blobs) | `readBlob` `containerd-shim/.../annotations.go:131` | none (no digest check) | out of scope under trust model — retired |
| S13 | `spec.Linux.Namespaces`, `.Seccomp`, `.RootfsPropagation`, `Process.Capabilities` | various | passed to libcontainer | **uncovered** — see §5.3 |

**Where the gaps actually are.** S1/S2 — the surface that got the most attention
historically, and where most retired findings lived — is now the *best*-defended,
because `81d15ab` added real validation. The under-defended surfaces are the ones
nobody thought of as "config": **S3, S4, S6**. All three flow straight from the spec
into behaviour with no validation layer whatsoever, and all three produced live
findings (F1, F2, F4, F5). S6 had zero target coverage until this pass.

**The pattern worth generalising:** validation in urunc is concentrated on fields
that *look* like configuration (annotations, paths, identifiers) and absent on
fields that look like *pass-through data* (args, env, hooks). Pass-through is
exactly where the conformance bugs live, because nobody writes assertions about data
they believe they are merely forwarding.

**S10 note:** `Get()` re-validates only `annotType`. Everything else in `state.json`
is trusted verbatim on reload, including values that `validateValues()` gated at
create time. This is fine under the trust model (the file is root-owned runtime
state, not attacker input), but it means any create-time invariant is *not* re-checked
on `start`/`exec`/`delete`. If a future change makes those invariants load-bearing
later in the lifecycle, this becomes the place it breaks.

### 1.2 Why these bugs exist — urunc is a transcoder

An earlier version of this analysis proposed: *"urunc validates what looks like
configuration and asserts nothing about what it merely forwards."* **That thesis is
false and was discarded.** `getDNSServer` (`utils.go:380`) is pure pass-through — the
host's `resolv.conf` relayed to the guest — and it is carefully validated:
`net.ParseIP`, an explicit `To4()` check, `IsLoopback()` rejection, graceful empty
return with a warning. Pass-through is not the predictor.

The actual predictor is narrower and sharper:

> **Bugs cluster where urunc re-encodes a value into a format that a *different
> codebase* parses.**

urunc's core job is transcoding: OCI spec in, monitor command lines / guest config
blobs / libcontainer configs out. `getDNSServer` is validated because urunc must
*interpret* the value (it needs an IP). Env entries, hook args and memory limits are
mishandled because urunc does not need to understand them — it only needs to *relay*
them into another format. Relaying is where the semantics get lost, and Go's type
system cannot help because both sides are `string`.

**This explains findings the thesis was not built from**, which is the test of a
thesis. Sorted by who owns the far side of the boundary:

| Finding | urunc encodes | consumed by | contract lives in |
|---|---|---|---|
| F0 / `#818` | bytes → `"N"` | qemu, CH, solo5 | those projects' CLI docs |
| F1 | `Command` → flag pair | qemu, CH, solo5 | those projects' CLI docs |
| F2 | `[]string` env → marker blob | **urunit** (separate repo) | nowhere written down |
| F5 | `hook.Args` → argv | the hook binary | POSIX `execv` |
| F4 | hook list → execution order | — | `config.md:589` |
| F6 | env → kernel cmdline | **the Linux kernel** | `kernel/params.c` |
| `#897` | args → quoted cmdline | urunit | nowhere written down |
| `#963`/`#909` | mask → CIDR | guest net stack | RFC |
| `#867` | kernel octal escapes → path | — | `proc(5)` |

Nine of the eleven catalogued findings sit on a boundary where **no compiler, type
checker, or test in either codebase validates the contract**. That is the structural
reason they survive: each side is individually well-tested and the contract between
them is untested by construction.

The two exceptions (F3, `#983`) are *intra*-codebase round trips — urunc encodes and
decodes its own data. Different failure mode: not semantic mismatch but lossiness
(dropped entries, ambiguous zero values). Different oracle: round-trip identity.

### 1.3 The scale of the transcoding surface

The encoding responsibility is **split across two interfaces**, and neither side owns
the whole contract:

- `types.Unikernel` (`types.go:20`) has **five encoder methods** — `CommandString`,
  `MonitorNetCli`, `MonitorBlockCli`, `MonitorSharedfsCli`, `MonitorCli`.
- `types.VMM` (`types.go:31`) consumes those fragments and assembles the final argv.

There are **7 monitor implementations** (`cloud_hypervisor`, `firecracker`, `hedge`,
`hvt`, `hyperlight`, `qemu`, `spt`) and **7 guest-type implementations** (`freebsd`,
`hermit_rs`, `linux`, `mewz`, `mirage`, `rumprun`, `unikraft`). The cross product is
real, not theoretical — guest encoders branch on the monitor they are paired with:

| guest file | monitor-conditional branches |
|---|---|
| `linux.go` | 9 |
| `freebsd.go` | 6 |
| `mewz.go`, `mirage.go`, `rumprun.go` | 2 each |
| `hermit_rs.go`, `unikraft.go` | 1 each |

F1 is exactly a split-responsibility failure: the *monitor* decides whether to emit
the `-append` pair; the *guest* decides what `Command` contains; neither owns the
question "is an empty command line meaningful". F6 was found by following this map —
`linux.go` has the most monitor-conditional branching and sits in the package scoring
50% mutation efficacy, so it was the highest-risk cell. The prediction held.

### 1.4 The rule that makes differential oracles work

Both real oracles written this pass initially produced **false findings**, both from
the same mistake, and the loud branch caught both within seconds:

1. `FuzzLinuxCmdlineEnvEncoding` used `len(strings.Fields(entry)) > 1` as a proxy for
   "contains whitespace". `strings.Fields(" =")` returns 1, so `" ="` fell through to
   the verbatim check it could not pass.
2. The same target then verified with `strings.Fields(out)`, which is **Unicode-aware**.
   It flagged `"=\u2000"` (EN QUAD) as fragmented — but the Linux kernel's parser is
   byte-oriented and splits on ASCII space/tab only, so the kernel would keep it whole.

Neither was a urunc bug. Both were the oracle mis-modelling the consumer. Hence:

> **A differential oracle's model of the far side must be derived from that
> consumer's own specification, never from whatever the standard library makes
> convenient, and never from urunc's encoder.**

Derive it from urunc's encoder and the test is vacuous — it asserts only that the
code does what the code does. This is precisely why `FuzzBuildExecCmd` missed F0 and
F1: its oracle ("argv elements should not be empty") was derived from urunc's own
notion of well-formedness rather than from what qemu and solo5 actually require.
`FuzzBuildExecCmdMemoryAgreement` caught F0 because its model came from the `#818`
thread and the Solo5 source — the consumer's side.

Put the reference model in a **named function with its source cited in the comment**
(`kernelFields`, `ociHookArgv`, `extractMemBytes`), so the assumption is reviewable
rather than buried in an expression.

---

## 2. Live findings

Findings that pass the trusted-input test. These are the only ones worth a
maintainer's attention.

### F1 — Empty `Command` is handled inconsistently across monitor backends

**Trusted-input test: YES.** A container image with no extra kernel arguments is
ordinary and well-formed. Nothing malformed is required.

**Path traced:**
```
spec.Process.Args
  → unikontainers.go:531   CmdLine: u.Spec.Process.Args
  → unikontainers.go:796   buildUnikernelCommand() → unikernel.CommandString()
  → unikontainers.go:722   vmmArgs.Command = <result, may legally be "">
  → hypervisors/*.BuildExecCmd(args)
```

**The divergence**, with `args.Command == ""`:

| backend | code | result |
|---|---|---|
| qemu | `qemu.go:164` — `append(exArgs, "-append", args.Command)` unconditional | emits `-append ""` |
| cloud-hypervisor | `cloud_hypervisor.go:155` — `append(exArgs, "--cmdline", args.Command)` unconditional | emits `--cmdline ""` |
| spt | `spt.go:82` — `if args.Command != "" { ... }` | omits the argument entirely |
| hvt | `hvt.go:172` — `if args.Command != "" { ... }` | omits the argument entirely |

Two backends pass an explicit empty kernel command line; two omit the parameter and
let the monitor fall back to its own default. Same trusted input, two different
guest boot configurations, selected only by which monitor the image asked for.

**Upstream:** nothing. Searched `empty command kernel cmdline`, `solo5 command line
empty`, `cmdline argument empty` — no issues.

**Status:** unreported, unfixed. Strongest live finding.

**Fix shape:** pick one convention and apply it to all four. Omitting is the safer
default (it preserves each monitor's own documented behaviour); emitting an explicit
empty value is the more predictable one. Either is defensible — the bug is that
urunc currently does both.

---

### F2 — `buildUrunitConfig` writes env values raw into a line-delimited format

**Trusted-input test: YES.** OCI places no constraint on an env var value containing
a newline. A PEM certificate or JSON blob passed via env is ordinary in real
deployments, not an attack.

**Path traced:**
```
spec.Process.Env
  → unikontainers.go:532   EnvVars: u.Spec.Process.Env
  → unikernels/linux.go:240   l.Env = data.EnvVars
  → unikernels/linux.go:318   buildUrunitConfig()
       sb.WriteString(strings.Join(l.Env, "\n"))   // no escaping, no validation
```

The config blob urunit parses inside the guest is newline-delimited and
marker-delimited (`UES`/`UEE` for env, `UCS`/`UCE` for process config, `UBS`/`UBE`
for block devices). An env value containing `\n` forges a line boundary inside that
format, so the guest parses a different environment than urunc intended to set.

**No validation gate exists on this path.** `validateValues()` (`annotations.go:389`)
and its `allowedPathRe` check apply only to annotation-derived path fields
(`UnikernelBinary`, `Initrd`, `Block`, …). `spec.Process.Env` never passes through
any of it.

**Scope note:** the FreeBSD guest support added in this drift window introduced a
second copy of the same serializer at `unikernels/freebsd.go:269`. The surface grew;
any fix must cover both.

**What is proven vs. what is not:**
- *Proven* by `FuzzBuildUrunitConfig`: the env section itself is corrupted — the
  guest receives a different set of env entries than were declared.
- **Updated, with evidence:** the mechanism is broader than "needs an embedded
  newline." The background 12-core regression campaign's own accumulated corpus
  produced `env = ["UEE", "0"]` — an env value that is **exactly** the literal marker
  string `UEE`, no newline anywhere in the input — and it forged the env section's
  own end marker one line early (`buildUrunitConfig` wrote 0 lines for 2 entries).
  This is a **strictly easier trigger** than F2's original newline framing: any
  ordinary single-line value that happens to exactly equal one of the six markers
  (`UES`/`UEE`/`UCS`/`UCE`/`UBS`/`UBE`) collides, no multi-line value required at
  all. `FuzzBuildUrunitConfig`'s `shapeOK` predicate originally only checked for an
  embedded newline — its own `t.Fatalf` message had said "a line boundary **or a
  marker**" from the start, but the marker half was never actually implemented,
  so the campaign's corpus caught its own harness's gap. Fixed: `shapeOK` now also
  matches exact marker-line equality; both are the same root cause (unescaped,
  marker-delimited serialization), so this stays under F2 rather than a new ID.
- **Now proven, against urunit's own source (2026-09-18).** Checked
  `nubificus/urunit@86913f1`, `src/main.c`. Three properties of its parser matter:
  1. `parse_envs` ends the env section on `memcmp(line, "UEE", 3) == 0`, a
     **3-byte prefix** match, not an exact line match. Any env var whose *name*
     starts with `UEE` (`UEE_DEBUG=1`) ends the section. That is a wider trigger
     than the exact-marker case above, and this project's own `FuzzBuildUrunitConfig`
     oracle cannot see it, because it models exact-line matching (Phase 2 target 1).
  2. After the section ends early, the read position is mid-list, so the next check
     `memcmp(conf_area, "UCS", 3)` fails. Every section check (`UES`/`UCS`/`UBS`/`UNS`)
     is an `if` with no `else`: the process, block and (FreeBSD) network sections are
     **silently skipped**, not rejected.
  3. `setup_exec_env(NULL)` logs "nothing to be done" and returns success: no
     `setgid`, `setuid` or `chdir`.

  **End to end**, with urunc's real `buildUrunitConfig` writing the file and urunit's
  real `get_config_from_file` (compiled from `src/main.c` with `main` renamed)
  parsing it, for UID/GID 1000, cwd `/app` and one block volume:

  | env | envs parsed | process config | block config |
  |---|---|---|---|
  | `PATH=/bin`, `B=2` | 2 | parsed | parsed |
  | `PATH=/bin`, `UEE_DEBUG=1`, `B=2` | 1 | **NULL** | **NULL** |
  | `PATH=/bin`, `"A=1\nX=injected"`, `B=2` | 4 (`X` injected) | parsed | parsed |

  So an ordinary env var name makes the guest app run without its later env vars,
  without its requested UID/GID/cwd (it inherits urunit's PID-1 identity), and
  without its block volumes mounted, with no error anywhere.

**Not an escalation by the spec author**, who sets `Process.User` and `Process.Env`
alike and could ask for UID 0 directly. It is a silent failure to apply the spec's
own requested identity and mounts, which is worse than the env-only corruption this
entry first recorded.

**Reach: opt-in, not default.** urunc sends env through exactly one of two paths.
`Linux.Init` sets `InitrdConf = strings.Contains(l.App, "urunit")` (`App` is the
image's first argument), and FreeBSD's `WithUrunit = usesUrunit(CmdLine)` works the
same way. Only guests whose entrypoint is urunit reach F2. Every other Linux guest
has its env appended to the kernel command line instead, which is F6. So the Phase 1
report ranks F6 first (default path, triggered by any env value containing a space)
and F2 second (most severe consequence, opt-in reach). How many real images use
urunit as their entrypoint was not measured.

**Upstream:** nothing, in either repository. `#897` is `parseCmdLine` quoting, a
different function.

**Fix shape, both sides:** urunc should reject or escape env entries that break the
format (`\n`, `\r`, a leading marker). urunit should match whole lines and fail loudly
when an expected section is missing instead of skipping it. Either alone leaves the
other side fragile.

---

### F3 — `Map()` / `UruncConfigFromMap` silently drop dotted identifiers

**Trusted-input test: YES.** A TOML section name containing a dot is syntactically
valid; nothing documents a prohibition.

**Path traced:**
```
/etc/urunc/config.toml
  → LoadUruncConfig → UruncConfig
  → urunc_config.go:210    Map()  writes "urunc_config.monitors.<name>.<field>"
  → unikontainers.go:111   confMap := config.Map()   (stored into state.json)
  ... later invocation (start / exec / delete) ...
  → unikontainers.go:157   u.UruncCfg = UruncConfigFromMap(state.Annotations)
  → urunc_config.go:233    UruncConfigFromMap:
       parts := strings.Split(key, ".")
       if len(parts) != 4 { continue }      // ← dotted name yields 5+, entry dropped
```

`Map` and `UruncConfigFromMap` are declared inverses. A monitor or extra-binary name
containing `.` produces 5+ parts on the way back and the whole entry is silently
discarded — so a container's configuration differs between the `create` call and
every subsequent `start`/`exec`/`delete`.

A related second defect at the same site: a field written as `0` reads back as the
built-in default, because the reader cannot distinguish "explicitly zero" from
"absent" (`if intVal, err := strconv.Atoi(val); err == nil && intVal > 0`).

**Reach:** host-operator only. The triggering value comes from the admin's own
`config.toml`, not from any container image. Real, but narrow — rank accordingly.

**Upstream:** nothing on dot-splitting. `#796` (closed) is a `DefaultMemoryMB`
overflow; `#1010` (closed, found by the maintainer) is partial `extra_binaries`
losing defaults — adjacent defaulting machinery, different bug.

---

### F4 — Hooks are executed concurrently, violating the spec's ordering MUST

**Trusted-input test: YES.** A hook list is ordinary, host-supplied, well-formed
configuration. Nothing malformed is required.

**The requirement**, OCI runtime-spec v1.2.1, `config.md:589`:

> Hooks MUST be called in the listed order.

**What urunc does** (`unikontainers.go:1035`):

```go
// NOTE: This wrapper function provides an easy way to toggle between
// the sequential and concurrent hook execution.
// By default the hooks are executed concurrently.
if true {
    return u.executeHooksConcurrently(name, hooks, s)
}
return u.executeHooksSequentially(name, hooks, s)
```

`executeHooksConcurrently` spawns every hook in its own goroutine simultaneously.
Listed order is not preserved, and cannot be. Both implementations exist; the
sequential one is unreachable behind a hardcoded `if true`. The code's own comment
concedes the risk: *"It is possible that the concurrent execution of the hooks may
cause some unknown problems down the line."*

**runc, for comparison** (`libcontainer/configs/config.go:549`): a plain
`for _, h := range hooks` loop — sequential, in order.

**Consequence:** any ordered hook chain races. A `createRuntime` list where hook 1
provisions a resource and hook 2 configures it is a normal, spec-sanctioned pattern
that urunc cannot execute correctly.

**Proven, not argued:** `TestHookExecutionOrderIsNotPreserved`
(`pkg/unikontainers/hooks_conformance_test.go`) runs two real hooks through the real
`ExecuteHooks` and observes the output written in inverted order (`SECONDFIRST`).

**Measured severity, not assumed:** ran a second probe — hook 1 creates a marker
file, hook 2 checks for it and fails if missing — through the real `ExecuteHooks`
200 times. **200/200 failed.** This is not a rare scheduler race that might show up
under load; `exec.CommandContext`'s fork/exec latency makes the dependent hook lose
essentially every time. Any real "hook 1 sets something up, hook 2 assumes it
exists" pattern — a completely ordinary, spec-sanctioned use of ordered hooks —
breaks in practice, not just on paper. This is why F4 is ranked above a pure
spec-conformance nitpick: it costs real, everyday functionality, even though (per
§1 the trusted-input test and `ananos`'s position on `#797`) it is not a security
finding, since hooks are already fully-trusted arbitrary code.

**Upstream:** nothing. Searched `hooks concurrent`, `hook order`, `hooks execution`,
`poststart hook`.

**Fix shape:** flip the `if true` to `if false`, or delete the concurrent path. The
sequential implementation already exists and is already maintained.

---

### F5 — Hook `argv[0]` is replaced with `path`, discarding the spec-supplied `argv[0]`

**Trusted-input test: YES.** `args[0]` differing from `path` is normal and explicitly
sanctioned by the spec.

**The requirement**, `config.md:555`: `hooks[].args` has *"the same semantics as IEEE
Std 1003.1-2008 `execv`'s argv"* — so `args` **is** the full argv, and `args[0]` is
the program name.

**What urunc does** (`utils.go:345`):

```go
args := hook.Args
if len(args) > 0 {
    args = args[1:]            // drop the spec's argv[0] ...
}
cmd := exec.CommandContext(ctx, hook.Path, args...)   // ... and substitute Path
```

`exec.CommandContext` sets `cmd.Args = append([]string{path}, args...)`, so the
spawned process sees `argv[0] == hook.Path`, never `hook.Args[0]`.

**runc, for comparison** (`libcontainer/configs/config.go:595`):
`exec.Cmd{Path: c.Path, Args: c.Args}` — passes `args` through as the literal argv.

**Consequence:** multi-call binaries dispatch on `argv[0]`. A hook of
`path: /bin/busybox, args: ["wget", "-q", url]` runs `wget` under runc and
misbehaves under urunc, which passes `argv = ["/bin/busybox", "-q", url]` — wrong
applet, and `-q` consumed as the applet name.

**Proven, not argued:** `TestHookArgvZeroIsPath` runs a real hook and reads back the
`$0` the process actually saw (`/bin/sh`, not the supplied canary).
`FuzzHookArgvConstruction` differentially compares urunc's argv construction against
the spec's across legal hook shapes — pure function, ~17k exec/sec, no process spawn.

**Upstream:** nothing. Searched `hook argv`.

**Fix shape:** build the command the way runc does — `exec.Cmd{Path: hook.Path,
Args: hook.Args}` — instead of `CommandContext` plus the `args[1:]` compensation.
Note this also removes the need for that compensation entirely.

**Framing note — important.** Present F4 and F5 as **conformance** bugs, never as
security bugs. Maintainer `ananos` closed `#797` (a hook-related report) NOT_PLANNED
with: *"OCI hooks come from config.json, which is written by the host-side engine
(containerd / kubelet) -- a container image cannot define hooks. Whoever can set a
hook is already executing arbitrary binaries."* That position is correct and settled.
The argument that lands is "urunc does not do what the spec says MUST happen", with
the line number, not "an attacker could…".

**Related, do not re-file:** `#700` (hooks without a timeout hang indefinitely) is
closed. Maintainer `cmainas` declined deliberately: *"Setting a timeout is optional
and up to the runtime… I doubt how much it will help."* The stale comment in
`executeHook` claiming "otherwise use global config timeout" is misleading — no such
global timeout exists anywhere in the codebase — but that is a comment nit, not a
finding.

---

### F6 — `spec.Process.Env` is space-joined into the guest kernel command line

**Trusted-input test: YES.** An env value containing a space is ordinary
(`docker run -e "GREETING=hello world"`). Nothing malformed is involved.

**Path traced:**
```
spec.Process.Env
  -> unikontainers.go:532      EnvVars: u.Spec.Process.Env
  -> unikernels/linux.go:240   l.Env = data.EnvVars
  -> unikernels/linux.go:111   bootParams += " " + eVar     // no escaping
```

**Reached when** `InitrdConf` is false. That flag is
`l.InitrdConf = strings.Contains(l.App, "urunit")` (`linux.go:248`) — so this is
the path for **any Linux guest whose binary is not urunit**, an ordinary
deployment rather than an edge case.

**Why it is a defect:** the Linux kernel splits its command line on whitespace and
honours the **last** occurrence of a repeated parameter. urunc appends env entries
*after* the boot parameters it sets itself, so an env value containing a space can
silently override them.

**Measured**, not argued — probe output for `A=1 root=/dev/sda1`:

```
panic=-1 console=ttyS0 root=/dev/vda rw A=1 root=/dev/sda1 init=/sbin/myinit --
                       ^^^^^^^^^^^^^^^ urunc's       ^^^^^^^^^^^^^^^^ env's, wins
```

The guest's root device is redirected by an env var. `MSG=x init=/bin/sh` likewise
injects a second `init=`.

**Relationship to F2 — these are different findings.** F2 is the *urunit* path
(`InitrdConf == true`), where env goes into a newline-delimited config blob. F6 is
the *non-urunit* path, where env goes onto the kernel command line. Same source
field, two different sinks, two different delimiters, both unescaped.

**Relationship to PR #858.** That PR ("replace string concatenation in CLI
construction") eliminated this class on the **monitor** side — argv is now built with
`append()` on a `[]string`. The **guest** side was never part of that change and
still concatenates. F6 is the surviving half of a bug class the project already
decided was worth fixing.

**Proven by:** `FuzzLinuxCmdlineEnvEncoding`
(`pkg/unikontainers/unikernels/cmdline_encoding_fuzz_test.go`), 1.7M execs at
~37k/sec clean after the oracle was corrected twice (see below).

**Upstream:** nothing. Searched `kernel command line env`, `env var space`,
`boot parameter injection`, `cmdline space`.

**Fix shape:** the same remedy #858 applied to the monitor side — stop
concatenating. Either reject whitespace in env entries on this path, or pass env to
the guest through a channel that is not whitespace-delimited (which is what the
urunit path already does, modulo F2).


**Reach and the common case (checked 2026-09-18):** this is the *default* Linux path.
`CommandString` appends env to the kernel command line only when `!InitrdConf`, i.e.
whenever the image does not use urunit as init (urunit guests take F2's path
instead). The override of `root=` is the dramatic case. The common case is plainer:
any env value containing a space is cut at the space, and the rest becomes separate
kernel parameters. Measured: env `"A=1 root=/dev/sda9"` gives `... rw A=1
root=/dev/sda9 B=2`, so `A` arrives as `1`. Ordinary values like
`JAVA_OPTS="-Xmx1g -Dfoo=bar"` are enough to trigger it. The kernel's `root=` handler
(`init/do_mounts.c`, `root_dev_setup`) copies into `saved_root_name` on every
occurrence, so the last one wins.
---

### F7 — RETIRED: Rumprun's repeated `"env"` JSON keys were assumed to collide, but they don't

**Was:** claimed Rumprun's hand-rolled env encoding (`rumprun.go:79-94`, one
`{"env":"K=V"}` fragment per variable, comma-joined) produces duplicate JSON keys
that silently drop every env var but the last, "verified" against Python's
standard `json` module.

**Why it died:** that verification used the wrong reference model — a generic JSON
decoder, not Rumprun's actual parser. Rumprun's guest-side config reader
(`rumprun-fork/lib/librumprun_base/config.c:770-836`) is a hand-written linear
token scanner over `jsmn` tokens, not a JSON-to-map decoder: it walks every
top-level key in sequence and dispatches to a handler on each occurrence, with no
deduplication. `handle_env` (`config.c:251`) calls `putenv()` once per dispatch.
A repeated `"env"` key is therefore not a collision at all — it's `N` independent
`putenv()` calls, one per variable, which is exactly what urunc's fragment-joining
loop produces. urunc's own comment (*"Rumprun does not use a valid JSON format...
we manually construct the JSON"*) was describing the correct wire format for this
parser, not a shortcut that happened to introduce a bug.

This is the same mistake the reference-model rule (§1.4) exists to catch, applied
against the finding that motivated writing that rule down — checked with a generic
decoder instead of the actual consumer's parser. All env vars survive; nothing is
silently dropped. No fix needed.

---

### F0 — `BytesToStringMB` uses decimal MB where every consumer reads binary MiB

Recorded here because it is **already found and already agreed upstream** — do not
re-file it. Listed so nobody rediscovers it and thinks it is new.

**Upstream:** `urunc-dev/urunc#818`, **fixed**. `BytesToStringMB` now calls `bytesToMiB` instead of `bytesToMB`; `bytesToMB` and its dedicated `TestBytesToMB` are deleted, since `bytesToMiB` was their only remaining caller. `qemu_test.go`'s and `solo5_test.go`'s stale "renders `-m`/`--mem` in MB" cases (both hardcoded `512 * 1000 * 1000` expecting `512`) were updated to `512 * 1024 * 1024`, since post-fix the old input yields `488`, not `512`.

Verified directly, not inferred from a passing test: `BytesToStringMB(1024*1024*1024)` now returns `"1024"` (was `"1073"`). Both suppressions built around this defect (`finding-7` in `memory_fuzz_test.go` and in `execcmd_differential_fuzz_test.go`) are now permanently unreachable rather than merely quiet — with both sides of each oracle using the same MiB truncation, the overshoot condition each suppression exists to catch can no longer occur. Left in place as regression guards; both files' comments were updated to say so and to correct an earlier misreading (an older comment cited `solo5_test.go`'s pre-fix assertion as a *conflicting, maintainer-reviewed* test — it was decimal because the code was decimal, not because decimal was the intended contract).

**The defect:** `hypervisors/utils.go` defines both `bytesToMiB` (`:38`, binary) and
`bytesToMB` (`:43`, decimal). Firecracker uses `bytesToMiB` (`firecracker.go:122`,
feeding its `mem_size_mib` field) and is correct. Everything else goes through
`BytesToStringMB` (`:48`) → `bytesToMB`, then hands the decimal result to a consumer
that interprets it as binary (`-m <N>M`, `--memory size=<N>M`, `--mem=<N>`). Guest
memory exceeds the OCI byte limit by up to ~4.86% (measured: **+51,380,224 bytes,
+4.79%**, for a 1 GiB limit — truncation makes the realised figure slightly below
the theoretical 1048576/1000000 ratio), risking host cgroup OOM kills.

For a 1 GiB OCI limit: firecracker guest gets 1024 MiB; qemu/CH/spt/hvt guests get
1073 MiB (1,125,122,048 bytes). Measured directly via
`FuzzBuildExecCmdMemoryAgreement`, not derived on paper.

**A third convention exists.** `hyperlight.go:70-72` emits `--memory <raw bytes>`
with no unit conversion at all -- neither `bytesToMiB` nor `bytesToMB`. Whether
hyperlight's CLI expects bytes or MiB was not verifiable from this repo, so the
differential target deliberately does not model it. **Open question for whoever
picks this up:** if hyperlight expects MiB, a 1 GiB limit currently asks it for
1,073,741,824 MiB (~1 PiB). Worth checking before anything else in this file.

**A fix already exists in this repo and was never upstreamed:** commit `362633d` on
branch `backup/fuzz-prerebase-20260907`. It is correct in substance but its
`qemu_test.go` hunk predates the `0a0e809` CLI refactor and the `76142c5` test
update, so it must be re-applied by hand rather than cherry-picked.

Applying it today requires exactly four edits:
1. `utils.go` — `BytesToStringMB` calls `bytesToMiB`.
2. `utils.go` — delete `bytesToMB` (becomes dead; only caller was the line above).
3. `utils_test.go` — delete `TestBytesToMB` (its subject is gone; build breaks otherwise).
4. `qemu_test.go` — the case `"custom MemSizeB renders -m in MB"` feeds
   `512 * 1000 * 1000` and asserts `-m 512M`. Post-fix that input yields `-m 488M`.
   Change the input to `512 * 1024 * 1024` so it asserts the correct arithmetic.

Verified `cloud_hypervisor_test.go`, `spt_test.go`, `hvt_test.go` contain no
memory-size assertions, so nothing else breaks.

**Also fixes for free:** `chooseTmpfsSize` (`shared_fs.go:100`) calls the same helper.

---

## 3. Retired findings — do not re-chase

Every entry below was investigated, written up as a finding at some point, and then
**disproved** by tracing the actual call path. The "why it died" column is the part
that matters; without it these get rediscovered every few weeks.

| Former finding | The claim | Why it died |
|---|---|---|
| `setupDev` raw `filepath.Join` | Malicious image plants a symlink at `dev/null` inside the monitor rootfs; urunc's device writes follow it out | Every image-derived mount is re-rooted under `containerRootfsMountPath` = `/cntrRootfs` (`internal/constants/constants.go:21`). `filterBindMounts` (`shared_fs.go:121`) additionally SecureJoins spec-supplied destinations before re-prefixing. Nothing image-controlled ever lands at `monRootfs/dev/*`, so there is no symlink to follow. Also fails the trusted-input test. |
| Empty `UnikernelPath` → empty argv | An empty binary path produces a stray empty argv element | `validate()` (`annotations.go:120`) hard-fails creation when `UnikernelBinary == ""`, on both the spec path and the urunc.json path. `Map()` only writes the key when non-empty. Unreachable. |
| Config-source divergence (spec skips `decode()`, urunc.json corrupts plaintext) | Identical bytes yield different configs depending on source | **Already upstream as `#983`** (filed by `Shreshtthh`, closed 2026-08-18) — its body describes both directions with the same `"qemu" → garbage` example. Also neutralised by `81d15ab`, which added `validateValues()` + `allowedPathRe = ^[A-Za-z0-9._/-]+$`, rejecting both raw base64 and decoded garbage. |
| `decode()` non-atomic | A failed decode leaves the config half-rewritten | Fails the trusted-input test: `decode()` only errors on non-base64 input. Also inert — `GetUnikernelConfig` returns `nil, ErrNotUnikernel` on failure, discarding the partially-mutated struct. No caller can observe it. |
| Log subsystem forging | Guest-controlled log text forges a `subsystem` field in host logs | **The premise is false.** `ForwardLogs` has one call site (`create.go:180`). The pipe's write end goes only to the re-exec'd urunc child (`_LIBCONTAINER_LOGPIPE=4`, `create.go:318`) and is closed at `create.go:236` — before the VMM boots. The guest is not a writer and cannot be. |
| Oversized log line stops forwarding | A >64KiB line kills log forwarding and fails `urunc create` | Same premise failure as above: only urunc's own child and the nsenter helper write to that pipe, and they emit controlled JSON. |
| Zero-value log level panics | `{}` with no `"level"` hits `logrus.PanicLevel == 0` and aborts urunc | Correct mechanically, but same pipe — not guest-reachable, and requires malformed JSON from a trusted internal writer. Fails the trusted-input test. |
| `chooseTmpfsSize` unchecked `uint64` addition | `mem + (1024*1024)` can overflow | Arithmetically impossible. `mem` comes from `monitorMemoryBytes`, bounded by `*resources.Memory.Limit` (an `int64`, required `> 0`), so ≤ 9.22e18. `uint64` max is 1.8e19. |
| `readBlob` no digest verification / unbounded buffer | Reimplements containerd's `content.ReadBlob` without its size cap or digest check | Real divergence, and defensible as defense-in-depth — but fails the trusted-input test: it only matters if containerd hands back bytes that do not match what was requested. Under "containerd is trusted", it never fires. Keep only if the project decides to harden against a compromised dependency. `pkg/containerd-shim/containerd/annotations.go:131`. |
| Makefile `FUZZ_PKGS` excluded 10 of 27 targets from CI | urunc's CI silently skipped most fuzz targets | **This was our own bug.** `git log -S FUZZ_PKGS` points at our commit `ddc1d2b`. Upstream has no fuzzing infrastructure at all — no fuzz files, no `.clusterfuzzlite`, no fuzz workflow. Not a finding about urunc. |
| `.clusterfuzzlite` exists but never runs | Config present, no workflow invokes it | Same — that config is ours, staged and uncommitted on this branch. Nothing upstream. |
| Rumprun's repeated `"env"` JSON keys | Duplicate keys collide, silently dropping all but the last env var | The reference model was wrong. Rumprun's actual parser (`config.c`) is a linear token scanner, not a JSON decoder — it calls `putenv()` once per `"env"` occurrence, so repeated keys are the correct wire format, not a collision. Verified in Rumprun's own source, not assumed. See F7. |

**Findings that belong to upstream, not to us** (do not re-file, do not claim):
`#754` `IsIPInSubnet` fail-open · `#963`/`#909` `subnetMaskToCIDR` non-contiguous
masks · `#897` `parseCmdLine` quoting · `#867` `getMountInfo` unescaping · `#818`
`BytesToStringMB` (see F0) · `#983` config-source divergence · `#1010` partial
`extra_binaries`.

---

## 4. Target inventory, re-ranked

27 fuzz targets + 2 deterministic proof tests exist today. The ranking below reflects
the trusted-input rule, **not** the order they were written in.

### Tier 1 — where the remaining value is

| Target | Drives | Oracle today | Verdict |
|---|---|---|---|
| `FuzzBuildExecCmd` | all 5 backends' `BuildExecCmd` | empty-argv-element check only | **Oracle is too weak — rewrite.** It missed both F0 and F1 despite driving the exact code. Needs a cross-backend differential (§5.1). |
| `FuzzBuildUrunitConfig` | `linux.buildUrunitConfig` | env section round-trip | **Keep, extend to FreeBSD.** Proves F2. Add `freebsd.go` now that a second copy exists. |
| `FuzzBytesToStringMB` | `BytesToStringMB` | OCI byte limit vs. emitted value | **Keep.** Reproduces F0 from seed corpus alone. Becomes a regression guard once the fix lands. |
| `FuzzHookArgvConstruction` | hook argv construction (mirrored) | differential vs. OCI/runc argv | **New this pass.** Proves F5. Pure function, ~17k exec/sec. |
| `TestHookArgvZeroIsPath` | real `executeHook` | observed `$0` of the spawned process | **New this pass.** End-to-end proof of F5. |
| `TestHookExecutionOrderIsNotPreserved` | real `ExecuteHooks` | observed completion order | **New this pass.** Proves F4 against `config.md:589`. |
| `FuzzBuildExecCmdMemoryAgreement` | all modelled backends | requested bytes vs OCI limit | **New this pass.** Measures F0: +51,380,224 bytes at 1 GiB. |
| `FuzzBuildExecCmdCommandAgreement` | all modelled backends | argv-length delta, empty vs set `Command` | **New this pass.** Measures F1: deltas 0 vs 1. |
| `FuzzLinuxCmdlineEnvEncoding` | `(*Linux).CommandString` | env entry survives as exactly one kernel parameter | **New this pass.** Proves F6. Oracle models the kernel's ASCII-only splitting, not Go's. |

### Tier 2 — sound targets, keep running

Round-trip properties are inherently trusted-input properties: they assert that what
urunc wrote it can read back. They need no adversary to be meaningful.

| Target | Note |
|---|---|
| `FuzzUruncConfigMapRoundTrip` | proves F3 |
| `FuzzUruncConfigFromMap` | same family as F3 |
| `FuzzUnikernelConfigSpecRoundTrip` | sound |
| `FuzzStatePersistenceRoundTrip` | sound |
| `FuzzTryInitrd`, `FuzzTryExplicitBlock` | rootfs selection over legal configs |
| `FuzzSplitMountOptions`, `FuzzMapVFSFlag` | mount-option parsing over legal specs |
| `FuzzUnikernelInit`, `FuzzUnikernelNew` | structure-aware; **oracle is crash-only — strengthen** (see §6, and the 50% mutation score in §7) |

### Tier 3 — demote

Targets whose findings are upstream-owned. Keep as cheap regression guards; do not
invest further and do not present them as this project's findings.

`FuzzSubnetMaskToCIDR` (#963/#909) · `FuzzIsIPInSubnet` (#754) ·
`FuzzParseCmdLine` (#897) · `FuzzGetMountInfoMatcher` (#867)

### Retired — delete or mark clearly

These aim at malformed input, which the trust model puts out of scope. Keeping them
costs CI time and, worse, implies findings the project no longer stands behind.

`FuzzUnikernelConfigJSONDecode` (malformed JSON) ·
`FuzzUnikernelConfigDecodeAtomicity` (retired finding) ·
`FuzzUnikernelConfigDecodePlaintext` (#983, fixed) ·
`FuzzConfigSourceDivergence` (#983, fixed) ·
`FuzzSetupDevPathEscape` (retired finding) ·
`FuzzLogSubsystemForging` + `TestLogSubsystemForging` (false premise) ·
`FuzzProcessEntryLevel` + `TestForwardLogsOversizedLineStopsForwarding` (false premise) ·
`FuzzValidateID`, `FuzzParseSignal` (validation functions; their job *is* rejecting
malformed input, so the trust model makes them moot)

---

## 5. Targets to add

### 5.1 Cross-backend semantic differential on `BuildExecCmd` — DONE

> **Implemented** in `pkg/unikontainers/hypervisors/execcmd_differential_fuzz_test.go`
> as `FuzzBuildExecCmdMemoryAgreement` + `FuzzBuildExecCmdCommandAgreement`. Retained
> below as the design rationale. Remaining work: extend `extractMemBytes` to cover
> hyperlight once its unit is confirmed, and firecracker if its file I/O is factored
> out of `BuildExecCmd`.

This single target generalises both F0 and F1, and is the one the existing
`FuzzBuildExecCmd` should have been.

**Inputs:** a `types.ExecArgs` with legal values only — `MemSizeB` over realistic
byte ranges, `Command` over `""` and non-empty, `VCPUs ≥ 1`, plausible paths.

**Oracle:** for one fixed input, build the argv for every backend and assert they
*agree semantically*, not textually:
- the guest memory each backend ends up requesting, converted back to bytes, is
  within one unit-rounding step of `MemSizeB` — catches F0 and any future
  unit-conversion drift;
- either every backend passes a kernel command line or none does — catches F1;
- no backend emits an argv element that is empty when the corresponding input was
  non-empty.

**Why differential and not property-based:** there are five independent
implementations of the same logical operation. That is the ideal case for a
differential oracle — no need to encode what the right answer is, only that the five
must agree. Both real findings in this project came from exactly this shape.

### 5.2 Marker-injection corpus for `buildUrunitConfig`

**Input:** `spec.Process.Env` entries seeded directly with `\n`, `\r`, and the
literal marker strings `UES`, `UEE`, `UCS`, `UCE`, `UBS`, `UBE`.

**Oracle:** the env section parsed back out of the blob equals the entries that went
in, exactly.

**Why a seeded corpus rather than free-form fuzzing:** the interesting region is a
handful of specific byte patterns in an otherwise unbounded string space. Go's
mutator has no dictionary support, and did not assemble these shapes on its own
across a full campaign. Seed them; do not wait for search to find them.

### 5.3 Uncovered surface: `spec.Linux` security fields (S13) — next place to look

`Namespaces`, `Seccomp`, `RootfsPropagation`, and `Process.Capabilities` are read and
forwarded to libcontainer with no urunc-side assertion that what was requested is
what gets applied. No target touches any of them.

This is the same shape that produced F4/F5: pass-through data nobody writes
assertions about. The spec has testable MUSTs here too — e.g. a requested namespace
must actually be entered, and `Process.Capabilities` sets must not be silently
widened.

**Suggested oracle:** build the libcontainer config from a spec, then assert the
generated config's namespace/capability/seccomp sets are equal to what the spec
asked for — a translation-fidelity differential, not a behavioural test, so it needs
no privileges and no real container. Start by reading `libcontainer.go` /
`libcontainer_cgo.go`, and note that `libcontainer_cgo.go:76-77` already deletes
`Poststart`/`Poststop` from the libcontainer hook set, which is precisely the kind of
silent divergence this oracle would catch.

**Caveat before investing:** confirm each MUST against `config.md` and check the
tracker first. This surface is adjacent to seccomp work already in flight
(`#974`), so coordinate rather than duplicate.

### 5.4 Dotted-identifier table test for the config round trip

Input space is just "identifier strings, with and without `.`" — small enough that a
table-driven unit test dominates a fuzz target on cost. Assert `Map()` →
`UruncConfigFromMap` is lossless for any identifier the TOML parser accepts.

---

## 6. Oracle design rules

Derived from what actually worked here, not from general fuzzing advice.

1. **Differential beats property beats crash-only.** Where a redundant
   implementation exists (5 VMM backends, `Map`/`FromMap`, spec-vs-json), assert the
   implementations agree. You do not need to know the correct answer, only that
   disagreement is a bug.
2. **Crash-only oracles are near-worthless in Go.** The language is memory-safe; a
   target that only asserts "does not panic" has almost nothing to fail on. This is
   measurable — see §7.
3. **Round-trip properties are the best fit for a trusted-input model.** "What urunc
   wrote, urunc reads back identically" needs no adversary and no notion of
   malformed input.
4. **The oracle must reject the bug, not describe it.** `FuzzBuildExecCmd` drove the
   exact code containing F0 and F1 for 60 seconds at 4 cores and reported nothing,
   because its oracle only looked for empty argv elements. Coverage was never the
   limiting factor; the assertion was.
5. **Filter harness artefacts, not findings.** If an input is impossible on any real
   system, filter it in the harness and say why. Precedent: `FuzzSetupDevPathEscape`
   fired on a 300+ byte path component — `SecureJoin` correctly returned
   `ENAMETOOLONG` (POSIX `NAME_MAX` is 255) while a pure string join has no length
   limit. That was a harness bug, not a finding; the fix was a `len(s) > 255` guard
   with a comment explaining it.

---

## 7. Mutation testing — the suite-quality signal

Run with `make mutate` (gremlins). Requires `--timeout-coefficient 200`: urunc's test
binaries run in ~0.03s, and gremlins' default timeout derives from that baseline,
landing below Go's own compile time and reporting every mutant as `TIMED OUT`.

Measured, all four packages green at time of run:

| Package | Killed/Lived | Efficacy | Mutator coverage |
|---|---|---|---|
| `pkg/unikontainers` | 302/56 | 84.4% | 44.1% |
| `.../hypervisors` | ~~39/11~~ **54/2** | ~~78.0%~~ **96.43%** | ~~56.8%~~ 65.12% |
| `.../unikernels` | ~~31/31~~ **139/8** | ~~**50.0%**~~ **94.56%** | ~~50.8%~~ **94.84%** |
| `cmd/urunc` | 18/0 | 100.0% | 10.1% |

**`unikernels` at 50% was the finding.** Half of every mutant the existing tests
reached survived. Survivors were spread across all six unikernel type files
(`unikraft.go`, `rumprun.go`, `mirage.go`, `mewz.go`, `linux.go`), not concentrated in
one. Root cause was uniform: `FuzzUnikernelInit` asserted only "does not panic" across
all six types and checked nothing about the generated `CommandString`/`MonitorCli`
output.

This was the same crash-only-oracle gap that let F0 and F1 sit undetected in
`cloud_hypervisor.go` and `qemu.go`, and it is the strongest *methodological* result
this project produced: it demonstrated, with numbers, what the test suite could not
see — more useful to the maintainers than any individual bug above.

**Closed.** Content-assertion unit tests (`Test*` functions, not fuzz targets — see
§1: this class of check is deep, guest-type-specific correctness, not top-level input
exploration, so `known.Expected`/`f.Fuzz` was the wrong tool) were added for all six
guest types: `linux_test.go`, `rumprun_test.go`, `unikraft_test.go`, `mirage_test.go`,
`mewz_test.go`, `hermit_rs_test.go`. Each asserts exact output strings/structs
obtained by *running* the real code first, not hand-computed from reading it — caught
two hand-computation errors in the process of writing them (a `linux.go` console
string and a `unikraft.go` Sprintf spacing count), both fixed before landing.

Remaining 8 `LIVED` + 8 `NOT COVERED`, all outside the encoder surface these tests
target: `linux.go`'s `parseCmdLine` (multi-word quoting, upstream #897/finding-4,
already fuzzed separately) and `setupUrunitConfig` (real file I/O —
`initrd.AddFileToInitrd`, `createFile`), plus `utils.go:createFile`'s two I/O error
paths (unreachable without injecting a real filesystem failure). Not chased further
in this pass; a real gap, but a different kind of test (I/O-error injection) than the
content assertions this pass was built to add.

**Two corrections made after a plan self-review caught them, both now fixed:**
- `mewz_test.go`/`mirage_test.go` are upstream-authored (present in
  `upstream/main`). An earlier pass in this project had `Write`-overwritten both
  without checking for existing content first, deleting upstream's own test
  functions. Restored verbatim; this project's additions now live in separate,
  non-colliding functions appended after them (`TestMewzInit`,
  `TestMirageInitNetworkNaming`, etc.) — a maintainer reviewing this diff sees only
  additions, not their own tests replaced. One recreated case
  (`TestMirageInitSubnetMaskConversion`, written earlier to replace what the
  overwrite had deleted) was dropped as redundant once upstream's real
  `TestMirageInitSubnetMask` came back.
- `linux_test.go` had one case pinning upstream's own known bug (#754's fail-open
  behavior) as expected output. Removed — pinning a bug this project doesn't own
  means our test breaks the day upstream fixes it, which is friction, not
  robustness. (It was also a byte-for-byte duplicate of the file's first case, so
  no coverage was lost.)

The `unikernels` numbers above were re-measured after rebasing onto `upstream/main`
(bringing in `freebsd.go` + `freebsd_test.go`) and after the two corrections above —
94.56%/94.84% is the real current state, not a number computed on a stale tree.

**Not quite a bonus find:** while probing `Rumprun.CommandString()` for its exact
output, initially flagged what looked like a duplicate-JSON-key defect (repeated
`"env"` keys). Retired on closer inspection — Rumprun's actual parser handles
repeated keys correctly; see F7's retirement writeup in §3. Worth keeping as an
example of the reference-model rule catching its own motivating case, not just
someone else's mistake
to find everything.

`cmd/urunc`'s 100% is still a small sample: only 10.1% of the package is reachable by
the 4 targets that exist. Not addressed in this pass.

**`hypervisors` also closed in this pass: 78.0% → 96.43%** (54/2 killed/lived, up
from 39/11). `cloud_hypervisor_test.go` did not exist at all before this pass — 9 of
the original 11 survivors were there. Also added: `qemu.go`'s `runtime.GOARCH`
netdev-device branch (same untestable-on-amd64 pattern as `linux.go`'s console
string — pins the boundary on the reachable side rather than needing arm64
hardware), and `hyperlight.go`'s `MemSizeB > 0` boundary (a `uint64`, so `> 0` vs
`>= 0` only differ at exactly zero, which neither pre-existing case reached).

**The remaining 2 `LIVED` are genuinely equivalent mutants, verified by running
them, not assumed:** `cloud_hypervisor.go:150` and `qemu.go:126` are both
`len(x) > 0` guards immediately followed by `append(dst, x...)`. Appending zero
elements from an empty slice is byte-identical output whether the guard reads `> 0`
or `>= 0` — confirmed directly for both (`MonitorCliArgs{OtherArgs: []string{}}` and
`MonitorBlockArgs{ExactArgs: []string{}}` respectively produce identical argv either
way). No test can kill these because the two code paths are not actually
distinguishable at the output level. Recorded here rather than left unexplained, so
nobody spends time writing a test that structurally cannot pass.

---

## 8. The suppression mechanism

`known.Expected(t, id, shapeOK, format, args...)` in `tests/fuzzing/known/known.go`.

Go's engine has no concept of a known issue: the first time an oracle fires it stops
and persists the failing input as a *seed*, so every later run dies during baseline
before fuzzing starts. Quarantining the seed does not help — for a defect that fires
across a large fraction of the input space, mutation regenerates a failing input in
milliseconds. Measured before this existed: 11 of 35 targets were in this state,
several for 20+ consecutive rounds, each contributing zero executions.

`shapeOK` must be true **only** for the exact catalogued defect. A violation at a
known site whose shape does not match fails loudly as a new finding. This makes the
oracle *more* specific, not weaker: from "this property holds" to "this property
holds, except for the one precisely-characterised way it is already known to fail".

`Fired()` / `ReportTo()` expose hit counts. **A suppression with zero hits across a
full campaign is a signal that the underlying bug was fixed** and both the
suppression and its catalogue entry should be re-verified. Check this before trusting
any entry in §2.

For a finding that cannot be usefully fuzz-suppressed, use a deterministic test with
an **inverted** assertion — it must fail if the known symptom ever *stops*
reproducing. Do not use `known.Expected` there; it would pass silently whether or not
the symptom fired.

---

## 9. Verification log

Facts established by reading current code, with locations, so they can be rechecked.

- `allowedPathRe = ^[A-Za-z0-9._/-]+$` — `annotations.go:69`. Added by `81d15ab`
  ("fix(annotations): validate annotation values"); did not exist before it.
- `validateValues()` — `annotations.go:389`, called unconditionally from `Create()`
  at `unikontainers.go:99`, after `GetUnikernelConfig` returns, on both config paths.
- `validate()` (mandatory-field presence) — `annotations.go:120`.
- `GetUnikernelConfig` — `annotations.go:135`. Spec path returns before `decode()`;
  urunc.json path calls it. (This asymmetry is `#983`, now gated by `validateValues`.)
- `InitialSetup` — `unikontainers.go:165`. `setupMonitorRootfs` — `:567`.
  `applyMounts` runs at `:580`, `setupDevices` at `:587` — mounts before devices.
- `containerRootfsMountPath = "/cntrRootfs"` — `internal/constants/constants.go:21`.
- `filterBindMounts` — `shared_fs.go:121`: SecureJoins the spec destination, then
  re-roots under `containerRootfsMountPath`.
- `ForwardLogs` — one call site, `create.go:180`; write end passed only to the
  re-exec'd child (`_LIBCONTAINER_LOGPIPE=4`, `create.go:318`); closed `create.go:236`.
- `bytesToMiB` `utils.go:38` · `bytesToMB` `utils.go:43` · `BytesToStringMB`
  `utils.go:48` · firecracker's correct use `firecracker.go:122`.
- `decode()` — `annotations.go:276`, field-by-field, early return on first failure.
- `UruncConfigFromMap` — `urunc_config.go:233`, `if len(parts) != 4 { continue }`.

**Upstream state at time of writing:** urunc has no fuzzing infrastructure of any
kind. This suite is new ground, not a reimplementation.

**Campaign result:** all 27 targets, 60s each, `GOMAXPROCS=4`, ~28 min wall time —
zero failures beyond one harness false positive (the `NAME_MAX` case in §6.5), which
was fixed and re-verified against the 104 pre-existing corpus entries.
