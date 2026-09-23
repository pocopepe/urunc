# Phase 2 proposal — fortifying urunc's implicit input surfaces

Companion to `tests/fuzzing/FUZZING_FINDINGS.md`, which holds the verified finding
catalogue, the input-surface map, and the current target inventory. **Read that file
first.** This one says what to build next and how.

**Two audiences.** Sections 1–3 argue the plan (for mentors/maintainers). Sections
4–7 are an implementation spec precise enough to code from without re-deriving
anything.

---

## 1. Thesis

> **urunc is a transcoder, and its bugs live where it re-encodes a value into a
> format that a different codebase parses.**

urunc's job is translation: OCI spec in; monitor command lines, guest config blobs
and libcontainer configs out. Wherever it must *interpret* a value it validates
carefully — `getDNSServer` parses `resolv.conf` with `net.ParseIP`, a `To4()` check
and an `IsLoopback()` rejection. Wherever it merely *relays* a value into another
format, it concatenates and hopes. Relaying is where semantics are lost, and Go's
type system cannot help, because both sides are `string`.

The structural reason these bugs survive: on a cross-codebase format boundary, **no
compiler, type checker, or test in either codebase validates the contract**. Each
side is individually well-tested; the contract between them is untested by
construction. Nine of the eleven catalogued findings sit on exactly such a boundary —
including findings this project did not discover, which is the test of a thesis
rather than a restatement of it.

*(An earlier version of this proposal argued "urunc validates config but not
pass-through data". That was falsified by `getDNSServer` and discarded. The full
derivation, including the falsification, is `FUZZING_FINDINGS.md` §1.2.)*

### 1.1 Why the surface is large

Encoding responsibility is **split across two interfaces**, so neither side owns a
whole contract. `types.Unikernel` exposes five encoder methods (`CommandString`,
`MonitorNetCli`, `MonitorBlockCli`, `MonitorSharedfsCli`, `MonitorCli`);
`types.VMM.BuildExecCmd` consumes their fragments and assembles the result. There are
**7 monitors × 7 guest types**, and the cross product is real — guest encoders branch
on which monitor they are paired with (`linux.go` does so 9 times, `freebsd.go` 6).

F1 is a textbook split-responsibility failure: the monitor decides whether to emit
the `-append` pair, the guest decides what `Command` holds, and neither owns "is an
empty command line meaningful".

## 2. Evidence the thesis works

It was used to *predict* a bug, not just explain old ones. The map says the
highest-risk cell is the guest encoder with the most monitor-conditional branching,
in the package with the worst mutation score: `linux.go`. Looking there produced
**F6** — `spec.Process.Env` space-joined into the guest kernel command line, where an
ordinary value like `A=1 root=/dev/sda1` appends a second `root=` *after* urunc's
own, and the kernel honours the last occurrence. Measured, then fixed into a target.

| Finding | urunc encodes | consumed by | status |
|---|---|---|---|
| F0 `#818` | bytes → `"N"` | qemu, CH, solo5 | **measured**: +51,380,224 bytes at 1 GiB |
| F1 | `Command` → flag pair | qemu, CH, solo5 | **measured**: deltas 0 vs 1 |
| F2 | env → marker blob | urunit (separate repo) | reproduced |
| F4 | hook list → order | OCI `config.md:589` | **measured**: order inverted |
| F5 | `hook.Args` → argv | POSIX `execv` | **measured**: observed `$0` |
| F6 | env → kernel cmdline | Linux `kernel/params.c` | **measured**: boot param overridden |

Findings written under adversarial framing all collapsed when traced — and that
framing is one maintainers have rejected in writing (`ananos`, closing `#797`:
*"a container image cannot define hooks… whoever can set a hook is already executing
arbitrary binaries"*). Transcoding framing is falsifiable, verifiable from the
consumer's own documentation, and does not depend on an attacker existing.

## 3. The two rules that govern all Phase 2 work

**Rule 1 — the trusted-input test.** Before writing a target, answer:

> If every input were 100% trusted and well-formed, would this bug still fire?

**YES** → in scope. **NO** → out of scope, however severe it sounds. urunc trusts
containerd and trusts the spec.

**Rule 2 — oracle doctrine.** Differential > property > *never* crash-only.

Crash-only oracles ("does not panic") are near-worthless in a memory-safe language.
This is measured, not asserted: the package where crash-only oracles dominate scores
**50% mutation efficacy** — half of every mutant the tests reach survives. Decisive
proof: `FuzzBuildExecCmd` drove the exact code containing F0 and F1 for a full 60s
campaign at 4 cores and reported nothing, because its oracle only checked for empty
argv elements. **Coverage was never the limiting factor. The assertion was.**

---

## 4. Work items

Ordered by value. Each is independently shippable.

### W1 — Resolve the hyperlight memory unit (blocking, do first)

**Why first:** it is either a severe live bug or nothing, and the answer changes W1's
own scope. `hyperlight.go:70-72` emits `--memory <raw bytes>` with **no unit
conversion at all** — a third convention alongside `bytesToMiB` (firecracker) and
`bytesToMB` (everyone else). If hyperlight's CLI expects MiB, then a 1 GiB OCI limit
currently requests **1,073,741,824 MiB ≈ 1 PiB**.

**Do:**
1. Determine hyperlight's actual `--memory` unit from its upstream source or docs.
   Do not guess; cite what you found.
2. If it expects MiB → this is a new finding. Add it to `FUZZING_FINDINGS.md` as **F7**
   (F6 is taken — see the cmdline finding) with the same evidence standard as F0–F6, and extend `extractMemBytes` in
   `pkg/unikontainers/hypervisors/execcmd_differential_fuzz_test.go` to cover it with
   a `known.Expected` suppression.
3. If it expects bytes → hyperlight is correct. Record that in the comment inside
   `extractMemBytes` (which currently says the unit was unverifiable) and add it to
   the differential as a *passing* backend.

**Acceptance:** `extractMemBytes` no longer has an "unverified" branch, and the doc
states the answer with a citation.

### W2 — Rebase forward, then extend `FuzzBuildUrunitConfig` to FreeBSD

**Why:** F2's serializer was duplicated into `unikernels/freebsd.go:269` by commit
`c5eb1cd`. That file does not exist in this worktree yet — the branch is 9 commits
behind `upstream/main`.

**Do:**
1. Rebase `feat/315-fuzzing-harnesses` onto `upstream/main`. Create a backup branch
   first (`backup/fuzz-prerebase-<date>`), matching the existing convention.
2. Re-run the full suite; confirm still green before touching anything.
3. Extend `FuzzBuildUrunitConfig` (`pkg/unikontainers/unikernels/urunit_fuzz_test.go`)
   to drive `freebsd.go`'s `buildUrunitConfig` with the same oracle.
4. If FreeBSD's serializer diverges from Linux's in how it escapes/handles values,
   that is itself a finding — two copies of one format that disagree.

**Acceptance:** both serializers driven by one target; `finding-3` suppression fires
for both or the divergence is documented.

### W3 — Marker-injection corpus for `buildUrunitConfig`

**Why:** F2's *proven* scope is limited to env-section corruption. Whether a forged
marker can corrupt a *later* section (process config, block devices) is **unverified
and must not be claimed** without evidence — urunit's parser is a separate guest-side
component not in this repo.

**Do:**
1. Seed a corpus directly with `\n`, `\r`, and the literal marker strings `UES`,
   `UEE`, `UCS`, `UCE`, `UBS`, `UBE` embedded in env values. Go's mutator has no
   dictionary support and did not assemble these shapes unaided across a full
   campaign — seed them, don't wait for search.
2. Oracle: the env section parsed back out equals the entries that went in, exactly.
3. **If** you can obtain urunit's parser source, extend the oracle to whole-blob
   structural integrity and settle the open question. Otherwise leave it open and say
   so.

**Acceptance:** corpus committed under `testdata/fuzz/`; the doc's "not proven"
caveat on F2 either stays or is replaced by evidence.

### W4 — New surface: `spec.Linux` → libcontainer translation fidelity (S13)

**Why:** `Namespaces`, `RootfsPropagation` and `Process.Capabilities` are forwarded
into libcontainer with no urunc-side assertion that what was requested is what gets
applied. No target touches any of them. Same shape as F4/F5: pass-through nobody
asserts about.

**Important — do not mis-frame this.** `libcontainer_cgo.go` deliberately drops some
things and **documents why**: `config.Seccomp = nil` (urunc applies monitor-specific
filters instead) and `delete(config.Hooks, Poststart/Poststop)` (urunc runs those
itself, in `start` and `delete`). Those are decisions, not bugs — do not report them.
The one acknowledged gap is the wildcard device rule, which carries its own
`TODO: Revisit this in the future and apply a stricter model`.

**Do:**
1. Read `pkg/unikontainers/libcontainer_test.go` first — `TestBuildContainerConfig`
   already exists. Extend it rather than duplicating it.
2. Target `BuildContainerConfig(systemdCgroup bool) (*configs.Config, error)` in
   `libcontainer_cgo.go`. **Note the `//go:build cgo` tag** — your test file needs it
   too, or it silently won't build.
3. Oracle — translation fidelity, per field:
   - every namespace in `spec.Linux.Namespaces` appears in `config.Namespaces`;
   - `Process.Capabilities` sets are never *widened* by translation;
   - `RootfsPropagation` survives;
   - mount order is preserved (`config.md:66` — "The runtime MUST mount entries in
     the listed order").
   Assert on the generated config struct. No privileges, no real container.
4. Anything that fails and is *not* one of the documented drops above is a finding.

**Acceptance:** a target covering at least namespaces + capabilities + mount order;
any divergence written up to the F-series evidence standard.

### W5 — Strengthen the `unikernels` oracles (attack the 50%)

**Why:** `unikernels` scores 50% mutation efficacy, and the survivors are spread
across all six unikernel type files, not concentrated. Root cause is uniform:
`FuzzUnikernelInit` asserts only "does not panic" and checks nothing about the
generated `CommandString()`/`MonitorCli()` output.

**Do:**
1. Replace the crash-only assertion with content assertions: for a given
   `UnikernelParams`, the generated command string must contain the values that went
   in (block IDs, mount points, net device names) and must not contain values that
   did not.
2. Prefer a differential where one exists: several unikernel types build
   structurally similar command lines from the same params.
3. Re-run `make mutate` and report the delta.

**Acceptance:** `unikernels` efficacy materially above 50%, with before/after numbers
in the doc. If it does not move, say so and explain why — a negative result honestly
reported is worth more than a number that was gamed.

### W5b — Propose the F6 fix upstream-ready

**Why:** F6 (env space-joined into the guest kernel command line) is the surviving
half of the bug class PR `#858` already eliminated on the monitor side. That makes it
an easy argument: the project has already decided this pattern is wrong, and one
half was missed.

**Do:**
1. Decide the remedy. Two defensible options, pick one and say why:
   - reject env entries containing ASCII space/tab on the non-urunit Linux path,
     failing container creation with a clear error; or
   - stop putting env on the kernel command line at all for this path, matching what
     the urunit path already does.
   Option (a) is smaller and cannot break a working deployment silently; option (b)
   is the real fix but changes how guests receive env.
2. Note the ordering issue in whatever you write up: urunc appends env **after** its
   own boot parameters, and the kernel honours the last occurrence — so this is not
   merely a dropped variable, it is a silent override of `root=`, `init=`, `console=`
   and `panic=`.
3. Keep `FuzzLinuxCmdlineEnvEncoding` green by updating the `finding-cmdline-env-split`
   suppression when the fix lands (the suppression going quiet is the signal, §8).

**Acceptance:** a minimal diff plus the target demonstrating the before/after.

### W6 — Retire the out-of-scope targets

**Why:** they aim at malformed input, which Rule 1 puts out of scope. They cost CI
time and, worse, imply findings this project no longer stands behind.

**Delete** (rationale for each is in `FUZZING_FINDINGS.md` §3 — read it before
deleting, and preserve any suppression IDs still referenced):

```
FuzzUnikernelConfigJSONDecode          FuzzConfigSourceDivergence
FuzzUnikernelConfigDecodeAtomicity     FuzzUnikernelConfigDecodePlaintext
FuzzSetupDevPathEscape                 FuzzValidateID
FuzzLogSubsystemForging                TestLogSubsystemForging
FuzzProcessEntryLevel                  TestForwardLogsOversizedLineStopsForwarding
FuzzParseSignal
```

**Acceptance:** suite still green; `Makefile` `FUZZ_PKGS` still correct; target count
and §4 inventory updated in the doc.

### W7 — Re-apply the `#818` fix

Agreed upstream (maintainer `cmainas`: *"Ok, then we can use MiB for all of them."*),
never implemented. A correct fix exists at `362633d` on
`backup/fuzz-prerebase-20260907` but **cannot be cherry-picked** — its `qemu_test.go`
hunk predates `0a0e809` and `76142c5`.

**Four edits, all in `pkg/unikontainers/hypervisors/`:**
1. `utils.go` — `BytesToStringMB` calls `bytesToMiB` instead of `bytesToMB`.
2. `utils.go` — delete `bytesToMB` (its only production caller was that line).
3. `utils_test.go` — delete `TestBytesToMB` (its subject is gone; the build breaks
   otherwise).
4. `qemu_test.go` — the case `"custom MemSizeB renders -m in MB"` feeds
   `512 * 1000 * 1000` and asserts `-m 512M`. Post-fix that input yields `-m 488M`.
   Change the input to `512 * 1024 * 1024` and rename to `…in MiB`.

Verified: `cloud_hypervisor_test.go`, `spt_test.go`, `hvt_test.go` contain no
memory-size assertions. `chooseTmpfsSize` (`shared_fs.go`) is fixed for free.

**Acceptance:** `FuzzBuildExecCmdMemoryAgreement`'s `finding-7` suppression stops
firing — which is the signal described in `FUZZING_FINDINGS.md` §8 that a finding is
fixed and its catalogue entry needs updating.

### W8 — Re-measure

After W5 and W7, re-run `make mutate` (remember `--timeout-coefficient 200`; urunc's
~0.03s test binaries make gremlins' default timeout shorter than Go's compile time,
reporting every mutant as `TIMED OUT`). Update the table in §7 of the findings doc.

---

## 5. Anti-goals

Do **not**:

- Write a target whose oracle is "does not panic". Rule 2.
- Write adversarial framing — "a malicious image could…". It has been rejected by
  maintainers in writing and every finding built on it collapsed.
- Re-chase anything in `FUZZING_FINDINGS.md` §3. Each entry records why it died.
- Re-file anything in the upstream-owned list (`#754`, `#963`/`#909`, `#897`, `#867`,
  `#983`, `#1010`, `#700`).
- Claim reachability you have not traced end to end. Three separate findings in this
  project asserted a data path that did not exist.
- Target `readBlob`'s missing digest check or `decode()`'s non-atomicity. Both fail
  Rule 1 — recorded in §3 with reasoning.

## 6. Working agreement for whoever implements this

1. **Never commit or push.** `git add` only. No `git commit`, no `git push`, no
   upstream issue or PR comments. This is a standing instruction with no exceptions.
2. **Verify every oracle actually fires.** A green fuzz target is ambiguous: it means
   either "bug detected and suppressed" or "oracle never fired". Prove which. Method
   that worked here: a temporary throwaway test that prints the values the oracle
   compares, run once, then deleted. Do not skip this — it is the exact failure that
   let `FuzzBuildExecCmd` sit on top of two real bugs.
3. **Use `known.Expected(t, id, shapeOK, …)` for known findings.** `shapeOK` must be
   true *only* for the exact catalogued defect, so a different bug at the same site
   still fails loudly. For findings that cannot be usefully fuzz-suppressed, use a
   deterministic test with an **inverted** assertion — it must fail if the symptom
   ever stops reproducing. Never `known.Expected` there; it would pass either way.
4. **Derive reference models from the consumer, never from urunc.** A differential
   oracle is only as good as its model of the far side. Both oracles written in the
   last pass produced false findings before this rule was applied: one used
   `len(strings.Fields(entry))>1` as a whitespace proxy (`Fields` strips leading
   whitespace, so `" ="` slipped through); the other verified with Unicode-aware
   `strings.Fields` when the Linux kernel splits on ASCII space/tab only, flagging
   `"=\u2000"` as a bug it is not. Put the model in a **named function with its
   source cited** (`kernelFields`, `ociHookArgv`, `extractMemBytes`) so the
   assumption is reviewable. Derive it from urunc's own encoder and the test asserts
   only that the code does what the code does.
5. **Mirror, don't extract.** When a target needs production logic, copy it into the
   test with a comment saying it is a mirror and must be updated in lockstep. Keeps
   the harness from forcing production changes. Precedent: `rawDeviceJoin`,
   `uruncHookArgv`, `extractMemBytes`.
6. **Filter harness artefacts, and say why in a comment.** If an input is impossible
   on any real system, filter it. Precedent: `FuzzSetupDevPathEscape` fired on a
   300+ byte path component where `SecureJoin` correctly returned `ENAMETOOLONG`
   (POSIX `NAME_MAX` is 255) — a harness bug, not a finding.
7. **Keep the suite green.** Mutation testing aborts coverage gathering if any test
   fails, so a red package disables the quality gate entirely.
8. **Separate what you ran from what you read.** Update §0.5 of the findings doc
   accordingly. Never present a reasoned consequence as an observed one.

## 7. Definition of done

- [ ] W1 answered with a citation; `extractMemBytes` has no unverified branch.
- [ ] W2 rebased, suite green, both urunit serializers covered.
- [ ] W3 corpus seeded; F2's open question either settled with evidence or still
      explicitly marked open.
- [ ] W4 target landed for S13; documented drops **not** reported as bugs.
- [ ] W5 `unikernels` efficacy re-measured, before/after in the doc.
- [ ] W6 retired targets deleted, inventory updated.
- [ ] W7 four edits applied, `finding-7` suppression stops firing.
- [ ] W8 mutation table refreshed.
- [ ] `go build ./...`, `go vet ./...`, full `go test` all clean.
- [ ] `FUZZING_FINDINGS.md` updated: findings, inventory, §0.4 manifest, §0.5
      run-vs-read status.
- [ ] Everything staged, nothing committed.
