Two git worktrees, same repo:
- /home/pocopepe/contrib/urunc-fuzz (branch feat/315-fuzzing-harnesses) — all fuzz code, tests/fuzzing/FUZZING_FINDINGS.md, tests/fuzzing/PHASE2_PROPOSAL.md
- /home/pocopepe/contrib/urunc (branch 852-fuzzing-phase1-report) — PHASE1_REPORT.tex, the Phase 1 mentorship deliverable, due 2026-09-27

STANDING RULE, NO EXCEPTIONS: never `git commit`, never `git push`, never comment on
a GitHub issue or PR. `git add` only. Everything you do stays as staged,
uncommitted working-tree state.

Read tests/fuzzing/FUZZING_FINDINGS.md in full before touching anything. It is the
verified finding catalogue — every claim in it was either measured by running code
or explicitly marked as reasoned-not-observed. Read tests/fuzzing/PHASE2_PROPOSAL.md
second; it's the work-item spec these tasks come from (W1-W8).

Do the tasks below in this exact order. Do not skip ahead to a later task because it
looks easier — the ordering reflects what's actually blocking, not a preference.

---

TASK 0 (do this first, it has a deadline the others don't): PHASE1_REPORT.tex is
stale — last edited 2026-09-14, before F4/F5/F6 existed and before F1/F0 were
measured. It still lists "setupDev raw filepath.Join" as the #1 "Top priority —
security-relevant" finding. That finding is DISPROVEN: FUZZING_FINDINGS.md section
3 traces the exact reason (every image-derived mount is re-rooted under
/cntrRootfs before setupDev ever runs, so there's no reachable symlink). Submitting
the report as it stands means presenting a refuted finding as the headline result.

Rewrite the report's findings section from tests/fuzzing/FUZZING_FINDINGS.md
sections 1-3 (the live findings F0-F6, each with its trusted-input-test verdict and
verification status) and section 3 (retired findings, so the report can explicitly
say what was investigated and ruled out rather than silently dropping it). Concretely:

- Drop the "Top priority — security-relevant" framing entirely. Every finding that
  survived scrutiny is a conformance or correctness bug, not a security
  vulnerability, and adversarial framing ("a malicious image could...") has been
  explicitly rejected by an urunc maintainer in writing (ananos, closing #797:
  "a container image cannot define hooks... whoever can set a hook is already
  executing arbitrary binaries"). Frame findings the way FUZZING_FINDINGS.md does:
  cite the spec line (config.md:589, config.md:555) or the measured divergence,
  not a hypothetical attacker.
- Lead with the two findings that have a spec citation and a number: F4 (hooks
  execute concurrently, violating "Hooks MUST be called in the listed order")
  and F5 (hook argv[0] replaced with path, violating execv semantics). Both are
  proven by a real running test, not just read from the code — say so.
  Then F0 (#818, already agreed upstream, measured +51,380,224 bytes at 1 GiB)
  and F1 (empty Command divergence, measured argv-length deltas 0 vs 1). Then F6
  (env space-joined into the guest kernel command line — mention it's the
  surviving half of a bug class PR #858 already fixed on the monitor side).
  F2 and F3 after that.
- Add a short "investigated and ruled out" list from FUZZING_FINDINGS.md section 3
  — the setupDev finding, the empty-UnikernelPath finding, the config-source
  divergence (now closed as #983), decode() non-atomicity, the two log-forwarding
  findings (their premise was false — the pipe's write end never reaches the
  guest). This is not padding: showing what was checked and ruled out is more
  credible than a list that only ever grows.
- Add the mutation-testing result (unikernels package, 50% efficacy, systemic
  across all 6 unikernel type files, crash-only-oracle gap) as its own point. It's
  evidence about what the suite can't see, which is a stronger Phase 1 result than
  any single bug.
- State plainly that the fuzz suite currently has 29 targets (after retiring 11
  that were aimed at malformed input, which the project's trust model puts out of
  scope — see FUZZING_FINDINGS.md section 1 for the exact rule used to decide
  that), and that a background campaign (12 cores, cycling all targets, running
  since [give the actual start time you observe]) has found zero new issues beyond
  what's already catalogued.

Recompile with pdflatex (twice, for cross-references), fix any overfull hbox by
rephrasing rather than relying on \- (this document's history shows \- does not
reliably fix long identifiers in tables), then actually render pages to PNG with
mutool draw and Read them to visually confirm no overflow before calling this done.
Do not claim the report is fixed without having looked at the rendered pages.

---

TASK 1: Fix #818 (W7 in PHASE2_PROPOSAL.md). Agreed upstream by the maintainer
("Ok, then we can use MiB for all of them"), never implemented. Four edits in
pkg/unikontainers/hypervisors/:
1. utils.go — BytesToStringMB calls bytesToMiB instead of bytesToMB.
2. utils.go — delete bytesToMB (its only production caller was that line).
3. utils_test.go — delete TestBytesToMB (its subject is gone, build breaks
   otherwise).
4. qemu_test.go — the case "custom MemSizeB renders -m in MB" feeds
   512*1000*1000 and asserts "-m 512M". Post-fix that yields "-m 488M". Change
   the input to 512*1024*1024, rename the case to "...in MiB".

After the fix, run FuzzBuildExecCmdMemoryAgreement and confirm the
finding-7 known.Expected suppression stops firing (zero hits in Fired()) — that's
the signal the fix worked, per FUZZING_FINDINGS.md section 8. Update F0's status
in FUZZING_FINDINGS.md to fixed, with the suppression-stopped evidence.

---

TASK 2: Resolve the hyperlight memory unit (W1). hyperlight.go:70-72 emits
"--memory <raw bytes>" with no conversion — a third convention alongside
bytesToMiB and bytesToMB. Find hyperlight's actual --memory unit from its
upstream source or docs, cite what you found (a source link or file:line, not a
guess). If it expects MiB, this is a new finding — add it to FUZZING_FINDINGS.md
as F7 (F6 is taken) with the same evidence standard as the others (measured, not
argued), and extend extractMemBytes in
pkg/unikontainers/hypervisors/execcmd_differential_fuzz_test.go to cover it with
a known.Expected suppression. If it expects bytes, hyperlight is correct — say so
in extractMemBytes's comment (it currently says the unit is unverifiable) and add
it to the differential as a passing backend.

---

TASK 3: Fix F6 (W5b). spec.Process.Env is space-joined into the Linux guest
kernel command line with no escaping (linux.go:111), and the kernel takes the
LAST occurrence of a repeated parameter — so an ordinary env value can silently
override root=, init=, console=, or panic=. Pick one fix and say why:
(a) reject env entries containing ASCII space/tab on this path, failing
    container creation with a clear error, or
(b) stop putting env on the kernel command line for this path at all, matching
    what the urunit path already does.
(a) is smaller and can't silently break a working deployment; (b) is the more
complete fix but changes how guests receive env. After the fix, confirm
FuzzLinuxCmdlineEnvEncoding's finding-cmdline-env-split suppression stops firing.
Update F6's status in FUZZING_FINDINGS.md.

---

TASK 4: Rebase feat/315-fuzzing-harnesses onto upstream/main (W2). Create a
backup branch first (backup/fuzz-prerebase-<today's date>, matching the existing
naming convention — check `git branch -a` for backup/fuzz-prerebase-20260907).
Re-run the full suite, confirm still green, before doing anything else. This
branch is currently 9 commits behind upstream/main, and one of those commits
(c5eb1cd) adds unikernels/freebsd.go, which has a second copy of F2's
env-serializer — it doesn't exist in this worktree yet, which is why the next
task is currently impossible.

---

TASK 5: Extend FuzzBuildUrunitConfig to freebsd.go (W3 depends on this being
possible — do it after Task 4). Drive both linux.go's and freebsd.go's
buildUrunitConfig with the same oracle. If they diverge in how they escape or
handle values, that divergence is itself a finding.

Then seed a corpus directly with \n, \r, and the literal marker strings UES, UEE,
UCS, UCE, UBS, UBE embedded in env values (W3). Go's mutator has no dictionary
support and didn't find these unaided across a full campaign — seed them, don't
wait for search. If you can find urunit's parser source, use it to settle F2's
open question (can a forged marker corrupt a later section, not just the env
section) with evidence. If you can't find it, leave the question explicitly open
in the doc rather than guessing.

---

TASK 6: New target for spec.Linux -> libcontainer translation fidelity (W4).
Read pkg/unikontainers/libcontainer_test.go first (TestBuildContainerConfig
already exists — extend it, don't duplicate it). Target
BuildContainerConfig(systemdCgroup bool) in libcontainer_cgo.go. It's
//go:build cgo — your test file needs that tag too or it silently won't build.

Do NOT report these as bugs, they're documented decisions: config.Seccomp = nil
(urunc applies monitor-specific filters instead), and
delete(config.Hooks, Poststart/Poststop) (urunc runs those itself). The one
acknowledged gap is the wildcard device rule, which carries its own
"TODO: apply a stricter model" comment.

Oracle: translation fidelity per field — every namespace in
spec.Linux.Namespaces appears in config.Namespaces; Process.Capabilities sets
are never widened by translation; RootfsPropagation survives; mount order is
preserved (config.md:66, "The runtime MUST mount entries in the listed order").
Assert on the generated config struct directly. No privileges, no real
container needed.

---

TASK 7: Strengthen the unikernels crash-only oracle (W5). FuzzUnikernelInit
asserts only "does not panic" across all 6 guest types and checks nothing about
generated CommandString()/MonitorCli() output — this is why the package scores
50% mutation efficacy. Replace with content assertions: for given
UnikernelParams, the generated command string must contain the values that went
in (block IDs, mount points, net device names) and must not contain values that
didn't. Prefer differential where a structural similarity exists across guest
types. Re-run `make mutate` after (needs --timeout-coefficient 200, already in
the Makefile) and report the before/after efficacy number. If it doesn't move,
say so honestly and explain why — don't game the number.

---

WORKING RULES, apply to every task above:

1. Verify every oracle actually fires before trusting a green result. A green
   fuzz target is ambiguous — "bug detected and suppressed" or "oracle never
   ran" look identical. Method that's worked in this project: write a throwaway
   test that prints the actual values being compared, run it once, delete it.
   This caught two false findings in this project already (both from an oracle's
   reference model not matching the real consumer) — don't skip this step.

2. Derive a differential oracle's reference model from the CONSUMER's own
   specification (its docs, its source, the OCI spec text), never from urunc's
   own encoder and never from whatever the standard library makes convenient.
   Concrete failure mode already hit in this project: using Go's
   Unicode-aware strings.Fields to check what the Linux kernel (ASCII-only
   space/tab splitting) would do — flagged a non-bug. Put the reference model in
   a named function with its source cited in a comment.

3. Apply the trusted-input test before writing any new target: "if every input
   were 100% trusted and well-formed, would this bug still fire?" If no, it's
   out of scope regardless of how severe it sounds. urunc trusts containerd and
   trusts the OCI spec.

4. Never frame a finding adversarially ("a malicious image could..."). Cite a
   spec line, a measured divergence, or a maintainer's own words instead.

5. Use known.Expected(t, id, shapeOK, ...) for known findings — shapeOK must be
   true ONLY for the exact catalogued shape, so a different bug at the same site
   still fails loudly. For findings proven by a deterministic test rather than a
   fuzz target, invert the assertion (fail if the symptom ever STOPS
   reproducing) — never use known.Expected there, it would pass either way.

6. Keep the suite green after every task. Mutation testing aborts entirely if
   any test fails, so a red package disables the quality gate for everything,
   not just the package you touched. Run `go build ./...`, `go vet ./...`, and
   `go test ./pkg/... ./cmd/...` (not ./... — that pulls in tests/e2e, which
   needs a real containerd socket and will fail in any sandbox for reasons
   unrelated to your changes) after every task, before moving to the next.

7. Update tests/fuzzing/FUZZING_FINDINGS.md as you go — section 0.4 (file
   manifest), section 0.5 (what's verified-by-running vs read-only), and each
   finding's status. Don't let the doc drift stale the way the report did.

8. A background loop (GOMAXPROCS=12, cycling all targets, 5 min each) may
   already be running against this same worktree. Don't kill it. It writes only
   corpus files under testdata/fuzz/ and doesn't touch source — safe to work
   alongside.

Report back after each numbered task with: what you changed, what you ran to
verify it, and the actual output of that verification (not a paraphrase of it).
