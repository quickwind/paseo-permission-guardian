# ADR-0009: Uncommitted Deletes Require a Human; Committed Files Stay L0

- **Status**: Accepted
- **Date**: 2026-11-23
- **Supersedes**: —
- **Superseded by**: —
- **Extends**: [ADR-0008](./0008-act-mode-evidence-gate.md)

## Context

Until now a non-recursive delete inside the worktree (`delete_worktree` without `recursive`) was
L0, so in `act` mode the plugin could auto-allow `rm notes.txt`. For a file whose content is in a
git commit that is recoverable (`git checkout -- <path>`). For an untracked, ignored, modified or
staged file the content exists nowhere else, so the delete is irreversible. After testing, the
user decided: *uncommitted files ask the human; files committed in git stay L0.*

The engine is deterministic and replay (ADR-0008) re-evaluates recorded history with the current
engine. Git state changes over time, so replay cannot ask git again and still be deterministic.

## Decision

1. A non-recursive `delete_worktree` effect is L0 only if **every** target is a regular tracked
   index entry (`git ls-files -v` tag `H`) for which `git status --porcelain=v1
   --untracked-files=all --ignored=matching` reports nothing (worktree and index equal HEAD).
   Otherwise the decision is at least L1 with reason `delete_uncommitted:<target>`. Untracked,
   ignored, modified, staged, assume-unchanged/skip-worktree, a directory, a target outside the
   worktree root or the repository (including temp-dir targets), not a repository, git missing, a
   timeout, an abort or any error ⇒ not clean (fail to human). Recursive deletes are unchanged.
   This applies to every path that yields `delete_worktree`: bash/sh `rm`, PowerShell
   `Remove-Item` and aliases, cmd `del`/`erase`, and the provider `delete` action kind, at any
   shell layer.
2. The lookup lives in `server/context/git-state.ts`: `execFile("git", …)` (no shell), cwd under
   the worktree root, `GIT_OPTIONAL_LOCKS=0`, `GIT_LITERAL_PATHSPECS=1`, a shared 1500 ms budget
   per request, and the hook's `AbortSignal`. It is injectable (`gitStateProvider` on the decide
   options / guardian options) so tests do not shell out. `decideAction` never spawns git by
   itself: without a provider every target is not clean.
3. The live decision records the per-target result in the audit record as
   `contextSnapshot.deleteTargetsClean: Record<redactedTarget, boolean>` (keys redacted like other
   paths; on a key collision `false` wins). Replay passes the recorded map and **never calls git**;
   a missing key ⇒ not clean (L1). Results are not cached anywhere else (no cross-state caching).
4. `ENGINE_DATA_VERSION` becomes 2, so an existing latch does not outlive the old rule.

## Consequences

### Positive

- Irreversible loss of uncommitted work always involves the human, including in `act` mode.
- Replay stays deterministic and offline; old records without the map replay as L1, which can only
  remove samples, never add a false allow.

### Negative / Trade-offs

- One to three short `git` processes per delete request (bounded by 1500 ms).
- Replay keys on the effect target. The live target is host-realpath-resolved while replay skips
  host realpaths, so a worktree reached through a symlinked directory replays as L1 (fewer samples;
  safe direction).
- More deletes reach the human than before (e.g. deleting a freshly created scratch file).

### Follow-up / Guardrails

- Tests: tracked-clean ⇒ L0; untracked/modified/staged/ignored/not-a-repo/error/timeout ⇒ L1;
  multi-target with one dirty ⇒ L1; each delete syntax; replay uses the record and never spawns
  git; a real temporary git repository integration test.
- DESIGN §10.4 and §13.1 document the rule and the snapshot field.

## Alternatives Considered

1. **Keep all non-recursive worktree deletes L0** — rejected by the user: uncommitted content is
   unrecoverable.
2. **Make every delete L1** — loses routine, recoverable deletes of committed files.
3. **Ask git again during replay** — non-deterministic (state has changed) and couples replay to
   the current working tree.
