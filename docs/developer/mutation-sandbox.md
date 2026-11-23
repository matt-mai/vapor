---
title: Mutation sandbox
---

# Mutation sandbox

Some slices carry Starlark scripts that adjust files after extraction: rewriting a
config, generating a symlink, splitting one file into several. Vapor runs them, and
that makes mutation the one place where catalogue content executes.

The catalogues are upstream's, and a catalogue is data from outside this project. So
the sandbox starts from an uncomfortable assumption: the script may be hostile, and
the resource limits are the only thing between it and the build host.

## On this page

- [Why a step limit is not a security boundary](#why-a-step-limit-is-not-a-security-boundary)
- [The worker](#the-worker)
- [The limits](#the-limits)
- [The content API](#the-content-api)
- [All or nothing](#all-or-nothing)
- [The adversarial suite](#the-adversarial-suite)
- [What the sandbox does not claim](#what-the-sandbox-does-not-claim)
- [Working on this package](#working-on-this-package)

## Why a step limit is not a security boundary

Starlark has a step budget, and `contents.slices-engine.max-steps` defaults to
`100000`. That bounds how many bytecode instructions run. It says nothing about how
much memory one instruction allocates: a single string concatenation in a loop can
allocate gigabytes in a handful of steps.

So the step budget stays, as a cheap guard against runaway loops, and it is not the
security boundary. The boundary is a separate worker process with its own resource
limits, and the step budget cannot relax any of them. That distinction is worth
keeping in mind when reading the limits: some exist for safety, one exists for
convenience.

## The worker

A script does not run in the build process. Vapor re-executes its own binary with
`VAPOR_SANDBOX_WORKER=1`, and the child enters:

- its own user, mount, PID and network namespaces;
- a `chroot` to an empty directory, so the host filesystem is not visible;
- a parent-death signal, so a killed build does not leave a worker behind;
- `RLIMIT_DATA` to bound the heap, with `GOMEMLIMIT` set at three quarters of it;
- `RLIMIT_CPU` for processor time.

`RLIMIT_DATA` rather than `RLIMIT_AS` is a considered choice. Go reserves a large
address space for the heap and runtime structures, so an address-space limit would
either be uselessly large or would kill the runtime before the script ran. The data
segment limit bounds what the process actually maps, and requires Linux 4.7 or newer
for `mmap` to count against it. The Go runtime needs roughly 128 MiB to start at all,
which is why the memory bound is 512 MiB rather than something smaller.

`RLIMIT_CPU` counts whole seconds and rounds up, so a sub-second CPU bound would be
enforced as a whole second. `Validate` refuses such a bound instead of silently
loosening it.

Only Linux is supported. `CheckSandboxPlatform` fails closed everywhere else, because
the limits are the guarantee and running untrusted code without them is not an
option. `SandboxSupported` applies the same rule to the current host.

## The limits

| Bound | Value | Purpose |
| --- | --- | --- |
| `MaxScriptBytes` | 1 MiB | source text of one script |
| `MaxReadBytes` | 64 MiB | bytes a script reads |
| `MaxWriteBytes` | 16 MiB | one content write |
| `MaxScriptWrites` | 64 MiB | all bytes one script writes |
| `MaxVFSGrowthBytes` | 256 MiB | bytes mutation may add across the build |
| `MaxMessageBytes` | 256 MiB | encoded script and image metadata |
| `MaxMemoryBytes` | 512 MiB | worker heap |
| `MaxWallTime` | 60 s | one script, including time blocked |
| `MaxCPUTime` | 30 s | one script's processor time |

These are internal safety bounds, not specification settings. A specification cannot
raise them, and raising the step budget does not move them. `Validate` rejects
inconsistent configurations, such as a single-write bound above the script total or a
CPU bound above the wall clock, so a misconfigured sandbox fails before a script runs
instead of enforcing something nobody intended.

## The content API

A script sees `content`, with three operations: `content.read`, `content.write` and
`content.list`. Nothing else touches the image.

Links are followed one component at a time through the selected content, so a script
cannot escape the selection by walking a symlink. A write to a path that is
hard-linked is refused: mutation edits contents, and letting it rewrite a shared inode
would change files the script did not name.

Reads and writes are counted as they happen, not checked afterwards. Counting after
the fact is how a limit becomes a post-mortem.

## All or nothing

`Mutate` stages a script's changes on a shallow copy of the tree. The worker returns
only the files that changed, and the parent applies them, or applies nothing.

Two consequences follow. A failed script leaves the committed tree exactly as it was,
which is what makes "resource failure does not corrupt a build" true rather than
hoped for. And a script that rewrites a file to the same bytes produces no change at
all, because unchanged writes are discarded before the result crosses the process
boundary.

Temporary content is handled around the scripts: paths marked `until: mutate` exist
during mutation so a script can use a generated file, and are removed afterwards. The
build records hashes of mutable paths, so it can prove that the cleanup left nothing
that a script wrote.

## The adversarial suite

`AdversarialCases` is a frozen table of attacks and the failure each must produce. It
is a contract published in the code, and the tests run every case.

| Attack | Expected failure |
| --- | --- |
| oversized script | `script-size` |
| repeated read | `read-bytes` |
| oversized write | `write-bytes` |
| write loop | `write-bytes` |
| tree growth | `vfs-growth` |
| oversized message | `message-size` |
| heap exhaustion | `memory` |
| sleeping script | `wall-time` |
| spinning script | `cpu-time` |
| step exhaustion | `steps` |
| missing capability | `capability` |
| cancelled build | `canceled` |
| dead worker | `worker-death` |

The contract is the failure kind, not the message. Wording can improve without
weakening the guarantee, and a failure that produces the wrong kind is a regression
even if it fails.

Every case also asserts that the committed tree is unchanged, because a bound that
stops a script after it has half-written the image is not a bound that worked.

## What the sandbox does not claim

- It does not make Starlark safe in the abstract. It bounds the damage one script can
  do to the build process and the host.
- It does not allow successful store-backed or Pro-backed mutation protocols that
  upstream cannot run. The sandbox is about isolation, not compatibility.
- Post-allocation checks and Go's soft memory limit are not treated as security
  boundaries. If a guarantee matters, it is enforced by the kernel.

## Working on this package

- Do not add a capability without adding an adversarial case for it. The table is the
  contract.
- Keep every new bound in `SandboxLimits`, validated, tested, and unreachable from the
  specification.
- Never move a check from inside the worker to the parent if it protects the parent.
  The parent trusts only changed files and a bounded message.
- When you change a limit, say which test would have failed with the old value. A
  limit nobody can trip in a test is decoration.
- Tests that wait on a bound run in parallel, because `RLIMIT_CPU` cannot express
  less than a second. The worker-leak check therefore runs once after the whole test
  binary, not around one test: mid-run, a live worker may belong to a test that is
  still going.
