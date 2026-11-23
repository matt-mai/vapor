# Coding Agent Instructions for Vapor

Vapor is a daemonless, rootless Go CLI (`vaporize`, module `github.com/matt-mai/vapor`)
for hardened, deterministic OCI images.
A reference would be "apko for debian based distributions". This is a simplification, not an instruction to
exactly follow apko's contract. Similarly upstream Chisel v3 is the reference for behavior Vapor implements, 
not a feature checklist: implement what our images need, and reject what we do not use
explicitly rather than shipping unused compatibility surface.

## Workflow

- If you find yourself reasononing about major architecture of feature set decisions, stop and ask the developer.
- Document decisions sparsely: code comments explain only non-obvious local
  rationale, never how a function works. Package/project-wide decisions belong in
  `docs/developer/`; `docs/user/` explains how user-facing behavior works, not why.
  Documentation must never reference the implementation plan, unless refering to future work.
  User documentation should be friendly to non technical readers; developer documentation may be more technical.
  All documentation should use simple terms and understandable language. Prefer readability oder information density.
- Commit with conventional commits. Scope commits by change.

## Engineering principles

- Prefer the smallest complete change, existing patterns and the Go standard
  library. Preserve the module/toolchain unless changing them is necessary.
- Add dependencies only when needed; discuss additions with the developer first.
- Keep packages acyclic and distribution policy behind `internal/distro`.
  Keep schema decoding, default policy and semantic validation separate.
- Authenticate inputs before parsing/extraction; consume verified immutable bytes,
  not mutable paths. Locks capture inputs; builds are offline and fail on missing
  or corrupt data. Registry push is an explicit output operation.
- Never execute maintainer scripts or require root/Docker/BuildKit for assembly.
  External container end-to-end runs require explicit opt-in.
- Preserve deterministic ordering/digest domains and epoch-normalized generated
  timestamps. Separate uncompressed serialization/DiffID from compression/digest.
- Use strict YAML, reject unknown/duplicate fields and interpolation; no legacy
  readers or migrations. Honor upstream chisel v3 semantics for the features Vapor
  implements; an unused upstream feature is refused by name and recorded as
  unsupported, never half-built to look compatible.
- Preserve security validation, resource bounds, license material and non-destructive
  filesystem behavior. A step counter alone is not memory safety.
- Keep credentials/private keys out of specs, locks, outputs and logs. Report safe
  outer errors, not raw library causes that may contain sensitive input.
- When removing something, fully remove it. Do not attempt backwards compatability or 
  think about migration paths. Clean up documentation in the same manner.

## References

Use `docs/architecture-and-expansion.md` for package boundaries and provider/security
contracts, `docs/image-spec-and-lockfile.md` for spec/lock design, and relevant
`docs/user/` / `docs/developer/` references for exact feature behavior and limits.
Pinned upstream compatibility evidence is in `docs/developer/chisel-v3-compatibility.md`.

## Quality gates

Before calling an implementation substep with go code changes complete, run:

```bash
task fix
task check
```

Require zero lint issues and passing tests; never weaken tests to conceal bugs.
Use offline synthetic fixtures and mock services in ordinary tests.

After bigger changes that could affect the entire application workflow, run either
targeted or the full end-to-end suite. The e2e suite builds real images from live
archives, so it needs the network and a container engine, and the whole set takes
about twenty minutes. `task test:e2e` runs everything; `task test:e2e <name>` runs
only the named images (`runtime-packages`, `debian-runtime-packages`, ...). A single
run is bounded: each container invocation has a timeout and a failed run removes its
own containers, so a hang fails instead of blocking. Watch a run in progress with
`E2E_LOG=/tmp/e2e.log`, which tees every step with a timestamp. Never wait on the
suite in one tool call; start it in the background and poll the log.