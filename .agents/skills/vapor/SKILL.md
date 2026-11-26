# Vapor

## Image specs

### Builder images take whole packages

A spec under `images/*/*/*/builder/` selects whole packages only — `apt`, `dpkg`,
`bash`, `ca-certificates` — never a slice. `internal/synthesis/packages.go` writes a
`Status:` field per record only when the image holds no slice, so one slice turns it
off for the whole database; `apt-get install` still works, but apt can no longer see
what is installed. A mixed database (a real status beside a statusless record) makes
apt refuse every operation with `E: Unmet dependencies`. Runtime images slice by
default; builder images never do.

## Self Improvement

You may add references in a subdir (`references/`).

### Update loop

1. **Trigger:** Only propose an update after completing a task where you uncovered a repeatable, non-obvious repo pattern (e.g., an internal test fixture convention, distro provider quirk, or Chisel slice edge case) that would save future investigation. Skip one-off fixes and anything already covered in `AGENTS.md` or `docs/`.
2. **Place:** Keep `SKILL.md` concise as an index and workflow guide. Put detailed examples, command recipes, or package-specific notes into focused files under `references/` and link them from `SKILL.md`.
3. **Verify:** Check that the proposed addition does not duplicate `AGENTS.md` or `docs/`, weaken any security/quality gate, or leak credentials, local paths, or implementation-plan references.
4. **Confirm:** Present the exact diff (or new reference file content) to the user and wait for explicit approval before writing or modifying any skill files.
