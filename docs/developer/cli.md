---
title: Command line
---

# Command line

`cmd/vaporize` is a small command tree built on `cobra`. Every command is a thin
layer: parse flags, build the library value the flag describes, call the library, and
report. None of the logic lives here, which is why this package stays readable as the
product grows.

## On this page

- [The commands](#the-commands)
- [Exit codes](#exit-codes)
- [Reporting, and why it is a library](#reporting-and-why-it-is-a-library)
- [Flags](#flags)
- [Testing the CLI](#testing-the-cli)
- [The version string](#the-version-string)
- [Working on this package](#working-on-this-package)

## The commands

| Command | Purpose | Writes |
| --- | --- | --- |
| `init` | write a starter `image.yaml` for Ubuntu 26.04 | `image.yaml` in `--dir` |
| `lock` | resolve inputs, verify evidence, write the lock | lock file |
| `inspect` | re-encode a lock's canonical YAML | stdout |
| `slices` | list slices from a catalogue | stdout |
| `build` | build images from locked inputs | layout, tarball, registry |
| `vex` | check claims against the built image and write statements | statement files |
| `cache` | report or collect the verified input cache | cache files |
| `version` | print the release version | stdout |

## Exit codes

The contract is small and worth keeping small:

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | the command ran and failed |
| 2 | usage error, or an unwrapped error |

`errOperation` marks errors a command produced on purpose, and those map to 1.
Anything else, including a `cobra` flag parsing error, is 2. The distinction lets a
script tell "I asked for something that cannot work" from "the tool broke".

## Reporting, and why it is a library

Progress and diagnostics go through `internal/ui`, not through `fmt.Fprintln`.

The reason is testability. A command that prints directly cannot be asserted on
without capturing the process's file descriptors, and every command would reimplement
its own formatting. `ui.Reporter` serializes all output behind a mutex, so a
concurrent build's phases cannot interleave into unreadable text.

What it does:

- renders a numbered phase per target: `[build] [3/7] extract packages`. The target names
  the command (`build`, `lock`, `vex`), and one command works on one image, so there is
  no target count to show;
- animates a spinner only when stderr is a terminal, and falls back to plain lines
  otherwise, so piping the output gives usable text;
- omits the target from the animated line, because that line redraws in place and the
  target never changes during a build. The completed line keeps the `[build]` prefix, so
  a log still says which command a step belonged to;
- names what a phase is working on with `Reporter.Stream`, which sets `Phase.Item` and an
  optional `Done`/`Max` pair. A phase with a total draws a bar; one without keeps the
  spinner and shows no count, because a bar needs a total to mean anything. The `Max`
  test is what decides it, so a caller streams either way and never has to ask whether
  a bar is drawn. Assembly is the one phase that stays busy for minutes, so it streams
  through `builder.Progress`: the locked archive bytes are one running total across
  platforms, and a stage with no archive (`compress layer`, `hardening`) repeats the last
  measurement instead of inventing one;
- prints a step once. A step reports twice, first when it starts and again when its
  measured details are known; the second report redraws rather than announcing the same
  step again. A stream is likewise never a new step: forty archives rewrite one line;
- counts only the steps the command planned. `build` numbers its phases through
  `buildOptions.reportPhase`, whose total comes from `plannedPhases`: evidence, assembly
  and attestations always, plus export when `--oci-dir` or `--tarball` is set, plus push
  for `--push`. A build with no output flag ends at `[3/3]` rather than stopping at
  `[3/5]`, so a finished run never looks like a truncated one;
- prints a streamed item every twentieth archive when it cannot redraw — a pipe,
  `--no-progress` — so a log shows movement without one line per archive;
- takes `--no-progress` and `--quiet` from `newReporterConfig`. `Plain` disables the
  animation, and `Quiet` additionally stops naming streamed items. Neither changes what
  a command does, only what it says;
- renders sizes in binary units (`12.4 MiB`), so a reader never has to guess whether a
  bare number was decimal or binary;
- leaves out a field it has nothing to say about. A build that wrote no files has no
  destination, and `destination=` at the end of a line reads as a bug;
- respects `NO_COLOR`;
- redacts secrets from every line it writes;
- collects output errors instead of ignoring them;
- closes a build with one `success:` line from `Reporter.Success`, which names what was
  produced — platforms, layers, attached statement kinds and destination — so a build
  does not have to be inspected to be understood.

`Config` takes `Terminal`, `Getenv`, `Now` and `Ticks` as functions, so tests drive the
reporter without a terminal or a clock. That is the pattern to follow for anything in
this package: presentation dependencies are injected, never read globally.

`Plain` and `Quiet` live in `Config` for the same reason. Whether a bar is drawn and
whether an item is named are decisions a test needs to make, and folding them into
`Terminal` would tie them to a terminal a test does not have.

`Terminal` is the one dependency a command must supply itself, because the answer
belongs to the writer a command was given rather than to the process. `newReporterConfig`
in `progress.go` finds the `*os.File` underneath whatever wraps stderr and asks
`ui.IsTerminal`. Getting this wrong is quiet rather than loud: a command that leaves
`Terminal` nil renders plainly, so the spinner silently never appears. That was the
case until the wrapper around stderr was unwrapped properly.

Redaction is not cosmetic. A URL can carry a token in its userinfo, a query string can
carry a signature, and a registry error can echo a request. Every message is rewritten
before it is written: each declared secret becomes `[redacted]`, and each URL loses its
userinfo, query and fragment. Overlapping matches are merged and answered with
`[redacted]` rather than resolved, so a substitution can never hide a later match or
leave half a credential visible.

Progress goes to stderr and results go to stdout, so `vaporize build > digest.txt`
leaves a file containing the digest and nothing else.

## Flags

Flags are declared next to the command that uses them and mapped straight onto a
library struct. Three conventions:

- **No hidden inputs.** Everything a command reads is a flag, an argument or a
  documented environment variable. `VAPOR_CACHE_DIR` is the only environment variable
  in the build and lock paths, and it exists so a CI system can relocate the cache.
- **Repository and tags are not flags.** `build` takes them from the specification,
  because a published reference is part of what was locked, and a flag would let the
  build publish somewhere the lock does not describe.
- **Zero means "all".** `--jobs` defaults to 0, which builds every declared platform
  at once. A positive value is clamped to the platform count.

`init` requires all four of its flags and says so, rather than filling in a default
release that would silently be wrong for the next release.

## Testing the CLI

The tests call `run(args, stdout, stderr)` directly and assert on exit code, stdout and
stderr. No subprocess, no temporary binary, no shell.

That shape is why `run` takes writers instead of using the process's own: the same
code runs in a test and in production, and a test can assert that the digest went to
stdout while the progress went to stderr.

What to test for a new command:

- the happy path, asserting on stdout;
- each failure mode, asserting the exit code *and* that the message is not the raw
  library error;
- flag validation, including "required flag missing" and "supplied twice";
- that nothing was written when the command failed.

## The version string

`version` prints one line, and the same value is the builder version recorded in
provenance statements. A binary installed with `go install ...@latest` gets its
version from the module system. A binary built by a release pipeline has no module
version, so the pipeline stamps one into `main.version` with `-ldflags -X`. When
neither is set the value is `development`, which is what an untagged local build
reports.

## Working on this package

- Keep commands thin. If a command needs a branch on business rules, the branch
  belongs in a package it calls.
- Never print with `fmt` directly. Use the reporter so redaction, ordering and
  terminal detection apply.
- New error categories need an exit code decision, and the default of 2 is a
  deliberate "this was not a planned failure".
- If a flag can be derived from the lock or the specification, derive it.
