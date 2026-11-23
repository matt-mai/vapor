 # Vapor licensing and boundaries

This repository uses a split licensing model: the core toolchain stays protected,
while users keep complete freedom and ownership over their container
specifications, inputs, and built container images.

## 1. Software and toolchain — EUPL-1.2

The Vapor engine, CLI and Go source code (including `cmd/`, `internal/` and the
related Go packages) are licensed under the European Union Public Licence version
1.2. The full terms are in [LICENSE](LICENSE).

## 2. Agent skills, starter templates and documentation — CC0-1.0

All agent skills (`skills/`), starter templates (`internal/starter/`) and
documentation (`docs/`) are dedicated to the public domain under the Creative
Commons CC0 1.0 Universal Public Domain Dedication. The full terms are in
[LICENSE-CC0](LICENSE-CC0). You may copy, modify, distribute and perform these
works, including commercially, without asking permission and without attribution.

## 3. Your specifications, inputs and built images

Your container specifications (`image.yaml`), lock files (`image.lock.yaml`),
custom slice definitions, input files, and the container images and layers Vapor
produces are not derivative works of Vapor. The EUPL copyleft applies to the
Vapor build tool itself, not to your specifications, inputs or generated images.
You may keep your specifications and built images private, proprietary or
commercial, under terms of your own choosing.

## Shipping a binary

A released archive carries [LICENSE](LICENSE), [LICENSE-CC0](LICENSE-CC0) and
this document. This file explains how they divide the repository; it adds no
terms of its own.
