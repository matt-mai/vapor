# Pinned Debian release samples

Real `InRelease` files, kept unchanged so the tests never depend on the live
archive. `trust_test.go` pins each file's SHA-256, so replacing one requires
updating both the file and the digest.

| File | Source | Retrieved |
| --- | --- | --- |
| `inrelease-trixie` | http://deb.debian.org/debian/dists/trixie/InRelease | 2026-11-20 |
| `inrelease-bookworm` | http://deb.debian.org/debian/dists/bookworm/InRelease | 2026-11-20 |
| `inrelease-trixie-security` | http://security.debian.org/debian-security/dists/trixie-security/InRelease | 2026-11-20 |
| `inrelease-bookworm-security` | http://security.debian.org/debian-security/dists/bookworm-security/InRelease | 2026-11-20 |

The samples are small because a release file only lists digests. The main archive
files declare no `Valid-Until`; the security files expire a week after signing, so
the tests verify them at a fixed time inside that window.
