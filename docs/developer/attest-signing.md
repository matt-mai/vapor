---
title: Signing statements
---

# Signing statements

A statement says what an image contains. A signature says who said it. Signing is
optional and off by default: without a key the payload is written exactly as before,
and with a key the same payload is wrapped in a DSSE envelope and signed.

## On this page

- [What gets signed](#what-gets-signed)
- [The envelope](#the-envelope)
- [Keys](#keys)
- [Signing from the command line](#signing-from-the-command-line)
- [Why Ed25519 and nothing else](#why-ed25519-and-nothing-else)
- [Working on this package](#working-on-this-package)

## What gets signed

The unsigned payload bytes, unchanged. Signing is a wrapper, not a rewrite:

```text
payload (SPDX, SLSA or OpenVEX JSON)     ← the bytes described on the format pages
  └─ envelope { payload, payloadType, signatures }   ← signed bytes
```

The payload inside the envelope is base64 of exactly the bytes that were signed, so a
verifier gets back what the signer wrote and never re-encodes it. That matters because
two encodings of one JSON object are different bytes: a signature over one of them is
not a signature over the other. `Envelope.Verify` returns the decoded payload bytes and
never re-serializes a parsed document.

Signing a statement does not change its subject or its claims. It replaces the bytes a
consumer receives, so the descriptors that describe them name the envelope: inside an
image, the attachment's `artifactType` and layer media type are
`application/vnd.dsse.envelope.v1+json` whenever the layer holds an envelope, and
`application/vnd.in-toto+json` when it holds the statement.

## The envelope

The envelope is the [DSSE](https://github.com/secure-systems-lab/dsse) JSON envelope,
version 1.0:

| Field | Value |
| --- | --- |
| `payload` | base64 of the payload bytes |
| `payloadType` | what the payload is, authenticated alongside it |
| `signatures` | one entry with `keyid` and `sig`, both base64 |

The value signed is the DSSE pre-authentication encoding:

```text
DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
```

Both lengths are decimal byte counts, and the spaces are literal. The type is inside
the signed bytes, so an envelope cannot be relabelled: a signature over an OpenVEX
document does not verify when the same payload is presented as something else.

`internal/attest/dsse_test.go` pins this against the worked example in the DSSE
protocol (`DSSEv1 29 http://example.com/HelloWorld 11 hello world`), so a changed
encoding fails a test rather than a verifier.

Payload types Vapor uses:

| Payload | `payloadType` |
| --- | --- |
| Every statement a build attaches (SPDX, provenance, VEX) | `application/vnd.in-toto+json` |
| An OpenVEX document from `vaporize vex` | `application/vnd.openvex+json` |

A build signs the in-toto statement, not the document inside it, so one signature
covers the predicate type and the subject as well as the claims. It signs all three
formats: a key given to `vaporize build` leaves nothing unattested. `vaporize vex`
writes the bare document, because that is what standalone VEX tooling reads, and signs
it directly.

## Keys

`--sign-key` names a PEM file holding one PKCS#8 Ed25519 private key:

```text
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

The file is opened once, without blocking, and the handle itself is checked: it must be
a regular file and at most 64 KiB. The read then stops one byte past that bound, so a
file that grows or is swapped for another after the check is still refused rather than
read whole. The non-blocking open matters for a named pipe: opening one for reading
waits for a writer, so a FIFO at the key path would otherwise hang the run until it is
interrupted. With the flag the open returns at once and the type check refuses it.

Loading refuses, in order: a path that is not a regular file, a file larger than
64 KiB, a file that is not PEM, a PEM block that is not `PRIVATE KEY`, more than one
PEM block, a body that is not a valid PKCS#8 key, and a key that is not Ed25519. Each
refusal is a plain, fixed sentence about the shape of the file. None of them carries
the path, the key bytes, the PEM label the file used, or a library message that might
quote them.

The key file is read once, into memory, and cleared when the run ends. Nothing writes
it back, and it never reaches a spec, a lock, a cache entry or a statement. The
`keyid` in the envelope is a SHA-256 of the public key, so it identifies the key
without revealing anything about the private half.

The key stays a file the person running the build owns. Vapor does not look up keys,
does not read environment variables for them and does not add a keyring.

## Signing from the command line

```text
vaporize build --sign-key signing.pem --oci-dir out/
vaporize vex --sign-key signing.pem -o out/
```

`vaporize build` attaches the envelope in place of the statement in the layout. The
`--attestations-dir` output stays the bare document, because a file is read by a
scanner and the signature belongs to the attachment. The attachment's `artifactType`
and layer media type name the
envelope (`application/vnd.dsse.envelope.v1+json`) rather than the statement, because a
reader that selects by media type would otherwise skip a signed attestation or try to
parse the envelope as a statement. `vaporize vex` writes the bare OpenVEX document
unless a key is given, in which case the file holds the envelope instead; a file has no
media type to describe, so nothing there has to be relabelled.
A key that cannot be loaded stops the command with exit code 1 and writes no file:
falling back to unsigned output would silently drop the signature the caller asked
for.

## Why Ed25519 and nothing else

Ed25519 is in the Go standard library, it needs no parameters to get wrong, and it is
deterministic: the same payload and key produce the same signature bytes, so a signed
statement is reproducible. A randomized algorithm would make two builds of identical
content disagree on the signature, and the payload would carry noise the image does
not have.

The project rule is that a new dependency is discussed before it is added. Ed25519
adds none. Algorithms that need a new library, a hardware token or a policy choice are
a separate decision, and the envelope can carry them later because DSSE does not fix
the algorithm.

## Working on this package

- `internal/attest/dsse.go` holds the envelope, the encoding and the key loading.
  Nothing there knows what a payload means.
- A new payload type is a string constant here and a statement in a format page, not a
  new envelope shape.
- Verification is part of the package because a signer that cannot verify its own
  output is not evidence. A future `verify` command should call `Envelope.Verify`, not
  re-implement it.
- When signing a second format, reuse `MaybeSigned`. The unsigned payload must stay
  reachable without a key, or a build without one changes shape.
