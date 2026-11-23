#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
# Typecheck it with: uvx --with mypy --with types-PyYAML mypy --strict attestations.py
"""Check the statements a build attached to an OCI layout.

Every attachment has to be an OCI artifact manifest whose subject is a platform
manifest and whose payload parses as an in-toto statement of the predicate type its
format names. The statements directory holds the same predicates as bare documents,
so a scanner can read them without unwrapping anything.

    attestations.py --layout DIR --statements DIR --lock FILE --expect spdx,provenance[,vex]
                    [--claims CVE-1,CVE-2] [--signed PUBLIC-KEY-PEM]

With --signed the attachments have to carry DSSE envelopes, the signature is checked
against the key, and the statement inside has to be the one the checks describe.

Exits non-zero with a plain message on the first problem it finds.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import urllib.parse
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from typing import NotRequired, NoReturn, TypedDict, TypeVar, cast

import yaml

PREDICATES: dict[str, str] = {
    "spdx": "https://spdx.dev/Document",
    "provenance": "https://slsa.dev/provenance/v1",
    "vex": "https://openvex.dev/ns/v0.2.0",
}
IN_TOTO = "application/vnd.in-toto+json"
DSSE = "application/vnd.dsse.envelope.v1+json"
# The DSSE label the payload type and length are prefixed with, spelled into the
# signed bytes along with both lengths.
DSSE_LABEL = b"DSSEv1"
STATEMENT = "https://in-toto.io/Statement/v1"
TITLE = "org.opencontainers.image.title"
# The sentence the generator writes on every package the image carries whole.
WHOLE = "This package is included whole."


# The documents are read from a layout this repository produced, so their shape is
# stated once here and used unchecked at the points that only read a field. A field
# the generator must set is required; anything it may leave out is NotRequired.
class Platform(TypedDict):
    os: str
    architecture: str


class Descriptor(TypedDict):
    digest: str
    mediaType: str
    size: NotRequired[int]
    artifactType: NotRequired[str]
    annotations: NotRequired[dict[str, str]]
    platform: NotRequired[Platform]


class Index(TypedDict):
    schemaVersion: NotRequired[int]
    manifests: NotRequired[list[Descriptor]]


class Manifest(TypedDict):
    config: Descriptor
    layers: list[Descriptor]
    subject: NotRequired[Descriptor]


class Signature(TypedDict):
    keyid: str
    sig: str


class Envelope(TypedDict):
    payload: str
    payloadType: str
    signatures: list[Signature]


class RootFS(TypedDict):
    diff_ids: list[str]


class Config(TypedDict):
    rootfs: RootFS


class Subject(TypedDict):
    digest: dict[str, str]


# "_type" and the OpenVEX "@" keys are not Python names, so the functional form is the
# only way to state them.
Statement = TypedDict("Statement", {
    "_type": str,
    "subject": list[Subject],
    "predicateType": str,
    "predicate": object,
})

Checksum = TypedDict("Checksum", {"algorithm": str, "checksumValue": str})
ExternalRef = TypedDict("ExternalRef", {"referenceLocator": str, "referenceType": str})


class Relationship(TypedDict):
    relationshipType: str
    spdxElementId: str
    relatedSpdxElement: str


class Element(TypedDict):
    SPDXID: str
    name: str
    comment: NotRequired[str]
    versionInfo: NotRequired[str]
    checksums: NotRequired[list[Checksum]]
    externalRefs: NotRequired[list[ExternalRef]]


class SpdxFile(TypedDict):
    SPDXID: str
    fileName: str
    checksums: list[Checksum]


class Spdx(TypedDict):
    spdxVersion: NotRequired[str]
    documentNamespace: NotRequired[str]
    name: NotRequired[str]
    packages: NotRequired[list[Element]]
    files: NotRequired[list[SpdxFile]]
    relationships: NotRequired[list[Relationship]]


class Dependency(TypedDict):
    name: str
    digest: dict[str, str]


class BuildDefinition(TypedDict):
    buildType: str
    externalParameters: dict[str, object]
    resolvedDependencies: NotRequired[list[Dependency]]


class Builder(TypedDict):
    id: str
    version: dict[str, str]


class RunDetails(TypedDict):
    builder: Builder


class Provenance(TypedDict):
    buildDefinition: BuildDefinition
    runDetails: RunDetails


class Vulnerability(TypedDict):
    name: str


class VexStatement(TypedDict):
    vulnerability: Vulnerability
    products: NotRequired[list[dict[str, str]]]
    status: NotRequired[str]
    justification: NotRequired[str]
    status_notes: NotRequired[str]
    action_statement: NotRequired[str]


Vex = TypedDict("Vex", {
    "@context": str,
    "@id": str,
    "author": str,
    "version": int,
    "statements": list[VexStatement],
})


class Provider(TypedDict):
    distro: NotRequired[str]
    release: NotRequired[str]


class Archive(TypedDict):
    sha256: NotRequired[str]


class Catalogue(TypedDict):
    name: str
    tree: str
    archive: NotRequired[Archive]


class LocalInput(TypedDict):
    role: str
    path: str
    sha256: str


class Content(TypedDict):
    sha256: str
    size: int


class Located(TypedDict):
    """A lock record that may belong to one platform; an absent platform means all."""

    platform: NotRequired[str]


class Repository(Located):
    id: str
    release: Content


class Package(Located):
    name: str
    version: str
    architecture: str
    content: Content
    source: NotRequired[str]


# The lock spells the definition digest with a hyphen, which a Python name cannot, so
# this record is stated in the functional form.
Sliced = TypedDict("Sliced", {
    "package": str,
    "version": str,
    "architecture": str,
    "content": Content,
    "definition-digest": str,
    "platform": NotRequired[str],
    "source": NotRequired[str],
    "selected": NotRequired[list[str]],
    "closure": NotRequired[list[str]],
})


class SBOM(TypedDict):
    name: NotRequired[str]
    version: NotRequired[str]
    cpe: NotRequired[str]


class Artifact(Located):
    name: str
    sha256: str
    size: int
    sbom: NotRequired[SBOM]


Lock = TypedDict("Lock", {
    "spec": NotRequired[str],
    "provider": NotRequired[Provider],
    "catalogues": NotRequired[list[Catalogue]],
    "local-inputs": NotRequired[list[LocalInput]],
    "repositories": NotRequired[list[Repository]],
    "packages": NotRequired[list[Package]],
    "slices": NotRequired[list[Sliced]],
    "artifacts": NotRequired[list[Artifact]],
})


class LockFile:
    """The lock the build was made from, filled in by `main` before anything reads it."""

    data: Lock = {}


LOCK = LockFile()

Record = TypeVar("Record", bound=Located)


def fail(message: str) -> NoReturn:
    sys.exit("FAIL: " + message)


def blob(layout: str, digest: str) -> bytes:
    algorithm, hexdigest = digest.split(":", 1)
    if algorithm != "sha256":
        fail("unexpected digest algorithm in " + digest)
    try:
        with open(os.path.join(layout, "blobs", "sha256", hexdigest), "rb") as handle:
            return handle.read()
    except OSError:
        fail("blob %s is missing from the layout" % digest)


def load(body: bytes, what: str) -> object:
    """Decode one JSON document. The shape is stated by the caller's cast, and every
    field it reads is checked where it is read."""
    try:
        return cast(object, json.loads(body))
    except ValueError as error:
        fail("%s is not JSON: %s" % (what, error))


def image_files(layout: str, digest: str) -> dict[str, dict[str, str]]:
    """Read file checksums from the platform image, including hardlink contents."""
    manifest = cast(Manifest, load(blob(layout, digest), "image manifest " + digest))
    config = cast(Config, load(blob(layout, manifest["config"]["digest"]), "image config"))
    diff_ids = config["rootfs"]["diff_ids"]
    layers = manifest["layers"]
    if len(layers) != len(diff_ids):
        fail("%s: %d layers but %d diff ids" % (digest, len(layers), len(diff_ids)))
    files: dict[str, dict[str, str]] = {}
    for layer, diff_id in zip(layers, diff_ids, strict=True):
        media_type = layer["mediaType"]
        if "gzip" in media_type:
            raw = gzip.decompress(blob(layout, layer["digest"]))
        elif media_type.startswith("application/vnd.oci.image.layer.v1.tar"):
            raw = blob(layout, layer["digest"])
        else:
            fail("unsupported layer media type " + media_type)
        # The layer has to hash to what the config's rootfs records, or the image
        # is describing bytes it does not contain.
        if "sha256:" + hashlib.sha256(raw).hexdigest() != diff_id:
            fail("%s: a layer does not match its diff id" % digest)
        archive = tarfile.open(fileobj=io.BytesIO(raw))
        links: list[tuple[str, str]] = []
        for member in archive.getmembers():
            path = "/" + member.name
            if member.isdir() or member.issym():
                continue
            if os.path.basename(path).startswith(".wh."):
                continue
            # A hardlink carries no bytes: it is another name for an entry that was
            # written earlier, and it is a real file in the image all the same.
            if member.islnk():
                links.append((path, "/" + member.linkname))
                continue
            handle = archive.extractfile(member)
            if handle is None:
                fail("%s is not a regular file" % path)
            body = handle.read()
            files[path] = {"SHA1": hashlib.sha1(body, usedforsecurity=False).hexdigest(),
                           "SHA256": hashlib.sha256(body).hexdigest()}
        for path, target in links:
            if target not in files:
                fail("%s is a hardlink to %s, which the layer does not contain" % (path, target))
            files[path] = files[target]
    return files


def check_spdx_against_image(layout: str, descriptor: Descriptor, predicate: Spdx,
                             subject: str, platform: str) -> None:
    """Every file the image holds is in the document, and every document file is the
    image's, with the same bytes. A document that names one and not the other is a
    false description of the image."""
    digest = descriptor["digest"]
    if predicate.get("spdxVersion") != "SPDX-2.3":
        fail("%s: spdxVersion is %r" % (digest, predicate.get("spdxVersion")))
    files = image_files(layout, subject)
    described: dict[str, dict[str, str]] = {}
    for entry in predicate.get("files") or []:
        checksums = {checksum["algorithm"]: checksum["checksumValue"] for checksum in entry["checksums"]}
        if len(entry["checksums"]) != 2 or set(checksums) != {"SHA1", "SHA256"}:
            fail("%s: %s must carry one SHA1 and one SHA256" % (digest, entry["fileName"]))
        described[entry["fileName"]] = checksums
    # SPDX 2.3 section 8.1 wants a path relative to the document's root, so the image's
    # absolute paths are compared without their leading slash.
    if set(described) != {path.lstrip("/") for path in files}:
        missing = sorted({path.lstrip("/") for path in files} - set(described))
        extra = sorted(set(described) - {path.lstrip("/") for path in files})
        fail("%s: SPDX files differ from the image (missing %s, extra %s)"
             % (digest, missing or "none", extra or "none"))
    for path, checksums in files.items():
        for algorithm, checksum in checksums.items():
            if described[path.lstrip("/")][algorithm] != checksum:
                fail("%s: SPDX %s checksum for %s is %s, the image has %s"
                     % (digest, algorithm, path, described[path.lstrip("/")][algorithm],
                        checksum))

    # Nothing may be described whole or by slice unless some file still carries it,
    # and a slice has to name the package it came from.
    elements: list[Element] = predicate.get("packages") or []
    in_document = {element["SPDXID"] for element in elements}
    if not in_document:
        fail("%s: SPDX describes no package" % digest)
    for element in elements:
        identifier = element["SPDXID"]
        if not SPDX_IDENTIFIER.fullmatch(identifier):
            fail("%s: %s is not an SPDX identifier" % (digest, identifier))
        kind = element_kind(element)
        comment = element.get("comment") or ""
        # Every element carries the package URL a VEX claim uses, including a slice
        # and an artifact, so the two payloads can be joined by purl alone.
        if kind is not None and first_reference(element) is None:
            fail("%s: %s (%s) has no package URL" % (digest, identifier, kind))
        if kind == "package":
            if not comment.startswith(WHOLE):
                fail("%s: %s is a package but %r" % (digest, identifier, comment))
            if first_checksum(element) is None:
                fail("%s: %s has no checksum" % (digest, identifier))
        if kind == "slice":
            # The name has to be the package a scanner looks up, because that is the name
            # an advisory is filed under. The slices the image holds are checked against
            # the lock below.
            locator = first_reference(element) or ""
            package = locator.split("/")[2].split("@")[0] if locator.startswith("pkg:deb/") else ""
            # A package URL percent-encodes everything outside its safe set, so
            # `libstdc++6` is written `libstdc%2B%2B6`. Compare the decoded name.
            package = urllib.parse.unquote(package)
            if element["name"] != package:
                fail("%s: slice %s is named %r, want the package %r"
                     % (digest, identifier, element["name"], package))
        if kind is None:
            fail("%s: %s is neither a package, a slice, an artifact nor a module"
                 % (digest, identifier))

    # The document reaches every file: a file no element contains would be an
    # orphan in the description.
    relationships: list[Relationship] = predicate.get("relationships") or []
    containers = {relationship["relatedSpdxElement"] for relationship in relationships
                  if relationship["relationshipType"] == "CONTAINS"}
    for entry in predicate.get("files") or []:
        if entry["SPDXID"] not in containers:
            fail("%s: %s is in the document but nothing contains it"
                 % (digest, entry["fileName"]))
    described_elements = {relationship["relatedSpdxElement"] for relationship in relationships
                          if relationship["relationshipType"] == "DESCRIBES"}
    if described_elements != in_document:
        fail("%s: DESCRIBES and the packages disagree" % digest)

    # The document is about this image and no other: the subject digest is in the
    # namespace, and the name carries the platform.
    namespace = predicate.get("documentNamespace") or ""
    if not namespace.endswith(strings_after(subject, ":")):
        fail("%s: the namespace %r does not name the subject %s"
             % (digest, namespace, subject))
    if platform not in (predicate.get("name") or ""):
        fail("%s: the document name %r does not name %s"
             % (digest, predicate.get("name"), platform))

    # The package, slice and artifact elements have to match the lock, so a document
    # cannot describe content the image was not built from.
    check_spdx_elements_against_lock(predicate, digest, platform)


def checksum_of(value: SpdxFile | Element, algorithm: str) -> str | None:
    for checksum in value.get("checksums") or []:
        if checksum["algorithm"] == algorithm:
            return checksum["checksumValue"]
    return None


def first_checksum(element: Element) -> str | None:
    return checksum_of(element, "SHA256")


def first_reference(element: Element) -> str | None:
    references = element.get("externalRefs") or []
    return references[0]["referenceLocator"] if references else None


def declared_cpe(record: Artifact) -> str | None:
    """The CPE the lock records for an artifact, which is how a scanner finds advisories
    about a payload no purl can name."""
    identity = record.get("sbom") or {}
    declared = identity.get("cpe") or ""
    return declared or None


def cpe_reference(element: Element) -> str | None:
    for reference in element.get("externalRefs") or []:
        if reference.get("referenceType") == "cpe23Type":
            return reference["referenceLocator"]
    return None


SPDX_IDENTIFIER = re.compile(r"SPDXRef-[a-zA-Z0-9.-]+")
WHOLE_COMMENT = "This package is included whole."
SLICE_COMMENT = "This package is present as slices "
ARTIFACT_COMMENT = "This package is the artifact payload."
MODULE_COMMENT = "This package is vendored inside the payload of another package."


def element_kind(element: Element) -> str | None:
    """What a package entry is, which its comment states because its identifier is an
    opaque hash."""
    comment = element.get("comment") or ""
    if comment.startswith(WHOLE_COMMENT):
        return "package"
    if comment.startswith(SLICE_COMMENT):
        return "slice"
    if comment.startswith(ARTIFACT_COMMENT):
        return "artifact"
    if comment.startswith(MODULE_COMMENT):
        return "module"
    return None


def element_identity(domain: str, payload: dict[str, object]) -> str:
    """The domain-separated element identity: sha256(label || 0x00 || canonical json).
    Canonical here is what the writer emits: sorted keys, no spaces."""
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(domain.encode() + b"\x00" + encoded).hexdigest()


def element_id(identity: str) -> str:
    """The SPDX identifier the writer builds from an element identity: the identity
    with its scheme separator replaced, which the identifier grammar accepts."""
    return "SPDXRef-" + identity.replace(":", "-", 1)


def bare_sha256(value: str) -> str:
    """The lock spells payload hashes bare and records derived ones with a scheme."""
    return value.removeprefix("sha256:")


def package_identity(record: Package) -> str:
    return element_identity("vapor.attest.package.v1", {
        "platform": record["platform"],
        "name": record["name"],
        "version": record["version"],
        "architecture": record["architecture"],
        "sha256": bare_sha256(record["content"]["sha256"]),
        "size": record["content"]["size"],
    })


def slice_identity(record: Sliced) -> str:
    """One element covers every slice of a package, because an advisory is filed under
    the package: an element per slice would report one finding once per slice."""
    return element_identity("vapor.attest.slices.v1", {
        "platform": record["platform"],
        "package": record["package"],
        "version": record["version"],
        "architecture": record["architecture"],
        "definition": bare_sha256(record["definition-digest"]),
        "sha256": bare_sha256(record["content"]["sha256"]),
        "size": record["content"]["size"],
        "slices": list(record.get("closure") or []),
    })


def artifact_identity(record: Artifact) -> str:
    identity = record.get("sbom") or {}
    declared: dict[str, str] = {"name": identity.get("name") or "",
                                "version": identity.get("version") or ""}
    # The CPE is omitted rather than empty when the spec declares none, so a payload
    # that a purl already names keeps the identity it had.
    if identity.get("cpe"):
        declared["cpe"] = identity["cpe"]
    return element_identity("vapor.attest.artifact.v1", {
        "platform": record["platform"],
        "name": record["name"],
        "identity": declared,
        "sha256": bare_sha256(record["sha256"]),
        "size": record["size"],
    })


def strings_after(value: str, separator: str) -> str:
    return value.split(separator, 1)[-1]


def check_spdx_elements_against_lock(predicate: Spdx, digest: str, platform: str) -> None:
    elements = {element["SPDXID"]: element for element in predicate.get("packages") or []}
    # identifier -> (checksum, version). A slice and an artifact have no package
    # checksum of their own, so either may be absent.
    expected: dict[str, tuple[str | None, str | None]] = {}
    for package in platform_records(LOCK.data.get("packages"), platform):
        expected[element_id(package_identity(package))] = (
            bare_sha256(package["content"]["sha256"]), package["version"])
    # A slice element is one element for the whole package, and the identity covers the
    # dependency-first closure rather than the requested slices. The lock records the
    # slices the spec asked for under "selected" and the ones a dependency pulled in
    # under "closure"; only the closure appear as the element, because only those have a
    # locked origin naming them. An element the document does not hold is allowed below.
    slice_closures: dict[str, list[str]] = {}
    for sliced in platform_records(LOCK.data.get("slices"), platform):
        if sliced.get("closure"):
            identifier = element_id(slice_identity(sliced))
            expected[identifier] = (None, sliced["version"])
            slice_closures[identifier] = list(sliced["closure"])
    artifact_cpes: dict[str, str | None] = {}
    for artifact in platform_records(LOCK.data.get("artifacts"), platform):
        identity = artifact.get("sbom")
        identifier = element_id(artifact_identity(artifact))
        expected[identifier] = (
            bare_sha256(artifact["sha256"]), identity.get("version") if identity else None)
        artifact_cpes[identifier] = declared_cpe(artifact)
    # A vendored module is found inside a payload, not locked, so the lock cannot
    # name it. It is accounted for here and described by its purl alone.
    unknown = sorted(identifier for identifier, element in elements.items()
                     if identifier not in expected and element_kind(element) != "module")
    if unknown:
        fail("%s: the document describes %s, which the lock does not hold"
             % (digest, ", ".join(unknown)))
    for identifier, (checksum, version) in expected.items():
        element = elements.get(identifier)
        if element is None:
            # An element appears only while some surviving file still carries it, so a
            # missing one is allowed; a wrong one is not.
            continue
        if version and element.get("versionInfo") != version:
            fail("%s: %s has version %r, the lock says %r"
                 % (digest, identifier, element.get("versionInfo"), version))
        recorded = first_checksum(element)
        if checksum and recorded != checksum:
            fail("%s: %s has checksum %r, the lock says %r"
                 % (digest, identifier, recorded, checksum))
        # A declared CPE has to reach the document: without it a payload that no purl
        # names is invisible to every advisory database.
        if expected_cpe := artifact_cpes.get(identifier):
            if cpe_reference(element) != expected_cpe:
                fail("%s: %s has CPE %r, the lock says %r"
                     % (digest, identifier, cpe_reference(element), expected_cpe))
        # One element covers a whole sliced package, so the comment is where the slices
        # appear. It has to be the locked closure, in lock order: that is what the
        # element covers and what the identity hashes.
        if expected_slices := slice_closures.get(identifier):
            wanted = SLICE_COMMENT + ", ".join(expected_slices) + "."
            if not (element.get("comment") or "").startswith(wanted):
                fail("%s: %s comment %r does not start %r"
                     % (digest, identifier, element.get("comment"), wanted))


def platform_records(records: Sequence[Record] | None, platform: str) -> list[Record]:
    """Lock records that belong to one platform, plus the ones that belong to all."""
    kept: list[Record] = []
    for record in records or []:
        if record.get("platform") in (None, "", platform):
            kept.append(record)
    return kept


def expected_dependencies(platform: str) -> dict[str, str]:
    """What a correct provenance statement lists for one platform, read from the lock:
    the catalogue trees, the snapshot inputs, the repository metadata, and every
    package, slice and artifact payload."""
    expected: dict[str, str] = {}
    for catalogue in LOCK.data.get("catalogues") or []:
        archive = catalogue.get("archive") or {}
        expected["catalogue/" + catalogue["name"]] = (archive.get("sha256") or
                                                      catalogue["tree"].split(":", 1)[1])
    for snapshot in LOCK.data.get("local-inputs") or []:
        expected["input/%s/%s" % (snapshot["role"], snapshot["path"])] = snapshot["sha256"]
    for repository in platform_records(LOCK.data.get("repositories"), platform):
        expected["repository/" + repository["id"]] = repository["release"]["sha256"]
    for package in platform_records(LOCK.data.get("packages"), platform):
        expected["package/" + package["name"]] = package["content"]["sha256"]
    for sliced in platform_records(LOCK.data.get("slices"), platform):
        expected["slice/" + sliced["package"]] = sliced["content"]["sha256"]
    for artifact in platform_records(LOCK.data.get("artifacts"), platform):
        expected["artifact/" + artifact["name"]] = artifact["sha256"]
    return expected


def check_provenance_against_lock(predicate: Provenance, digest: str, platform: str) -> None:
    """A provenance statement is only worth attaching if it names exactly the inputs the
    lock holds. A missing input hides what the image was built from; an extra one claims
    an input the build never read."""
    definition = predicate["buildDefinition"]
    if not definition.get("buildType"):
        fail("%s: the provenance has no build type" % digest)
    parameters = definition["externalParameters"]
    if parameters.get("spec") != LOCK.data.get("spec"):
        fail("%s: the provenance names spec %r, the lock is %r"
             % (digest, parameters.get("spec"), LOCK.data.get("spec")))
    builder = predicate["runDetails"]["builder"]
    if not builder["id"] or not builder["version"]:
        fail("%s: the provenance names no builder" % digest)

    expected = expected_dependencies(platform)
    recorded: dict[str, str] = {}
    for dependency in definition.get("resolvedDependencies") or []:
        name = dependency["name"]
        recorded_digest = (dependency.get("digest") or {}).get("sha256")
        if not recorded_digest:
            fail("%s: input %s has no sha256" % (digest, name))
        recorded[name] = recorded_digest
    # "lock" names the canonical lock bytes, which this check cannot re-encode; the
    # rest has to match the lock exactly.
    if "lock" not in recorded:
        fail("%s: the provenance does not name the lock it was built from" % digest)
    missing = sorted(set(expected) - set(recorded))
    extra = sorted(set(recorded) - set(expected) - {"lock"})
    if missing or extra:
        fail("%s: inputs differ from the lock (missing %s, extra %s)"
             % (digest, missing or "none", extra or "none"))
    for name, want in expected.items():
        if recorded[name] != want:
            fail("%s: input %s is %s, the lock says %s" % (digest, name, recorded[name], want))


def purl_escape(value: str) -> str:
    """The escaping the writer uses for a package URL: everything outside letters,
    digits and "._~" is percent-encoded."""
    out: list[str] = []
    for ch in value:
        if ch.isascii() and (ch.isalnum() or ch in ".-_~"):
            out.append(ch)
        else:
            out.append("".join("%%%02X" % byte for byte in ch.encode()))
    return "".join(out)


def deb_url(distro: str, release: str, name: str, version: str, arch: str,
            upstream: str) -> str:
    url = "pkg:deb/"
    if distro:
        url += purl_escape(distro) + "/"
    url += purl_escape(name) + "@" + purl_escape(version)
    url += "?arch=" + purl_escape(arch)
    if distro and release:
        url += "&distro=" + purl_escape(distro + "-" + release)
    # Advisories are published per source package, so a binary built from one with a
    # different name says so; the build omits the qualifier when they agree.
    if upstream and upstream != name:
        url += "&upstream=" + purl_escape(upstream)
    return url


def locked_products(platform: str) -> dict[str, str]:
    """Every product URL the lock holds for one platform. A claim may only name one of
    these, so a statement cannot describe content the image does not contain."""
    provider = LOCK.data.get("provider") or {}
    distro = provider.get("distro") or ""
    release = provider.get("release") or ""
    products: dict[str, str] = {}
    for package in platform_records(LOCK.data.get("packages"), platform):
        products[deb_url(distro, release, package["name"], package["version"],
                         package["architecture"], package.get("source") or "")] = (
            "package " + package["name"])
    # A slice is named by the package it was cut from: the image holds part of that
    # package, and the package is what a scanner looks up.
    for sliced in platform_records(LOCK.data.get("slices"), platform):
        if not sliced.get("selected"):
            continue
        products[deb_url(distro, release, sliced["package"], sliced["version"],
                         sliced["architecture"], sliced.get("source") or "")] = (
            "slice of " + sliced["package"])
    for artifact in platform_records(LOCK.data.get("artifacts"), platform):
        identity = artifact.get("sbom")
        name = identity.get("name") if identity is not None else None
        if not name:
            continue
        version = (identity.get("version") if identity is not None else None) or ""
        url = "pkg:generic/" + purl_escape(name) + "@" + purl_escape(version)
        products[url] = "artifact " + artifact["name"]
    return products


def check_vex_against_lock(predicate: Vex, digest: str, subject: str, platform: str) -> None:
    """A VEX statement has to be about this image: the document names the subject, and
    every product it names is a package, slice or artifact the lock holds for this
    platform. A qualifier the document states has to match; one it omits constrains
    nothing, which is why a bare URL can appear."""
    if predicate.get("@context") != "https://openvex.dev/ns/v0.2.0":
        fail("%s: OpenVEX context is %r" % (digest, predicate.get("@context")))
    if not (predicate.get("@id") or "").endswith(strings_after(subject, ":")):
        fail("%s: the document id %r does not name the subject %s"
             % (digest, predicate.get("@id"), subject))
    if not predicate.get("author"):
        fail("%s: the document names no author" % digest)
    if predicate.get("version") != 1:
        fail("%s: the document version is %r" % (digest, predicate.get("version")))
    statements = predicate.get("statements") or []
    if not statements:
        fail("%s: the VEX document states nothing" % digest)

    known = locked_products(platform)
    for statement in statements:
        name = statement["vulnerability"]["name"]
        status = statement.get("status")
        if status not in ("not_affected", "affected", "fixed", "under_investigation"):
            fail("%s: %s has status %r" % (digest, name, status))
        if status == "not_affected" and not (statement.get("justification")
                                             or statement.get("status_notes")):
            fail("%s: %s is not_affected without a justification or notes" % (digest, name))
        if status == "affected" and not statement.get("action_statement"):
            fail("%s: %s is affected without an action statement" % (digest, name))
        products = statement.get("products") or []
        if not products:
            fail("%s: %s names no product" % (digest, name))
        for product in products:
            url = product.get("@id")
            if url not in known:
                fail("%s: %s names %s, which the lock does not hold for %s"
                     % (digest, name, url, platform))


def check_attachment(layout: str, descriptor: Descriptor, wanted: list[str],
                     public_key: str | None) -> tuple[str, str, bytes, str]:
    """Check one attachment and return its kind, subject digest, the statement inside
    and the attachment digest."""
    digest = descriptor["digest"]
    kind = (descriptor.get("annotations") or {}).get(TITLE, "").split(" ")[-1]
    if kind not in wanted:
        fail("%s is a %r statement, want one of %s" % (digest, kind, ",".join(wanted)))
    # The media type has to describe the bytes: an envelope is not a statement, and a
    # reader that selects by media type would misparse one labelled as the other.
    layer_type = IN_TOTO if public_key is None else DSSE
    if descriptor.get("artifactType") != layer_type:
        fail("%s: artifactType is %r, want %r"
             % (digest, descriptor.get("artifactType"), layer_type))
    manifest = cast(Manifest, load(blob(layout, digest), "manifest " + digest))
    layers = manifest["layers"]
    if len(layers) != 1:
        fail("%s: %d layers, want exactly one statement" % (digest, len(layers)))
    if layers[0]["mediaType"] != layer_type:
        fail("%s: layer mediaType is %r, want %r"
             % (digest, layers[0]["mediaType"], layer_type))
    payload = blob(layout, layers[0]["digest"])
    if "sha256:" + hashlib.sha256(payload).hexdigest() != layers[0]["digest"]:
        fail("%s: the payload does not hash to its descriptor" % digest)
    if public_key is not None:
        payload = unwrap_envelope(payload, digest, public_key)
    statement = cast(Statement, load(payload, "statement " + digest))
    if statement["_type"] != STATEMENT:
        fail("%s: _type is %r" % (digest, statement["_type"]))
    if statement["predicateType"] != PREDICATES[kind]:
        fail("%s: predicateType is %r, want %r"
             % (digest, statement["predicateType"], PREDICATES[kind]))
    subjects = statement["subject"]
    if len(subjects) != 1:
        fail("%s: %d subjects, want one platform image" % (digest, len(subjects)))
    described = subjects[0]["digest"]
    subject = manifest.get("subject")
    if subject is None or "sha256:" + described.get("sha256", "") != subject["digest"]:
        fail("%s: the manifest subject and the statement subject disagree" % digest)
    return kind, "sha256:" + described["sha256"], payload, digest


def pre_authentication_encoding(payload_type: str, payload: bytes) -> bytes:
    """The DSSE bytes a signature covers: the label, the type and the payload, each
    preceded by its length."""
    return b" ".join([DSSE_LABEL, str(len(payload_type)).encode(),
                      payload_type.encode(), str(len(payload)).encode(), payload])


def unwrap_envelope(body: bytes, digest: str, public_key: str) -> bytes:
    """Verify the DSSE envelope and return the statement it carries."""
    envelope = cast(Envelope, load(body, "envelope " + digest))
    if envelope["payloadType"] != IN_TOTO:
        fail("%s: envelope payloadType is %r" % (digest, envelope["payloadType"]))
    signatures = envelope["signatures"]
    if len(signatures) != 1:
        fail("%s: %d signatures, want one" % (digest, len(signatures)))
    payload = base64.b64decode(envelope["payload"])
    signature = base64.b64decode(signatures[0]["sig"])
    signed = pre_authentication_encoding(envelope["payloadType"], payload)
    # openssl verifies the signature without a Python crypto dependency, the same
    # way the key was made: no library parses the key for us.
    with tempfile.TemporaryDirectory() as scratch:
        message = os.path.join(scratch, "pae")
        with open(message, "wb") as handle:
            _ = handle.write(signed)
        signature_file = os.path.join(scratch, "sig")
        with open(signature_file, "wb") as handle:
            _ = handle.write(signature)
        verified = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", public_key,
             "-rawin", "-in", message, "-sigfile", signature_file],
            capture_output=True)
    if verified.returncode != 0:
        fail("%s: the envelope signature does not verify" % digest)
    return payload


def canonical(value: object) -> str:
    """A comparable form of a JSON value, so two spellings of one document match."""
    return json.dumps(value, sort_keys=True)


def statement_predicate(payload: bytes, digest: str) -> object:
    return cast(Statement, load(payload, "statement " + digest))["predicate"]


def check_claims(document: Vex, wanted: set[str], platform: str) -> None:
    claimed = {claim["vulnerability"]["name"] for claim in document["statements"]}
    if claimed != wanted:
        fail("%s VEX claims differ: missing %s; unexpected %s"
             % (platform, ",".join(sorted(wanted - claimed)) or "none",
                ",".join(sorted(claimed - wanted)) or "none"))


class Arguments(argparse.Namespace):
    """Typed view of the flags, so `parse_args` fills a known shape."""

    layout: str = ""
    statements: str = ""
    expect: str = ""
    claims: str | None = None
    lock: str = ""
    signed: str = ""


def main() -> None:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--layout", required=True)
    _ = parser.add_argument("--statements", required=True)
    _ = parser.add_argument("--expect", required=True)
    _ = parser.add_argument("--claims", help="exact comma-separated CVE IDs per image")
    _ = parser.add_argument("--lock", required=True, help="lock the image was built from")
    _ = parser.add_argument("--signed", default="",
                            help="public key of the signing key the build used")
    arguments = parser.parse_args(namespace=Arguments())
    layout = arguments.layout
    statements_dir = arguments.statements
    wanted = arguments.expect.split(",")
    claims = None if arguments.claims is None else set(filter(None, arguments.claims.split(",")))
    if claims and "vex" not in wanted:
        fail("expected VEX claims but no VEX attachment type")
    public_key = arguments.signed or None
    with open(arguments.lock, "rb") as handle:
        LOCK.data = cast(Lock, yaml.safe_load(handle))

    with open(os.path.join(layout, "index.json"), "rb") as handle:
        index = cast(Index, load(handle.read(), "index.json"))
    descriptors = index.get("manifests") or []

    # A platform image; the tag descriptors and the build index carry no platform,
    # so only the platform entries describe an image.
    images: dict[str, str] = {}
    attachments: list[Descriptor] = []
    for descriptor in descriptors:
        if "artifactType" in descriptor:
            attachments.append(descriptor)
            continue
        found = descriptor.get("platform")
        if found is None or not found.get("os") or not found.get("architecture"):
            continue
        images[descriptor["digest"]] = "%s/%s" % (found["os"], found["architecture"])
    if not attachments:
        fail("the layout carries no attached statements")
    if not images:
        fail("the layout carries no images")

    # Every platform image gets exactly the statements the caller expected, each
    # attached to that platform and to nothing else.
    received: dict[str, list[str]] = {}
    documents: set[str] = set()
    for descriptor in attachments:
        kind, subject, payload, digest = check_attachment(layout, descriptor, wanted,
                                                         public_key)
        if subject not in images:
            fail("%s is attached to %s, which is not an image in the layout" % (digest, subject))
        # The statement has to describe the image it is attached to, not just carry
        # the right shape.
        predicate = statement_predicate(payload, digest)
        documents.add(canonical(cast(dict[str, object], predicate)))
        attached_to = images[subject]
        if kind == "spdx":
            check_spdx_against_image(layout, descriptor, cast(Spdx, predicate),
                                     subject, attached_to)
        if kind == "provenance":
            check_provenance_against_lock(cast(Provenance, predicate), digest, attached_to)
        if kind == "vex":
            document = cast(Vex, predicate)
            check_vex_against_lock(document, digest, subject, attached_to)
            if claims is not None:
                check_claims(document, claims, attached_to)
        received.setdefault(subject, []).append(kind)
    for subject, attached_to in images.items():
        kinds = sorted(received.get(subject, []))
        if kinds != sorted(wanted):
            fail("%s carries %s, want %s"
                 % (attached_to, ",".join(kinds) or "nothing", ",".join(wanted)))

    # The directory holds each attachment's predicate as a bare document, no more and
    # no fewer, so a reader gets the payload without unwrapping a statement.
    written: set[str] = set()
    for name in sorted(os.listdir(statements_dir)):
        with open(os.path.join(statements_dir, name), "rb") as handle:
            bare = load(handle.read(), "document " + name)
        if not isinstance(bare, dict):
            fail("%s is not a JSON object" % name)
        entry = cast(dict[str, object], bare)
        if "_type" in entry or "predicate" in entry:
            fail("%s holds an in-toto statement, want the bare document" % name)
        written.add(canonical(entry))
    if written != documents:
        fail("the documents written and the predicates attached differ")

    print("%d statements over %d platforms: %s"
          % (len(attachments), len(images), ",".join(wanted)))


if __name__ == "__main__":
    main()
