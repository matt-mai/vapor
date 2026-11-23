import hashlib
import io
import json
import tarfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import attestations


class SpdxChecksumsTest(unittest.TestCase):
    def test_sha1_must_match_layer_even_with_correct_sha256(self):
        body = b"hello\n"
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            member = tarfile.TarInfo("hello")
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        raw = layer.getvalue()
        blobs = {
            "manifest": json.dumps({"config": {"digest": "config"}, "layers": [
                {"digest": "layer", "mediaType": "application/vnd.oci.image.layer.v1.tar"}]}).encode(),
            "config": json.dumps({"rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]}}).encode(),
            "layer": raw,
        }
        checksums = [
            {"algorithm": "SHA1", "checksumValue": "0" * 40},
            {"algorithm": "SHA256", "checksumValue": hashlib.sha256(body).hexdigest()},
        ]
        predicate = {"spdxVersion": "SPDX-2.3", "files": [{"fileName": "hello", "checksums": checksums}]}
        with patch.object(attestations, "blob", side_effect=lambda _layout, digest: blobs[digest]):
            with self.assertRaisesRegex(SystemExit, "SPDX SHA1 checksum for /hello"):
                attestations.check_spdx_against_image("unused", {"digest": "spdx"}, predicate, "manifest", "linux/amd64")


class ElementKindTest(unittest.TestCase):
    def test_a_vendored_module_is_recognised(self):
        element = {"comment": attestations.MODULE_COMMENT}
        self.assertEqual(attestations.element_kind(element), "module")

    def test_an_unknown_comment_is_not_an_element(self):
        self.assertIsNone(attestations.element_kind({"comment": "something else"}))


class VexClaimsTest(unittest.TestCase):
    def test_exact_claims_for_each_platform(self):
        expected = ["CVE-2026-0001", "CVE-2026-0002"]
        platforms = ["amd64", "arm64"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lock.yaml").write_text("{}\n")
            (root / "statements").mkdir()
            descriptors = [{"digest": arch, "platform": {"os": "linux", "architecture": arch}}
                           for arch in platforms]
            descriptors += [{"digest": arch, "artifactType": "vex"} for arch in platforms]
            (root / "index.json").write_text(json.dumps({"manifests": descriptors}))
            args = ["attestations.py", "--layout", directory, "--statements", str(root / "statements"),
                    "--lock", str(root / "lock.yaml"), "--expect", "vex", "--claims", ",".join(expected)]

            for arm_claims, error in [(expected, None), (expected[:1], "missing CVE-2026-0002"),
                                      (expected + ["CVE-2026-0003"], "unexpected CVE-2026-0003")]:
                with self.subTest(arm_claims=arm_claims):
                    def claims(arch):
                        return expected if arch == "amd64" else arm_claims

                    def predicate(arch):
                        return {"statements": [{"vulnerability": {"name": name}} for name in claims(arch)]}

                    # The directory holds the bare document of every attachment, so the
                    # fixture writes what each statement's predicate carries.
                    for arch in platforms:
                        document = json.dumps(predicate(arch)).encode()
                        (root / "statements" / arch).write_bytes(document)

                    def attachment(_layout, descriptor, _wanted, _public_key):
                        arch = descriptor["digest"]
                        payload = json.dumps({"predicate": predicate(arch)}).encode()
                        return "vex", arch, payload, hashlib.sha256(payload).hexdigest()

                    with (patch("sys.argv", args), patch.object(attestations, "check_attachment", side_effect=attachment),
                          patch.object(attestations, "check_vex_against_lock")):
                        if error is None:
                            attestations.main()
                        else:
                            with self.assertRaisesRegex(SystemExit, f"linux/arm64 VEX claims differ: .*{error}"):
                                attestations.main()


if __name__ == "__main__":
    unittest.main()
