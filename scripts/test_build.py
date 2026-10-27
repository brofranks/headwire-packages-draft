"""Exercise release selection and real package metadata/signature verification."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build


def release(version, **fields):
    return {
        "tag_name": version,
        "draft": False,
        "prerelease": False,
        "published_at": "2026-10-01T00:00:00Z",
        "immutable": True,
        **fields,
    }


class SelectionTests(unittest.TestCase):
    def test_numeric_order_stable_floor_and_retention(self):
        records = [release(tag) for tag in ("v0.2.0", "v0.2.1", "v0.2.9", "v0.2.10", "v0.3.0", "v0.3.1-rc1")]
        records.extend((release("v1.0.0", draft=True), release("v2.0.0", prerelease=True)))
        self.assertEqual([r["tag_name"] for r in build.releases(records)], ["v0.3.0", "v0.2.10", "v0.2.9"])

    def test_missing_and_mutable_releases_fail(self):
        for records in ([], [release("v0.2.1", immutable=False)]):
            with self.assertRaises(ValueError):
                build.releases(records)

    def test_checksum_paths_duplicates_and_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            package = directory / "headwire.deb"
            package.write_bytes(b"package")
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            manifest = directory / "SHA256SUMS"
            manifest.write_text(f"{digest}  ./headwire.deb\n")
            build.verify_hash(package, build.checksums(manifest))
            package.write_bytes(b"corrupted")
            with self.assertRaises(ValueError):
                build.verify_hash(package, build.checksums(manifest))
            for name in ("../headwire.deb", "/headwire.deb", "headwire.deb\n" + f"{digest}  headwire.deb"):
                manifest.write_text(f"{digest}  {name}\n")
                with self.assertRaises(ValueError):
                    build.checksums(manifest)


class PackageTests(unittest.TestCase):
    def test_rpm_signature_output(self):
        for signature in ("RSA/SHA256 Signature", "RSA/SHA256 signature"):
            with self.subTest(signature=signature):
                with patch.object(build, "run", side_effect=[f"{signature}: OK", "headwire\n0.2.1\nx86_64"]):
                    build.verify_package(Path("headwire.rpm"), "0.2.1", "amd64", Path("rpmdb"))
        for output in (
            "Header SHA256 digest: OK",
            "RSA/SHA256 signature: NOT OK",
            "RSA/SHA256 signature: NOKEY",
            "RSA/SHA256 signature: NOTTRUSTED",
            "RSA/SHA256 signature: OK\nPayload SHA256 digest: NOT OK",
        ):
            with self.subTest(output=output):
                with patch.object(build, "run", return_value=output), self.assertRaises(ValueError):
                    build.verify_package(Path("headwire.rpm"), "0.2.1", "amd64", Path("rpmdb"))

    def test_signed_repository_and_package_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            home = work / "gnupg"
            home.mkdir(mode=0o700)
            with patch.dict(os.environ, {"GNUPGHOME": str(home), "REPOSITORY_PASSPHRASE": ""}):
                build.run(
                    "gpg",
                    "--batch",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--quick-generate-key",
                    "Package test <test@example.com>",
                    "rsa2048",
                    "sign",
                    "0",
                )
                key = work / "key.asc"
                key.write_text(build.run("gpg", "--armor", "--export"))
                signer = build.fingerprint(key)
                database = work / "rpmdb"
                build.run("rpm", "--dbpath", str(database), "--initdb")
                build.run("rpm", "--dbpath", str(database), "--import", str(key))
                fixtures = work / "headwire"
                (fixtures / "apt/pool/main").mkdir(parents=True)
                for arch, rpm_arch in build.ARCHITECTURES.items():
                    deb_tree = work / f"deb-{arch}"
                    (deb_tree / "DEBIAN").mkdir(parents=True)
                    (deb_tree / "DEBIAN/control").write_text(
                        f"Package: headwire\nVersion: 0.2.1\nArchitecture: {arch}\nMaintainer: Test <test@example.com>\n"
                        "Description: Package test fixture\n"
                    )
                    deb = fixtures / f"apt/pool/main/headwire_v0.2.1_linux_{arch}.deb"
                    build.run("dpkg-deb", "--build", str(deb_tree), str(deb))
                    build.verify_package(deb, "0.2.1", arch, database)
                    control = deb_tree / "DEBIAN/control"
                    control.write_text(control.read_text().replace("Package: headwire", "Package: other"))
                    other = work / f"other-{arch}.deb"
                    build.run("dpkg-deb", "--build", str(deb_tree), str(other))
                    with self.assertRaises(ValueError):
                        build.verify_package(other, "0.2.1", arch, database)
                    top = work / f"rpm-{arch}"
                    spec = work / f"{arch}.spec"
                    spec.write_text(
                        "Name: headwire\nVersion: 0.2.1\nRelease: 1\nSummary: Fixture\nLicense: BSD\n"
                        "%description\nFixture\n%install\nmkdir -p %{buildroot}/usr/share/headwire\n"
                        "echo fixture > %{buildroot}/usr/share/headwire/test\n%files\n/usr/share/headwire/test\n"
                    )
                    build.run(
                        "rpmbuild",
                        "--nodeps",
                        "--define",
                        f"_topdir {top}",
                        "--dbpath",
                        str(database),
                        "--target",
                        rpm_arch,
                        "-bb",
                        str(spec),
                    )
                    rpm_directory = fixtures / f"rpm/{rpm_arch}/Packages"
                    rpm_directory.mkdir(parents=True)
                    rpm = rpm_directory / f"headwire_v0.2.1_linux_{arch}.rpm"
                    shutil.copyfile(next((top / "RPMS").rglob("*.rpm")), rpm)
                    with self.assertRaises(ValueError):
                        build.verify_package(rpm, "0.2.1", arch, database)
                    build.run(
                        "rpmsign",
                        "--define",
                        f"_gpg_name {signer}",
                        "--define",
                        "__gpg /usr/bin/gpg",
                        "--define",
                        "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase ''",
                        "--addsign",
                        str(rpm),
                    )
                    build.verify_package(rpm, "0.2.1", arch, database)
                    with self.assertRaises(ValueError):
                        build.verify_package(rpm, "0.2.2", arch, database)
                    empty_database = work / f"empty-{arch}"
                    build.run("rpm", "--dbpath", str(empty_database), "--initdb")
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        build.verify_package(rpm, "0.2.1", arch, empty_database)
                source = work / "source"
                (source / "keys").mkdir(parents=True)
                for name in ("repository.asc", "headwire-rpm.asc"):
                    shutil.copyfile(key, source / "keys" / name)
                packages = [*fixtures.rglob("*.deb"), *fixtures.rglob("*.rpm")]
                records = release("v0.2.1")
                real_run = build.run
                provenance = []

                def fake_github(*arguments, **kwargs):
                    if arguments[:2] == ("gh", "api"):
                        return json.dumps([[records]])
                    if arguments[:3] == ("gh", "release", "download"):
                        downloaded = Path(arguments[arguments.index("--dir") + 1])
                        for package in packages:
                            shutil.copyfile(package, downloaded / package.name)
                        (downloaded / "SHA256SUMS").write_text(
                            "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  ./{p.name}\n" for p in packages)
                        )
                        return ""
                    if arguments[:3] == ("gh", "attestation", "verify"):
                        provenance.append(arguments)
                        return "verified fixture"
                    return real_run(*arguments, **kwargs)

                with patch.object(build, "ROOT", source), patch.object(build, "run", side_effect=fake_github):
                    build.build(work / "site")
                self.assertEqual(len(provenance), 4)
                self.assertTrue(all("refs/tags/v0.2.1" in arguments for arguments in provenance))
                for arguments in provenance:
                    self.assertEqual(arguments[arguments.index("--repo") + 1], "brofranks/headwire")
                    self.assertEqual(
                        arguments[arguments.index("--signer-workflow") + 1],
                        "brofranks/headwire/.github/workflows/release.yml",
                    )
                    self.assertIn("--deny-self-hosted-runners", arguments)
                site = work / "site"
                self.assertEqual((site / "CNAME").read_text(), "pkgs.headwire.org\n")
                self.assertIn(
                    "baseurl=https://pkgs.headwire.org/rpm/$basearch\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1",
                    (site / "headwire.repo").read_text(),
                )
                self.assertIn(
                    "Signed-By: /etc/apt/keyrings/headwire-packages.asc", (site / "headwire.sources").read_text()
                )
                distribution = site / "apt/dists/stable"
                build.run("gpg", "--verify", str(distribution / "InRelease"))
                self.assertNotIn("Valid-Until:", (distribution / "Release").read_text())
                for arch, rpm_arch in build.ARCHITECTURES.items():
                    index = (distribution / f"main/binary-{arch}/Packages").read_text()
                    self.assertIn(f"Architecture: {arch}\n", index)
                    self.assertEqual(index.count("Package: headwire\n"), 1)
                    metadata = site / f"rpm/{rpm_arch}/repodata/repomd.xml"
                    build.run("gpg", "--verify", str(metadata) + ".asc", str(metadata))
                signed = distribution / "InRelease"
                signed.write_text(signed.read_text().replace("Suite: stable", "Suite: tampered"))
                with self.assertRaises(subprocess.CalledProcessError):
                    build.run("gpg", "--verify", str(signed))


if __name__ == "__main__":
    unittest.main()
