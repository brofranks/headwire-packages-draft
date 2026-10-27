#!/usr/bin/env python3
"""Verify published release packages and build the signed package website."""

import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://pkgs.headwire.org"
REPOSITORY = "brofranks/headwire"
MINIMUM = (0, 2, 1)
ARCHITECTURES = {"amd64": "x86_64", "arm64": "aarch64"}
RETAIN = 3


def run(*args, cwd=None, input=None):
    return subprocess.run(args, cwd=cwd, input=input, text=True, check=True, stdout=subprocess.PIPE).stdout


def fingerprint(key):
    lines = run("gpg", "--batch", "--with-colons", "--show-keys", str(key)).splitlines()
    if sum(line.startswith("pub:") for line in lines) != 1:
        raise ValueError(f"{key}: expected one public key")
    return next(line.split(":")[9] for line in lines if line.startswith("fpr:"))


def releases(records):
    selected = {}
    for release in records:
        match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", release["tag_name"])
        if not match or release["draft"] or release["prerelease"]:
            continue
        version = tuple(map(int, match.groups()))
        if version < MINIMUM:
            continue
        if not release["immutable"]:
            raise ValueError(f"{release['tag_name']}: published release is mutable")
        selected[version] = release
    if not selected:
        raise ValueError("no eligible published immutable release")
    return [selected[version] for version in sorted(selected, reverse=True)[:RETAIN]]


def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](?:\./)?([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        if not match or match[2] in result:
            raise ValueError(f"invalid or duplicate checksum entry: {line}")
        result[match[2]] = match[1]
    return result


def verify_hash(path, manifest):
    with path.open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != manifest[path.name]:
            raise ValueError(f"checksum mismatch: {path.name}")


def verify_package(path, version, architecture, rpm_database):
    if path.suffix == ".deb":
        fields = run("dpkg-deb", "--field", str(path), "Package", "Version", "Architecture")
        actual = dict(line.split(": ", 1) for line in fields.splitlines())
        expected = {"Package": "headwire", "Version": version, "Architecture": architecture}
        if actual != expected:
            raise ValueError(f"unexpected DEB identity: {actual}, expected {expected}")
        return
    signatures = run("rpmkeys", "--dbpath", str(rpm_database), "--checksig", "--verbose", str(path))
    if not re.search(r"Signature[^\n]*: OK", signatures, re.IGNORECASE) or re.search(
        r"NOT OK|NOKEY|NOTTRUSTED", signatures
    ):
        raise ValueError(f"RPM signature was not verified: {signatures}")
    actual = run("rpm", "--dbpath", str(rpm_database), "-qp", "--qf", "%{NAME}\n%{VERSION}\n%{ARCH}", str(path))
    expected = f"headwire\n{version}\n{ARCHITECTURES[architecture]}"
    if actual != expected:
        raise ValueError(f"unexpected RPM identity: {actual!r}, expected {expected!r}")


def download_release(release, destination, rpm_database):
    tag = release["tag_name"]
    names = [f"headwire_{tag}_linux_{arch}.{kind}" for arch in ARCHITECTURES for kind in ("deb", "rpm")]
    destination.mkdir()
    arguments = ["gh", "release", "download", tag, "--repo", REPOSITORY, "--dir", str(destination)]
    for name in ["SHA256SUMS", *names]:
        arguments.extend(("--pattern", name))
    run(*arguments)
    manifest = checksums(destination / "SHA256SUMS")
    for architecture in ARCHITECTURES:
        for kind in ("deb", "rpm"):
            package = destination / f"headwire_{tag}_linux_{architecture}.{kind}"
            verify_hash(package, manifest)
            run(
                "gh",
                "attestation",
                "verify",
                str(package),
                "--repo",
                REPOSITORY,
                "--signer-workflow",
                f"{REPOSITORY}/.github/workflows/release.yml",
                "--source-ref",
                f"refs/tags/{tag}",
                "--deny-self-hosted-runners",
            )
            verify_package(package, tag[1:], architecture, rpm_database)


def sign(source, destination, signing_key, *, clear=False):
    run(
        "gpg",
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--local-user",
        signing_key,
        "--digest-algo",
        "SHA256",
        "--armor",
        "--output",
        str(destination),
        "--clearsign" if clear else "--detach-sign",
        str(source),
        input=os.environ["REPOSITORY_PASSPHRASE"] + "\n",
    )


def metadata(output, signing_key):
    apt = output / "apt"
    distribution = apt / "dists/stable"
    for architecture in ARCHITECTURES:
        index = distribution / f"main/binary-{architecture}"
        index.mkdir(parents=True)
        (index / "Packages").write_text(run("apt-ftparchive", "-a", architecture, "packages", "pool", cwd=apt))
    release = run(
        "apt-ftparchive",
        "-o",
        "APT::FTPArchive::Release::Origin=Headwire",
        "-o",
        "APT::FTPArchive::Release::Label=Headwire",
        "-o",
        "APT::FTPArchive::Release::Suite=stable",
        "-o",
        "APT::FTPArchive::Release::Codename=stable",
        "-o",
        "APT::FTPArchive::Release::Components=main",
        "-o",
        "APT::FTPArchive::Release::Architectures=amd64 arm64",
        "release",
        "dists/stable",
        cwd=apt,
    )
    (distribution / "Release").write_text(release)
    sign(distribution / "Release", distribution / "InRelease", signing_key, clear=True)
    for architecture in ARCHITECTURES.values():
        repository = output / f"rpm/{architecture}"
        run("createrepo_c", "--checksum", "sha256", "--general-compress-type", "gz", str(repository))
        sign(repository / "repodata/repomd.xml", repository / "repodata/repomd.xml.asc", signing_key)


def bootstrap(output, repository_key, rpm_key):
    shutil.copyfile(repository_key, output / "repository.asc")
    shutil.copyfile(rpm_key, output / "headwire-rpm.asc")
    (output / "headwire.sources").write_text(
        f"Types: deb\nURIs: {SITE}/apt\nSuites: stable\nComponents: main\n"
        "Architectures: amd64 arm64\nSigned-By: /etc/apt/keyrings/headwire-packages.asc\n"
    )
    (output / "headwire.repo").write_text(
        f"[headwire]\nname=Headwire\nbaseurl={SITE}/rpm/$basearch\n"
        "enabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n"
        f"gpgkey={SITE}/headwire-rpm.asc {SITE}/repository.asc\n"
    )
    instructions = f"""APT (Debian and Ubuntu):
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL {SITE}/repository.asc -o /etc/apt/keyrings/headwire-packages.asc
sudo chmod 0644 /etc/apt/keyrings/headwire-packages.asc
sudo curl -fsSL {SITE}/headwire.sources -o /etc/apt/sources.list.d/headwire.sources
sudo apt update
sudo apt install headwire

DNF (Fedora and Rocky Linux):
sudo curl -fsSL {SITE}/headwire.repo -o /etc/yum.repos.d/headwire.repo
sudo dnf install headwire

zypper (openSUSE, choose x86_64 or aarch64):
sudo rpm --import {SITE}/repository.asc {SITE}/headwire-rpm.asc
sudo zypper addrepo --refresh --gpgcheck-strict {SITE}/rpm/x86_64 headwire
sudo zypper refresh
sudo zypper install headwire
"""
    (output / "index.html").write_text(
        "<!doctype html><html lang=en><meta charset=utf-8><title>Headwire packages</title>"
        "<h1>Headwire packages</h1><p>Architectures: amd64 / x86_64 and arm64 / aarch64.</p>"
        f"<p>Repository signing key: <code>{fingerprint(repository_key)}</code><br>"
        f"RPM signing key: <code>{fingerprint(rpm_key)}</code></p><pre>{html.escape(instructions)}</pre>"
        "<p>Metadata signatures authenticate packages. Metadata has no expiry, so old signed metadata can be replayed."
        " Updates to an active service restart it. Initial installation does not start or enable it.</p></html>"
    )
    (output / "CNAME").write_text("pkgs.headwire.org\n")
    (output / ".nojekyll").touch()


def build(output):
    repository_key = ROOT / "keys/repository.asc"
    rpm_key = ROOT / "keys/headwire-rpm.asc"
    output.mkdir()
    (output / "apt/pool/main").mkdir(parents=True)
    for architecture in ARCHITECTURES.values():
        (output / f"rpm/{architecture}/Packages").mkdir(parents=True)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        records = json.loads(run("gh", "api", "--paginate", "--slurp", f"repos/{REPOSITORY}/releases"))
        rpm_database = work / "rpmdb"
        run("rpm", "--dbpath", str(rpm_database), "--initdb")
        run("rpm", "--dbpath", str(rpm_database), "--import", str(rpm_key))
        for release in releases([release for page in records for release in page]):
            downloaded = work / release["tag_name"]
            download_release(release, downloaded, rpm_database)
            for architecture, rpm_architecture in ARCHITECTURES.items():
                name = f"headwire_{release['tag_name']}_linux_{architecture}"
                shutil.move(downloaded / f"{name}.deb", output / f"apt/pool/main/{name}.deb")
                shutil.move(downloaded / f"{name}.rpm", output / f"rpm/{rpm_architecture}/Packages/{name}.rpm")
    metadata(output, fingerprint(repository_key))
    bootstrap(output, repository_key, rpm_key)


if __name__ == "__main__":
    build(ROOT / "site")
