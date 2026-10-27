# Headwire package repositories

Signed APT and RPM repositories at <https://pkgs.headwire.org>.

Publishes the latest three immutable stable releases from `brofranks/headwire`,
starting at `v0.2.1`, for amd64 and arm64. Packages are verified before signing
repository metadata. Publication is manual on `main`; PRs and pushes run checks.

Run local checks:

```sh
bash scripts/check.sh
```
