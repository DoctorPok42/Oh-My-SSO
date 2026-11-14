# Releasing

Versions follow [semantic versioning](https://semver.org). The image tags are `doctorpok/omsso:<image>-X.Y.Z`.

## Publish a version

1. Move the **Unreleased** notes of [CHANGELOG.md](../CHANGELOG.md) under `## [X.Y.Z] - date` (`X.Y.Z-rc.N` for a
   pre-release). Under **Manual steps**, write what to do by hand before or after
   `scripts/deploy.sh --version X.Y.Z`: a setting to add, a compose file to update, a migration that cannot be rolled
   back.
2. Merge, and wait for the CI of that commit: its `docker` job pushes the images the release re-tags.
3. Tag that commit: `git tag vX.Y.Z <sha> && git push origin vX.Y.Z`.

The `Release` workflow then checks the tag (semantic version, on `main`, notes present), re-tags the images the CI
built for that commit (it never rebuilds, and never replaces an existing version), signs them with cosign and
attaches their SBOM, and creates the GitHub release with the notes. A tag with a `-` (`1.0.0-rc.1`) is a pre-release.

## Verify an image

See [PRODUCTION.md](PRODUCTION.md), "Images".
