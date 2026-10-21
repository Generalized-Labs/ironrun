# Homebrew formula-to-cask migration

GoReleaser 2.18.2 generates `Casks/ironrun.rb` for the precompiled Linux and
macOS archives. Its deprecated `brews` integration generated a formula that
installed precompiled binaries. GoReleaser now recommends casks for this use,
including Linuxbrew. See the [deprecation and migration instructions](https://goreleaser.com/resources/deprecations/#brews)
and [cask configuration](https://goreleaser.com/customization/homebrew_casks/).

The configuration preserves the versioned tap branch, draft pull request, and
`skip_upload: auto` behavior. A stable release stages a tap change for review;
prereleases are not automatically installed from the tap. GitHub release assets
remain draft until the release workflow signs and verifies them. Publishing the
GitHub release does not merge the tap pull request.

## Maintainer steps in `generalized-labs/homebrew-tap`

After the signed GitHub release is public and its artifacts have been verified:

1. Review the generated draft pull request's `Casks/ironrun.rb`. Check all four
   archive URLs, archive SHA-256 digests, version, and `binary "ironrun"` entry
   against that exact release. Snapshot-generated casks are validation fixtures;
   they are not installable release metadata.
2. In the same reviewed tap change, merge the following entry into the tap-root
   `tap_migrations.json`, preserving any existing entries:

   ```json
   {
     "ironrun": "ironrun"
   }
   ```

3. Remove the old `Formula/ironrun.rb` from the tap. The migration entry directs
   existing formula installations to the same-named cask on upgrade. The
   `Formula/ironrun.rb` in this source repository is historical packaging; the
   live tap is the destination of this migration.
4. Test clean installation and upgrade from the previous formula on actual
   macOS and Linux Homebrew installations before merging. For a clean install,
   select the cask explicitly with
   `brew install --cask generalized-labs/tap/ironrun`. For upgrade coverage, start
   with the previous formula installed, apply the reviewed tap change in a test
   tap, run `brew update` and `brew upgrade ironrun`, and check that the formula
   migrates to the cask. Verify `ironrun version -v` and a credential-free command
   after both paths. A generated Ruby file alone does not prove either path.
5. Merge the tap change only after those checks pass. Keep the migration entry
   for existing users. This repository change does not modify or remove anything
   in the external tap.

## macOS signing gate

Casks use macOS quarantine and Gatekeeper behavior. Sigstore bundles authenticate
release provenance; they do not provide Apple Developer ID signing or
notarization. The current release configuration does not establish Apple
notarization. Actual macOS cask installation and execution must pass before the
maintainer merges the migration. Arrange the appropriate Apple signing and
notarization if required by that check.

No quarantine-removal hook, Gatekeeper bypass, or destructive uninstall/zap step
is configured. Vaults and user credentials are not part of the migration.

## Local validation

Run the pinned `goreleaser check` and a credential-free snapshot with publication,
signing, SBOM generation, and before hooks skipped. Inspect
`dist/homebrew/Casks/ironrun.rb` and compare each platform digest to its generated
archive. These checks establish configuration and generation behavior. Final
release signing, Homebrew execution, and formula-to-cask upgrades still require
the gates above.
