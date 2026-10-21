# One-time npm bootstrap for `@generalized-labs/ironrun`

The release workflow publishes the npm launcher with **OIDC trusted publishing**
(no long-lived token). Trusted publishing can only be configured on a package
that already exists, so the **first publish must be done manually**. Until this
is complete, `npx @generalized-labs/ironrun` is not an available install method.
The npm release step is temporarily non-blocking; it must become a hard gate
before a v1 GA release.

## Do this once (needs an npm account with rights to the `@generalized-labs` scope)

```bash
# 1. Log in (2FA strongly recommended).
npm login

# 2. Create the org/scope if it does not exist yet:
#    https://www.npmjs.com/org/create  ->  name: generalized-labs
#    (a free org is fine for public scoped packages)

# 3. From the repository root, prepare the exact signed release artifacts.
# Set this to the already-published release being bootstrapped, not a snapshot.
release_tag=vX.Y.Z
mkdir -p dist
gh release download "$release_tag" --dir dist --clobber \
  --pattern 'ironrun_*.tar.gz' --pattern 'checksums.txt' \
  --pattern '*.sigstore.json'
# Follow docs/INSTALL.md to verify checksums.txt and each archive using
# the release workflow's Sigstore identity for this exact tag BEFORE proceeding.

# 4. Generate the package version and immutable hashes from those archives.
# This checks each archive against checksums.txt and hashes the extracted binary.
node npm/scripts/build-manifest.mjs "$release_tag" dist
node --test npm/test/*.test.js
npm --prefix npm run validate-manifest

# 5. Inspect and publish the prepared launcher package.
cd npm
npm pack --dry-run
npm publish --access public --tag latest
```

Use `--tag next` for any prerelease (alpha, beta, or RC), and `latest` only for
a stable release. The checked-in manifest is deliberately unprepared; publishing
directly from checkout is refused by `prepublishOnly`. Do not bypass lifecycle
scripts with `--ignore-scripts`. Metadata validation checks version, all four
platforms, filenames, sizes, and digest formats; it does not replace signature
verification of the release inputs. Keep the prepared package and manifest
together, and never hand-fill artifact hashes.

## Then enable trusted publishing (so CI publishes every future release)

1. npmjs.com → the `@generalized-labs/ironrun` package → **Settings → Trusted
   Publisher** → add a GitHub Actions publisher:
   - Repository: `generalized-labs/ironrun`
   - Workflow: `release.yml`
2. Remove the two `continue-on-error: true` lines from the npm steps in
   `.github/workflows/release.yml` to make npm publishing a hard gate again.

After that, tagging `vX.Y.Z` publishes the binaries (GitHub release), the npm
launcher (`npx @generalized-labs/ironrun`), and the Sigstore bundles in one run.

> v0.4.0 shipped without the npm launcher and without Sigstore signatures (the
> npm step failing skipped signing on that run). Both are pre-1.0 / GA-gate
> items, not required for v0.4.0. The next tagged release after this bootstrap
> gets all three.
