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

# 3. First manual publish from the built launcher package.
cd npm
npm publish --access public --tag latest
```

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
