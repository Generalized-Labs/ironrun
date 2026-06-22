# Examples

Copy one of these to your project root as `ironrun.yml`, edit the command IDs,
`argv`, and secret references, then run `ironrun doctor` to check your setup.

| File | Stack / provider | Shows |
|---|---|---|
| [`local-envfile.yml`](local-envfile.yml) | any / `envfile` | Local dev with secrets in a file — no cloud account needed |
| [`go-service-1password.yml`](go-service-1password.yml) | Go service / `1password` | `op://` references, deploy with multiple secrets |
| [`nextjs-doppler.yml`](nextjs-doppler.yml) | Next.js / `doppler` | `doppler://` references, dev + build + migrate |
| [`python-vault.yml`](python-vault.yml) | Python / `vault` | `vault://path#field`, `no_network` on tests |
| [`ci-github-action.yml`](ci-github-action.yml) | GitHub Actions | Running a sealed command in CI via the ironrun action |

## Reference format per provider

| Provider | Reference | Example |
|---|---|---|
| `envfile` | plain `NAME` (set `provider: "envfile:<path>"`) | `API_KEY` |
| `1password` | `op://vault/item/field` | `op://prod/db/url` |
| `vault` | `vault://<path>#<field>` | `vault://secret/myapp#DB_URL` |
| `doppler` | `doppler://project/config/NAME` or `NAME` | `doppler://app/prod/DB_URL` |
| `infisical` | `infisical://projectId/env/NAME` or `NAME` | `infisical://abc/prod/DB_URL` |
| `env` | `env:NAME` or `NAME` | `env:DATABASE_URL` |

See the [main README](../README.md#where-secrets-come-from) for full details.
