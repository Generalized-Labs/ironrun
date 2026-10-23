# Primary-source web check

Reviewed October 21, 2026 (America/New_York), against Ironrun source
`803aa420d35af969ca4ff858a374a7dcdf20796d`.

Question: do current primary sources change the paper's prior-work comparison,
arXiv source preparation, or release-verification claims?

Three Exa searches returned 15 ranked results. Seven distinct primary-source
URLs were then fetched. Search rank was used for discovery, not as evidence of
correctness. The findings below concern the relevant retrieved sections; no
vendor implementation was dynamically tested.

## arXiv source and metadata

- [Metadata preparation](https://info.arxiv.org/help/prep.html) still specifies
  ASCII metadata and an abstract limit of 1,920 characters. The checked-in
  `paper/ARXIV.md` abstract is 1,905 ASCII characters, freshly counted.
- [TeX submission instructions](https://info.arxiv.org/help/submit_tex.html)
  accept complete `.bib` sources and can select the bibliography processor.
  A pre-generated `.bbl` is also accepted and takes precedence; its basename
  must match the main `.tex` file. A `.bbl` is therefore not universally required.
  Ironrun's existing bundle includes both `ironrun.bbl` and `references.bib`.
- The same instructions require the submitter to inspect arXiv's generated PDF.
  Local compilation does not replace that check or validate research results,
  author authorization, licensing, endorsement, or moderation eligibility.

Before the related-work correction, the manuscript and PDF at `803aa42` had the following hashes. The follow-up build is recorded separately in `paper-build-summary.json`:

| Artifact | SHA-256 |
| --- | --- |
| `paper/ironrun.tex` | `57dfa06f0628a542d6cc05938a225140805945b54a4204d5a948c79a8a82888e` |
| `paper/ironrun.pdf` | `598da2d529fad85686be24b23e5de5807d64bb6443ee3e5539bc43964c1ed117` |

## Signature verification

- [Sigstore's quickstart](https://docs.sigstore.dev/quickstart/quickstart-cosign/)
  describes checking the blob signature, signing certificate, timestamp, and
  transparency-log material, with an expected identity and OIDC issuer.
- The [cosign v2.4.3 command reference](https://github.com/sigstore/cosign/blob/v2.4.3/doc/cosign_verify-blob.md)
  confirms the identity/issuer flags for the installer's pinned verifier.
  Current documentation alone is not substituted for that version-specific
  reference. The broader [verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/)
  covers additional modes that Ironrun need not use.
- Source inspection finds the expected identity/issuer checks in `install.sh`,
  `action.yml`, and `.github/workflows/release.yml`. Earlier regression and real
  historical-asset verification results remain separately scoped evidence.

Interpretation: signature verification binds an artifact to signing material and
the configured identity policy. It does not by itself establish that the code is
safe, that binaries reproduce a clean source checkout, or that a future release
has passed verification. The historical public binaries' `vcs.modified=true`
therefore remains relevant even though their signatures verify.

## 1Password prior work

- The official [`op run` reference](https://www.1password.dev/cli/reference/commands/run)
  says stdout/stderr secrets are concealed by default and provides `--no-masking`
  to turn this off. The current manuscript acknowledges that output masking is
  already provided by this prior system.
- The official [CLI release notes](https://releases.1password.com/developers/cli/)
  entry for 2.40.0, dated October 1, 2026, states: “Clarified in `op run` help
  text that secret masking on stdout and stderr is best effort and does not
  guarantee concealment.” This supports carefully bounded comparison language;
  it does not establish that Ironrun has strictly stronger empirical coverage.

The closest-system review of fnox and Prismor is recorded separately. Absence of
a feature from a retrieved passage is not treated as proof that the system lacks
that feature.

## Status

High confidence in the cited documentation's stated requirements and the local
abstract count. This pass adds current primary-source evidence; it does not
resolve the missing historical audit/performance records. Author/order/license
and launch-target questions remain with the user. The subsequent manuscript correction acknowledges the documented overlap and removes broad missing-design/firstness wording. Runtime source is unchanged.
