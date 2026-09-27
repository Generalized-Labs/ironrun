// Postinstall for @generalized-labs/ironrun.
//
// Pre-warms the verified native-binary cache so the first `npx ironrun`
// (or `ironrun` via the package bin) does not pay the download cost.
//
// Fail-open by design: a missing network, an unpublished release, or an
// unsupported platform only prints a warning. The launcher (lib/launcher.js)
// re-verifies size + SHA-256 lazily on every run and refuses to execute
// anything that does not match the release manifest, so skipping the
// pre-warm can never weaken the verification story.
import { verifiedBinary } from "../lib/launcher.js";

try {
  const path = await verifiedBinary();
  console.log(`[ironrun] verified native binary cached at ${path}`);
} catch (error) {
  console.warn(`[ironrun] postinstall: ${error.message}`);
  console.warn("[ironrun] the binary will be fetched and verified on first run instead.");
}
