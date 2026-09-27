#!/usr/bin/env node
// CLI entry point for @generalized-labs/ironrun.
//
// Never executes anything unverified: lib/launcher.js resolves the native
// binary for this platform from the pinned GitHub release, verifies the
// archive AND the extracted binary against the release manifest hashes,
// caches the verified binary, and only then spawns it.
import { launch } from "../lib/launcher.js";

await launch(process.argv.slice(2));
