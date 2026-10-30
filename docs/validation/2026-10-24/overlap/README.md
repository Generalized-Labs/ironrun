# Overlap counterexample supporting the paper correction

This is one synthetic counterexample to the paper's former general claim that
overlap exposure was limited to eleven bytes. It is **not** a runtime change or a
new general bound. Register `prefix-X` and `Xabcdefghijklmnopqrstuv`, including
`Encodings(value, 8)` for each. On input `prefix-Xabcdefghijklmnopqrstuv`, the
current redactor emits `[REDACTED]abcdefghijklmnopqrstuv`: 22 of the second
value's 23 bytes remain contiguously visible. Batch and one-byte writes produce
the same output. Chunking invariance does not establish confidentiality for
overlapping matches.

`result.json` retains the observed output, command, compiler, and scope.
`source-hashes.json` identifies the **original repository bytes** of
`internal/redact/redact.go` and `internal/redact/encodings.go`. The standalone
probe used those files with only `package redact` changed to `package main`.
The current runtime manifest in `../runtime/source-manifest.json` independently
contains both original hashes. `main.go.txt` reports an explicit expected residual
count; the output string itself permits checking that count independently.
The text suffix keeps the standalone probe out of normal repository builds.

To replay from the repository root using Go 1.26.10, the following creates an
isolated temporary copy, verifies source identity, changes only package names,
and runs the probe. Use a Go installation that reports `go1.26.10`, rather than
the GNU Go game executable sometimes installed as `/usr/bin/go`.

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, os, shutil, subprocess, tempfile

root = Path.cwd()
evidence = root / 'docs/validation/2026-10-24/overlap'
hashes = json.loads((evidence / 'source-hashes.json').read_text())
with tempfile.TemporaryDirectory(prefix='ironrun-overlap-') as temporary:
    replay = Path(temporary)
    shutil.copyfile(evidence / 'main.go.txt', replay / 'main.go')
    for name, expected in hashes.items():
        source = (root / 'internal/redact' / name).read_bytes()
        assert hashlib.sha256(source).hexdigest() == expected, name
        assert source.count(b'package redact\n') == 1, name
        (replay / name).write_bytes(
            source.replace(b'package redact\n', b'package main\n', 1))
    environment = dict(os.environ, GO111MODULE='off')
    subprocess.run(['go', 'run', 'main.go', 'redact.go', 'encodings.go'],
                   cwd=replay, env=environment, check=True)
PY
```

This probe uses two hand-selected values and does not measure a leak rate,
arbitrary transformations, production behavior, or a universal maximum residual.
The paper now states that the surviving suffix depends on value length and
matching tier, while retaining the separate streaming property.

`artifact-manifest.json` inventories this directory except itself.
