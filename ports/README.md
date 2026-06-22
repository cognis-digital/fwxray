# Ports of fwxray

The fwxray **core check** — Shannon entropy + magic-signature carving over a
firmware image — ported across languages so you can drop it into any stack or
ship a single static binary. Every port is **passive and offline**: it reads one
image and emits the same JSON shape:

```json
{"tool":"fwxray","path":"fw.bin","size":1545,"entropy":2.9333,
 "sections":[{"label":"elf","offset":133}]}
```

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../fwxray/` | `fwxray inspect fw.bin` | `pytest -q` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js fw.bin` | `cd ports/javascript && node --test` |
| Go | `go/` | `cd ports/go && go run . ../../demos/05-debug-backdoor/new.bin` | `cd ports/go && go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- ../../demos/05-debug-backdoor/new.bin` | `cd ports/rust && cargo test` |
| Shell (POSIX) | `shell/` | `bash ports/shell/fwxray.sh fw.bin` | `bash ports/shell/test.sh` |

All ports agree byte-for-byte on entropy (verified against the Python reference).
Go and Rust are built + tested on GitHub runners by `.github/workflows/ports.yml`
(the Go/Rust toolchains are not assumed present locally); Python, JavaScript, and
Shell are also verified locally.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
