# CLAUDE.md

@AGENTS.md

## Start here

1. Find the feature in `docs/FEATUREMAP.md`, or the file in `docs/CODEMAP.md`. Use the recipes there for adding a transport, arg, flag or port.
2. Put logic in `domain`, traits in `ports`, I/O in `adapters`, wiring in `src/main.rs`. `cargo test --test architecture` tells you when a layer rule is broken.
3. Finish with `cargo fmt --check && cargo clippy --all-targets && cargo test`, and update README, `docs/CODEMAP.md` and `docs/FEATUREMAP.md` when files or behaviour changed.
