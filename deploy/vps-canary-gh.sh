#!/bin/bash
# Canary VPS lot 3 github-gateway-rs : toolchain + build release + install + demarrage.
# Idempotent. Aucune modification du service prod github-mcp-gateway.service.
# Pre-requis crees par l'exploitant (sudo) : Bearer canary dedie
#   /opt/github-gateway-rs/.mcp_token (0600 github-app, >= 32 car., JAMAIS le
#   Bearer prod). Le PAT upstream partage /srv/github/secrets/github-pat est
#   relu en place (jamais copie ni journalise).
set -euo pipefail
export HOME=/home/juliann
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/juliann/build/mcp-rust-migration

if ! command -v cargo >/dev/null 2>&1; then
  echo "[canary] installation rustup (profil minimal)…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable
  rm -f /tmp/rustup-init.sh
fi
cargo --version
rustup component add rustfmt clippy
cd "$BUILD/github-gateway-rs"
echo "[canary] fmt/clippy/test…"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
echo "[canary] build release…"
cargo build --release
echo "[canary] installation /opt/github-gateway-rs…"
sudo install -d -o github-app -g github-app -m 0755 /opt/github-gateway-rs
sudo install -m 0755 target/release/github-gateway-rs /opt/github-gateway-rs/github-gateway-rs
sudo install -m 0644 deploy/github-gateway-rs.service /etc/systemd/system/github-gateway-rs.service
sudo systemctl daemon-reload
echo "[canary] demarrage github-gateway-rs.service (:18999)…"
sudo systemctl enable --now github-gateway-rs.service
sleep 3
sudo systemctl is-active github-gateway-rs.service
curl -s http://127.0.0.1:18999/health; echo
curl -s http://127.0.0.1:18999/ready; echo
echo "[canary] OK"
