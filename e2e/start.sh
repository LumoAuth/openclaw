#!/usr/bin/env bash
# End-to-end stage 1: a real OpenClaw in Docker, the packed plugin, a mock
# model, and `openclaw lumoauth setup` against a real LumoAuth.
#
#   CA_CERT=/path/to/root.crt e2e/start.sh
#
# Then approve the agent on the printed page. Setup keeps polling in the
# container (log: /root/e2e-setup.log) until it is approved or expires.
#
# Environment (all optional except CA_CERT when LumoAuth uses a private CA):
#   LUMOAUTH_URL      dashboard URL (default https://localhost:8000/orgs/northwind-labs/portal)
#   CA_CERT           CA certificate of LumoAuth's TLS certificate (NODE_EXTRA_CA_CERTS)
#   OPENCLAW_VERSION  default 2026.11.5
#   CONTAINER         default lumoauth-oc-e2e
#   MOCK_LLM_PORT     default 47321 (the container uses the host network)
#   AGENT_NAME        default "E2E OpenClaw"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/e2e/.work"
CONTAINER="${CONTAINER:-lumoauth-oc-e2e}"
OPENCLAW_VERSION="${OPENCLAW_VERSION:-2026.11.5}"
LUMOAUTH_URL="${LUMOAUTH_URL:-https://localhost:8000/orgs/northwind-labs/portal}"
MOCK_LLM_PORT="${MOCK_LLM_PORT:-47321}"
AGENT_NAME="${AGENT_NAME:-E2E OpenClaw}"
SETUP_LOG=/root/e2e-setup.log

mkdir -p "$WORK"
rm -f "${WORK:?}"/lumoauth-openclaw-*.tgz
echo "› Packing the plugin"
(cd "$ROOT" && npm pack --silent --pack-destination "$WORK" >/dev/null)
cp "$ROOT/e2e/mock-llm.mjs" "$WORK/mock-llm.mjs"
TGZ="$(cd "$WORK" && ls lumoauth-openclaw-*.tgz | head -1)"

CA_ENV=""
if [ -n "${CA_CERT:-}" ]; then
  cp "$CA_CERT" "$WORK/ca.crt"
  chmod 0644 "$WORK/ca.crt"
  CA_ENV="NODE_EXTRA_CA_CERTS=/e2e/ca.crt"
fi

echo "› Starting container $CONTAINER (node:24, host network)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --network host -v "$WORK:/e2e:ro" node:24 sleep infinity >/dev/null

echo "› Installing openclaw@$OPENCLAW_VERSION and the plugin"
docker exec "$CONTAINER" bash -c "npm i -g openclaw@$OPENCLAW_VERSION --no-audit --no-fund --loglevel=error >/dev/null && openclaw --version"
if ! docker exec "$CONTAINER" bash -c "cd /root && openclaw plugins install /e2e/$TGZ --force --accept-capabilities 2>&1 | tail -3" | tee /dev/stderr | grep -q 'Installed plugin'; then
  echo "✗ The plugin was not installed." >&2
  exit 1
fi

echo "› Configuring the mock model (http://127.0.0.1:$MOCK_LLM_PORT/v1)"
docker exec "$CONTAINER" node -e '
const fs = require("fs");
const p = "/root/.openclaw/openclaw.json";
const c = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : {};
c.models = { mode: "merge", providers: { mock: {
  baseUrl: "http://127.0.0.1:" + process.argv[1] + "/v1", apiKey: "mock-key", api: "openai-completions",
  models: [{ id: "mock-1", name: "Mock", api: "openai-completions", reasoning: false, input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 128000, maxTokens: 4096 }] } } };
c.agents = { ...(c.agents ?? {}), defaults: { ...(c.agents?.defaults ?? {}), model: { primary: "mock/mock-1" } } };
fs.writeFileSync(p, JSON.stringify(c, null, 2));
' "$MOCK_LLM_PORT"
docker exec -d "$CONTAINER" bash -c "PORT=$MOCK_LLM_PORT TOOL_CALL_FILE=/tmp/e2e-tool-call.json LOG=/tmp/e2e-mock-llm.log node /e2e/mock-llm.mjs > /tmp/e2e-mock-llm.out 2>&1"

echo "› Starting openclaw lumoauth setup (log: $CONTAINER:$SETUP_LOG)"
docker exec -d "$CONTAINER" bash -c "cd /root && $CA_ENV openclaw lumoauth setup --url '$LUMOAUTH_URL' --preset assistant --approvals auto --yes --name '$AGENT_NAME' > $SETUP_LOG 2>&1; echo \"exit=\$?\" >> $SETUP_LOG"

for _ in $(seq 1 120); do
  if docker exec "$CONTAINER" grep -qE 'Check that the page shows|✗|exit=' "$SETUP_LOG" 2>/dev/null; then
    break
  fi
  sleep 1
done
echo
docker exec "$CONTAINER" cat "$SETUP_LOG"
echo
echo "Approve the agent on the page above. Follow the log with:"
echo "  docker exec $CONTAINER tail -f $SETUP_LOG"
