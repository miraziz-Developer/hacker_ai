# Hacker AI

Private, scope-enforced assistant for **authorized bug bounty work only**. It validates every
target against an imported allowlist, performs a single low-impact HTTP probe, sanitizes evidence
before Azure inference, stores an audit trail, and renders reviewable Markdown finding drafts.

It deliberately does not implement phishing, malware, persistence, stealth/evasion, denial of
service, credential theft, destructive exploitation, or data exfiltration.

## Kali Linux installation

Developing on macOS is supported, but the approved external toolchain should be installed inside a
dedicated Kali Linux 2026/rolling VM. Both Apple Silicon (`arm64`) and Intel/AMD (`amd64`) guests are
supported by the reviewed Kali packages. Give the VM only the network access required by the
authorized program; use snapshots and encrypted storage, and do not use bridged networking unless
it is explicitly needed.

Copy or clone this private repository into the VM, then run the idempotent bootstrap as a regular
user (not root):

```bash
cd /path/to/hacker_ai
./scripts/bootstrap-kali.sh --dry-run  # review every command first
./scripts/bootstrap-kali.sh
source .venv/bin/activate
hacker-ai --help
```

The script installs only Python/venv support and the approved Kali packages `nmap`, `subfinder`,
`httpx-toolkit`, and `whatweb`; then it runs local identity diagnostics. It does not install the
large `kali-linux-everything` metapackage, enable network execution, scan a target, or run an
external security tool against the network. Re-run local checks without package changes using:

```bash
./scripts/bootstrap-kali.sh --verify-only
```

ProjectDiscovery HTTPX is deliberately packaged by Kali as `httpx-toolkit`. This avoids collision
with the unrelated `/usr/bin/httpx` and `.venv/bin/httpx` Python client commands; Hacker AI verifies
the ProjectDiscovery identity before accepting the Kali alias. The bootstrap prefers `uv sync
--locked --extra dev` when `uv` is available and otherwise creates `.venv` with standard Python.

## Azure configuration

Do **not** paste a key into source code, Git, reports, or chat. If a key is ever pasted into a
message, rotate it immediately. Azure uses the deployment name in the `model` field.

Recommended Entra ID configuration for the Azure endpoint and `gpt-5.4` deployment:

```bash
az login
export AZURE_OPENAI_BASE_URL='https://YOUR-RESOURCE.services.ai.azure.com/openai/v1'
export AZURE_OPENAI_DEPLOYMENT='gpt-5.4'
export AZURE_OPENAI_AUTH='entra'
hacker-ai doctor
hacker-ai ai test
```

`DefaultAzureCredential` uses the Azure CLI identity during local development and Managed Identity
when deployed to Azure. Assign that identity permission to invoke the model deployment.

API-key fallback is available when Entra ID cannot be used. Retrieve the key from Key Vault rather
than storing it in a file:

```bash
export AZURE_OPENAI_AUTH='api_key'
export AZURE_OPENAI_API_KEY="$(az keyvault secret show \
  --vault-name YOUR-VAULT --name azure-openai-key --query value -o tsv)"
```

The provider uses the OpenAI-compatible Responses API, structured JSON output and `store=False`.
The Azure project endpoint ending in `/api/projects/...` is not the model inference base URL.

## Workflow

Create a workspace and import the program's exact scope. The included scope is only a format
example and does not grant authorization. It demonstrates explicit domain/CIDR allowlisting, an
empty exclusion list, and the highest supported bounded automation setting (`allowed`); there is no
`any`/internet-wide scope or `unlimited` mode:

```bash
hacker-ai init
cp examples/scope.yaml my-program.yaml
# Edit my-program.yaml to exactly match the published program rules.
hacker-ai program import my-program.yaml
hacker-ai scope check https://api.example.com/v1/users
```

## Approved external tools

The application does not clone or execute arbitrary GitHub repositories. Its allowlisted toolchain
uses upstream projects with explicit identity checks, bounded version probes, and no shell
execution. Inspect the local environment with:

```bash
hacker-ai tools doctor
hacker-ai tools install-plan
```

The approved package-managed tools are Nmap (network/service inventory), Subfinder (passive
subdomain discovery), ProjectDiscovery HTTPX, and WhatWeb. No tool is automatically built from a
Git repository. A Python executable named `httpx` is **not** the ProjectDiscovery scanner;
`tools doctor` rejects that name collision and uses Kali's `httpx-toolkit` binary only after its
identity check passes. Installing a tool does not grant
permission to scan: every future invocation must still pass imported scope, program rules, rate
limits, timeout, private-address, and audit controls.

Recon defaults to a dry run. `--execute` performs DNS resolution and exactly one HTTP GET, uses a
rate limit, verifies TLS, does not follow redirects, and blocks unexpected private destinations:

```bash
hacker-ai recon run https://api.example.com/v1/ --execute
```

The scope-enforced external adapters also default to dry-run. Subfinder is passive and accepts only
an explicitly included root domain; every emitted hostname is checked against exclusions before it
is returned or audited. Nmap accepts only explicit domain, IP, or CIDR assets and uses a fixed TCP
connect profile with bounded ports, rate, concurrency, retries, output, and runtime. CIDRs are
limited to 256 addresses and denied when exclusions exist.

```bash
hacker-ai recon subdomains example.com
hacker-ai recon subdomains example.com --execute
hacker-ai recon ports 192.0.2.10 --ports 80,443
hacker-ai recon ports 192.0.2.10 --ports 80,443 --execute
```

No adapter accepts arbitrary tool arguments. `--execute` is an acknowledgement, not authorization:
imported scope and program policy remain authoritative, and denied attempts are audited.

Real network and approved-tool execution also requires an explicit environment opt-in. It is
disabled by default and accepts only the literal values `true` or `false`:

```bash
export HACKER_AI_ALLOW_NETWORK_EXECUTION=true   # permit authorized --execute operations
export HACKER_AI_ALLOW_NETWORK_EXECUTION=false  # block all real network/tool execution
```

This switch is an additional kill switch, not a scope bypass. Setting it to `true` does not disable
the imported allowlist, exclusions, program policy, private-address checks, rate limits, timeouts,
auditing, dry-run default, or the separate `--execute` acknowledgement. Invalid values fail closed.

Analyze a saved HTTP response or other textual evidence. Authorization headers, cookies and
common token forms are redacted before inference:

```bash
hacker-ai analyze file https://api.example.com/v1/ evidence.txt
hacker-ai report render 1 --output finding-1.md
hacker-ai audit show
```

AI output is always stored as `needs-review`; it is not proof of a vulnerability. Manually verify
all claims and follow the platform's disclosure and safe-harbor rules.

## Telegram agent interface

Users do not need to type Hacker AI subcommands for routine scope, recon, and web assessment
operations. A private Telegram bot can accept natural-language requests, ask Azure AI to select one
constrained action, and return the result. Create a bot with BotFather, obtain your numeric Telegram
user ID, and load both secrets into the environment (prefer a secret manager rather than a checked-in
`.env`):

```bash
export TELEGRAM_BOT_TOKEN='retrieve-from-a-secret-store'
export TELEGRAM_ALLOWED_USER_IDS='123456789'  # comma-separated IDs are supported
# Enable only the capabilities required for this authorized engagement:
export HACKER_AI_TELEGRAM_ALLOW_HTTP_RECON=true
export HACKER_AI_TELEGRAM_ALLOW_SUBDOMAIN_RECON=false
export HACKER_AI_TELEGRAM_ALLOW_PORT_RECON=false
hacker-ai telegram run
```

Example requests include “example.com scope ichidami?”, “example.com zaif tomonlarini topib himoya
tavsiyalarini ber”, and “192.0.2.10 da 80,443 portlarni tekshir”. A web assessment performs bounded
HTTP recon, analyzes only the resulting evidence, saves a needs-review finding, and returns severity,
evidence, impact, and remediation directly in Telegram. Status and scope checks are immediate. Every
network action is staged and requires a separate `/confirm` from the same Telegram user and chat;
`/cancel` discards it. Confirmation is only an execution acknowledgement: imported allowlists,
exclusions, program rules, bounded adapters, timeouts, rates, audit logging, and
`HACKER_AI_ALLOW_NETWORK_EXECUTION=true` remain mandatory.

All three Telegram recon capabilities default to `false` and accept only literal `true` or `false`.
They can independently disable HTTP, subdomain, or port recon without stopping status and scope
checks. To execute enabled recon, the global network switch must also be `true`. These switches do
not and cannot disable scope, exclusions, program policy, confirmation, auditing, rate limits,
timeouts, or the approved adapter restrictions.

Routine operation, including assessment results, is available in Telegram without evidence-file
uploads. The imported server-side scope remains mandatory and a chat message cannot authorize a new
target. The bot ignores all users not listed in `TELEGRAM_ALLOWED_USER_IDS`, does not expose a shell,
and does not accept arbitrary tool arguments. Telegram transport necessarily sends the user's
message to Telegram; do not paste credentials, private evidence, or secrets into chat. Evidence-file
analysis remains local through `hacker-ai analyze file` so that sanitization occurs before Azure
inference. Run the bot in the initialized workspace containing the imported scope.

## Fine-tuning dataset safety

Audit large JSONL files in streaming mode; raw examples are never printed:

```bash
hacker-ai dataset audit '/path/to/archive/all.jsonl'
```

Prepare a deterministic, deduplicated ChatML train/validation set:

```bash
hacker-ai dataset prepare '/path/to/archive/all.jsonl' training-output
```

Preparation accepts only rows with complete provenance metadata, the `redistributable_text`
release mode, and the built-in advisory/bug-bounty/fix/vulnerability allowlist. Exploit archives,
exploit Q&A, hacker-community, malware, phishing, illicit-marketplace, initial-access,
script-kiddie, restricted-license, secret-bearing, malformed, and unknown rows are excluded and
counted in `manifest.json`. The original system persona is replaced with the project's
authorized-use policy. These safety filters cannot be disabled by a CLI flag. Review both the
generated files and source licenses before uploading them to any model provider. Dataset
preparation does not create or submit an Azure fine-tuning job.

## Universal scope schema

Supported asset types are `domain`, `wildcard_domain`, `url`, `ip`, and `cidr`. Exclusions always
override inclusions. Unknown YAML fields are rejected to catch policy typos. Active recon requires:

```yaml
rules:
  active_scanning: true
  automated_scanning: limited # or allowed
```

Dangerous capabilities cannot be enabled through configuration.

## Development checks

```bash
uv run pytest
uv run ruff check .
uv run mypy
```

The `.hacker-ai/` workspace and `.env` are Git-ignored. Keep the entire repository private and
encrypt backups containing program data.