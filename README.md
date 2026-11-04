# Feature Gate Multisig Tool

CLI tool for creating and managing Solana feature gate multisigs using the Squads protocol. Enables collective governance over Solana feature activations and revocations.

## Installation

The tool is distributed as source: you build the exact code you reviewed, and
`--locked` builds use the committed lockfile, which pins every dependency by
version and checksum.

Requires a Rust toolchain ([rustup](https://rustup.rs)), and `libudev-dev` +
`pkg-config` on Linux (for hardware-wallet support).

To check hardware-wallet support in your build: any command against a
`usb://ledger` fee payer with no device plugged in must fail with "no device
found", not "hidapi crate compilation disabled" (Ledger signing cannot work in
that build).

Install a released version:

```bash
cargo install --locked --git https://github.com/nbelenkov/feature-gate-multisig --tag <version>
```

Or clone and build:

```bash
git clone https://github.com/nbelenkov/feature-gate-multisig.git
cd feature-gate-multisig
git checkout <version>   # pick a release tag; omit for the development branch
cargo build --release --locked
```

Binary: `./target/release/feature-gate-multisig-tool`

Releases are announced as git tags; see [CHANGELOG.md](CHANGELOG.md) for what
each version contains.

## Quick Start

```bash
# Interactive mode (recommended)
feature-gate-multisig-tool

# Direct commands
feature-gate-multisig-tool create --keypair ~/.config/solana/id.json
feature-gate-multisig-tool show <MULTISIG_ADDRESS>
feature-gate-multisig-tool config
```

## Commands

| Command | Description |
|---------|-------------|
| `create` | Create a new feature gate multisig with an activation proposal |
| `show <address>` | Display multisig details, members, and proposal status |
| `verify <address>` | Check program authenticity, feature state and owners on every configured network |
| `propose` / `approve` / `reject` / `execute` | Act on a proposal non-interactively |
| `check-signer` | Confirm a keypair (including `usb://ledger`) can act on a multisig; signs nothing |
| `config` | Show saved configuration |
| `interactive` | Launch interactive menu (default) |

### Before an activation: check every signer

```bash
feature-gate-multisig-tool check-signer --keypair usb://ledger --multisig "$MULTISIG"
```

Resolves the key (device present and unlocked; signs nothing) and reports
whether it is a voting member of the multisig. Non-zero exit means that signer
cannot act: wrong device, derivation path, or multisig, or a build without
hardware-wallet support. Run it days ahead, not at the first signature.

### Scripting

`verify` exits non-zero when a check fails **or** cannot be completed, so it can
gate a runbook:

```bash
feature-gate-multisig-tool verify "$MULTISIG" && \
  feature-gate-multisig-tool approve --multisig "$MULTISIG" --kind activate --index 1 --yes
```

It still reports every problem in one run rather than stopping at the first.
A non-zero exit means the multisig has not been shown to be correct - not
necessarily that it is malicious; an unreachable network fails the same way.

`verify` fails when the multisig is not autonomous, has been rekeyed
(permanently frozen), or its voting members differ from the expected set:
`KNOWN_SIGNERS` when vendored into the build, otherwise the `members` list in
your config. With neither it says so, and fails on mainnet. Keep config
`members` equal to the agreed signer set and `verify` catches a swapped, added,
or removed owner.

`propose`, `approve`, `reject`, and `execute` print the action, multisig,
feature gate, and network before signing; `--yes` does not suppress this. They
also refuse up front when the proposal's status or staleness means the action
cannot succeed.

`--yes` resolves each confirmation to its default answer. It does not force an
action through: a proposal this tool cannot classify, and any config change
(membership or threshold), abort under `--yes` and need an interactive decision.

## Interactive Mode

> **See [docs/WORKFLOWS.md](docs/WORKFLOWS.md) for detailed step-by-step examples.**

The interactive menu provides:
- **Create new feature gate multisig** - guided setup with member collection
- **Show / Verify feature gate multisig** - inspect any address
- **Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)** - act on proposals
- **Show configuration** - view saved settings

### Proposal Actions

Choosing **Create (Activate / Revoke / Rekey)** asks which transaction type:

| Type | Effect |
|---|---|
| Activate Feature Gate | queue a feature for activation at the next epoch boundary |
| Revoke Feature Gate | close a **pending** activation and burn its lamports to the incinerator |
| Rekey Multisig | **irreversible**: replaces every member with an unsignable dummy and sets threshold 1, so no proposal can ever pass again |

Approve, Reject and Execute act on proposals that already exist. The
interactive picker reads each proposal's kind from its on-chain transaction;
the CLI subcommands still require `--kind`, and refuse to act when it does not
match the on-chain transaction, so an existing proposal cannot be mislabelled
either way.

## Proposal Structure

When a multisig is created, one proposal is automatically generated:

| Index | Type | Purpose |
|-------|------|---------|
| 1 | Vault Transaction | Feature Activation |

**Note**: Activating or revoking a feature gate does not change the multisig threshold.

`create` also adds a throwaway contributor member with Initiate-only permission,
generated on the fly and never saved. Its key is discarded, so that member can
never act again and a "2 member" multisig reports 3 members.

Revocation only works while the feature is **Pending**. Once the runtime stamps
`activated_at` at an epoch boundary it is permanent, and the program rejects the
instruction with `FeatureGateError::FeatureAlreadyActivated`.

Revocation proposals are **not** pre-created. If you need to revoke a feature, create a new revocation proposal using "Proposal Actions" → "Revoke Feature Gate" → "Create". See [Emergency Revocation workflow](docs/WORKFLOWS.md#4-emergency-revocation) for details.

## Parent → Child Multisig Voting

For programmatic voting from a parent multisig:

> **Important**: Add the parent's **vault PDA** (not multisig address) as a member of the child multisig with Vote/Execute permissions.

The **fee payer keypair** must be a member of the parent multisig. Initiate is
enough to create the parent proposal, which is all the tool checks up front,
but approving needs Vote and executing needs Execute, so in practice give it
all three. Here `voting_key` and the fee payer are deliberately *different*:
pass the parent multisig as `--voting-key` and sign with your own key.

The parent multisig address cannot sign during CPI - only the vault PDA can be
signed for using PDA seeds. That PDA is off-curve, so no private key exists for
it; the Squads program signs as it once a parent proposal passes.

```
Parent vault PDA = get_vault_pda(parent_multisig, 0)
```

The tool detects the mode automatically: if `--voting-key` resolves to a Squads
multisig account, it takes the parent path.

**Each child action costs three parent transactions** - create the parent
proposal, approve it, execute it - and only the execute reaches the child. So one
activation is six, and a revoke drill is fifteen. The CLI prompts for all three
in sequence; interrupting between them leaves a half-finished parent proposal
and the child untouched.

The CLI will display the required PDA if misconfigured. See [Parent Multisig Voting workflow](docs/WORKFLOWS.md#3-activating-a-feature-parent-multisig-voting) for detailed steps.

## Configuration

Stored in your OS config directory (for example `~/.config/feature-gate-multisig-tool/config.json` on Linux, `~/Library/Application Support/feature-gate-multisig-tool/config.json` on macOS). Run `feature-gate-multisig-tool config` to print the exact path:

```json
{
  "threshold": 2,
  "members": ["<pubkey1>", "<pubkey2>"],
  "networks": ["https://api.devnet.solana.com"],
  "fee_payer_path": "usb://ledger",
  "voting_key": "<pubkey1>"
}
```

| Field | Description |
|-------|-------------|
| `threshold` | Required signatures |
| `members` | Saved member public keys |
| `networks` | RPC endpoints for deployment |
| `fee_payer_path` | Keypair path (file, `usb://ledger` or `usb://keystone`) |
| `voting_key` | Default voting identity: your own key, or a parent multisig |

**Voting as yourself: `voting_key` and `fee_payer_path` must be the same key.**
Only the fee-payer keypair is loaded, and the voting key has to sign, so a
mismatch fails fast rather than producing an unsignable transaction:

```
Error: In EOA mode, voting_key must match fee_payer.
```

That rule inverts when voting through a parent multisig; see below.

## Network Support

- Mainnet: `https://api.mainnet-beta.solana.com`
- Devnet: `https://api.devnet.solana.com`
- Testnet: `https://api.testnet.solana.com`
- Custom RPC endpoints supported

The cluster is identified by its **genesis hash**, and mainnet gets the strict
checks. A forked-mainnet staging cluster reports mainnet's genesis hash by
design, so neither this tool nor a hardware-wallet screen can tell the two
apart. When rehearsing against a fork, put **only** the staging RPC in
`networks`: a member with mainnet still in the list who picks the wrong entry
signs a real mainnet transaction with real keys.

## Testing

The e2e harness auto-answers prompts via `E2E_TEST_MODE`, which only exists
behind the `e2e-harness` cargo feature and is **compiled out of release
builds**. `make test-surfpool` enables it; such builds print a warning banner
on every run.

```bash
# Unit tests
cargo test

# E2E tests (requires surfpool)
make test-surfpool
```

### E2E Setup

```bash
# Install surfpool
curl -sL https://run.surfpool.run/ | bash
# Or: brew install txtx/taps/surfpool

# Run tests
make test-surfpool
```

## License

MIT - see [LICENSE](LICENSE)
