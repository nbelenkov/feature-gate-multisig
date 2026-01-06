# Feature Gate Multisig Tool

CLI tool for creating and managing Solana feature gate multisigs using the Squads protocol. Enables collective governance over Solana feature activations and revocations.

## Installation

```bash
git clone https://github.com/Squads-Protocol/feature-gate-multisig.git
cd feature-gate-multisig
cargo build --release
```

Binary: `./target/release/feature-gate-multisig-tool`

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
| `create` | Create a new feature gate multisig with paired proposals |
| `show <address>` | Display multisig details, members, and proposal status |
| `config` | Show saved configuration |
| `interactive` | Launch interactive menu (default) |

## Interactive Mode

> **See [docs/WORKFLOWS.md](docs/WORKFLOWS.md) for detailed step-by-step examples.**

The interactive menu provides:
- **Create new feature gate multisig** - Guided setup with member collection
- **Show multisig details** - Inspect any multisig address
- **Proposal Actions** - Create/Approve/Reject/Execute proposals
- **Show configuration** - View saved settings

### Proposal Actions

Supports three transaction types:
- **Activate Feature Gate** - Enable a Solana feature gate
- **Revoke Feature Gate** - Cancel a pending activation
- **Rekey Multisig** - Brick the multisig (rekey use only)

Each supports: Create, Approve, Reject, Execute

## Proposal Structure

When a multisig is created, two proposals are automatically generated:

| Index | Type | Purpose |
|-------|------|---------|
| 1 | Vault Transaction | Feature Activation |
| 2 | Config Transaction | Lower threshold to 1 |

**Note**: Interacting with feature gate activation will auto handle Vault + Config transaction.

Revocation proposals are **not** pre-created. If you need to revoke a feature, create a new revocation proposal using "Proposal Actions" → "Revoke Feature Gate" → "Create". See [Emergency Revocation workflow](docs/WORKFLOWS.md#4-emergency-revocation) for details.

## Parent → Child Multisig Voting

For programmatic voting from a parent multisig:

> **Important**: Add the parent's **vault PDA** (not multisig address) as a member of the child multisig with Vote/Execute permissions.

The **fee payer keypair** must be a member of the parent multisig with full permissions. The fee payer's signature is used to create/approve/execute proposals on the parent multisig.

The parent multisig address cannot sign during CPI - only the vault PDA can be signed for using PDA seeds.

```
Parent vault PDA = get_vault_pda(parent_multisig, 0)
```

The CLI will display the required PDA if misconfigured. See [Parent Multisig Voting workflow](docs/WORKFLOWS.md#3-activating-a-feature-parent-multisig-voting) for detailed steps.

## Configuration

Stored at `~/.feature-gate-multisig-tool/config.json`:

```json
{
  "threshold": 2,
  "members": ["<pubkey1>", "<pubkey2>"],
  "networks": ["https://api.devnet.solana.com"],
  "fee_payer_path": "usb://ledger"
}
```

| Field | Description |
|-------|-------------|
| `threshold` | Required signatures |
| `members` | Saved member public keys |
| `networks` | RPC endpoints for deployment |
| `fee_payer_path` | Keypair path (file or `usb://ledger`) |

## Network Support

- Mainnet: `https://api.mainnet-beta.solana.com`
- Devnet: `https://api.devnet.solana.com`
- Testnet: `https://api.testnet.solana.com`
- Custom RPC endpoints supported

## Testing

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
