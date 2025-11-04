# Feature Gate Multisig Tool

This CLI tool enables the creation of feature gate multisigs across all Solana networks (mainnet, devnet, testnet) leveraging the Squads multisig program. It enables the distribution of keys required to activate or revoke pending feature activations through governance.

## How It Works

The configuration file dictates the members and parent multisigs for the feature gate multisig to be created. The fee payer keypair is used to pay transaction fees and sets up the multisig configurations and proposals for a given feature gate.

**Proposals are always created in the following order:**
1. **Feature Activation Proposal** (Index 0)
2. **Feature Activation Revocation Proposal** (Index 1)

Once a feature gate multisig has been created, the CLI exposes transaction generation functionality to enable voting on either proposal and executing them when the threshold is met.

## Key Features

- **Multi-Network Deployment**: Deploy identical multisigs across mainnet, devnet, and testnet
- **Persistent Configuration**: Saved member lists and network settings for reuse
- **Transaction Generation**: Create voting transactions for feature activation/revocation
- **Interactive Mode**: Guided setup with prompts and validation

## Installation

```bash
# Clone the repository
git clone https://github.com/Squads-Protocol/feature-gate-multisig.git
cd feature-gate-multisig

# Build the project
cargo build --release

# The binary will be available at ./target/release/feature-gate-multisig-tool
```

## Usage

### Commands

```bash
# Create a new feature gate multisig
feature-gate-multisig-tool create --keypair ~/.config/solana/id.json

# Show existing multisig details
feature-gate-multisig-tool show <MULTISIG_ADDRESS>

# Interactive mode (default)
feature-gate-multisig-tool

# Show configuration
feature-gate-multisig-tool config
```

## Configuration

The tool saves configuration to `~/.feature-gate-multisig-tool/config.json`:

```json
{
  "threshold": 2,
  "members": [
    "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
  ],
  "networks": [
    "https://api.devnet.solana.com",
    "https://api.testnet.solana.com",
    "https://api.mainnet-beta.solana.com"
  ],
  "fee_payer_path": "~/.config/solana/id.json"
}
```

## Transaction Generation

Once a multisig is created, use the transaction generation commands to:
- Vote on Feature Activation Proposal (Index 1)
- Vote on Feature Activation Revocation Proposal (Index 2)
- Execute proposals when threshold is met

### Parent → Child multisig voting

If a parent multisig is configured to vote on a proposal in a child multisig, the child multisig must include the parent vault PDA as a member with Vote permission (not the parent multisig address itself).

Why: During execution, the parent program can sign for its vault PDA using PDA seeds, but it cannot sign as the parent multisig address in CPI. Listing the parent multisig address as the voter will lead to missing/invalid signer errors. Listing the parent vault PDA avoids this and enables programmatic approval.

What to add to the child multisig:
- Member: Parent vault PDA (usually index 0)
- Permissions: Vote (and optionally Execute if the parent should execute child proposals)

The CLI will print a clear error and the exact PDA to add if the child multisig isn’t configured correctly.

## Network Support

Supports deployment to any Solana network:
- **Mainnet Beta**: `https://api.mainnet-beta.solana.com`
- **Devnet**: `https://api.devnet.solana.com`
- **Testnet**: `https://api.testnet.solana.com`
- **Custom RPC**: Any valid Solana RPC endpoint

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture
```

## Testing setup

To test multisigs use `squads-multisig-cli` to spin up a multisig and add the PDA Vault as a member of the feature gate multisig.

```bash
multisig-create --rpc-url <RPC_URL> --program-id <PROGRAM_ID> --keypair <KEYPAIR_PATH> --config-authority <CONFIG_AUTHORITY> --members <MEMBER_1> <MEMBER_2> ... --threshold <THRESHOLD>

```

see more info here https://docs.squads.so/main/development/cli/commands#multisig-create

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.