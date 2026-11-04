# Feature Gate Multisig Workflows

Step-by-step examples for common operations.

## Table of Contents
- [0. Configuration Setup](#0-configuration-setup)
- [1. Creating a Feature Gate Multisig](#1-creating-a-feature-gate-multisig)
- [2. Activating a Feature (Non multisig Voting)](#2-activating-a-feature-non-multisig-voting)
- [3. Activating a Feature (Parent Multisig Voting)](#3-activating-a-feature-parent-multisig-voting)
- [4. Emergency Revocation](#4-emergency-revocation)
- [5. Rejecting a Proposal](#5-rejecting-a-proposal)
- [6. Rekey (Bricking the Multisig)](#6-rekey-bricking-the-multisig)
- [CLI quick reference](#cli-quick-reference)

---

## CLI quick reference

Every workflow below has a non-interactive equivalent. Shared setup:

```bash
export TOOL=./target/release/feature-gate-multisig-tool
export RPC=https://api.devnet.solana.com
export MS=<FEATURE_GATE_MULTISIG>
export KP=~/.config/solana/id.json     # fee payer
export VK=<VOTING_KEY>                 # your pubkey, or a parent multisig address
```

`--voting-key` decides the mode. Your own pubkey uses the EOA path, where it
**must equal the fee payer**. A Squads multisig address uses the parent path,
where the fee payer must instead be a member of that parent.

### Create

```bash
$TOOL create --threshold 2 --keypair $KP
```
Reads members from config. Prints the multisig address and the feature gate id
(its vault-0 PDA), and pre-creates activation proposal **index 1**. This is the
same flow the interactive menu runs; interactive mode is the preferred way to
create (see [section 1](#1-creating-a-feature-gate-multisig)).

### Inspect

```bash
$TOOL show   $MS --network $RPC
$TOOL show   $MS --index 1 --network $RPC     # full proposal detail
$TOOL verify $MS                              # exits non-zero if anything fails
```

### Activate

```bash
$TOOL approve --multisig $MS --kind activate --index 1 --voting-key $VK --keypair $KP --network $RPC
$TOOL execute --multisig $MS --kind activate --index 1 --voting-key $VK --keypair $KP --network $RPC
```
Repeat `approve` with each member until the threshold is met, then `execute`
once. The feature is then **Pending** and activates at the next epoch boundary.

### Revoke

Only while **Pending**. Once activated it is permanent. Not pre-created, so
propose first:

```bash
$TOOL propose --multisig $MS --kind revoke --voting-key $VK --keypair $KP --network $RPC
$TOOL show    $MS --network $RPC                                   # note the new index
$TOOL approve --multisig $MS --kind revoke --index <N> --voting-key $VK --keypair $KP --network $RPC
$TOOL execute --multisig $MS --kind revoke --index <N> --voting-key $VK --keypair $KP --network $RPC
```
Closes the feature account and burns its lamports to the incinerator.

### Reject

```bash
$TOOL reject --multisig $MS --kind activate --index 1 --voting-key $VK --keypair $KP --network $RPC
```
A proposal dies at `members - threshold + 1` rejections.

### Rekey

**Irreversible.** Replaces every member with an unsignable dummy and sets the
threshold to 1, so no proposal can ever pass again. Do it only after the feature
has done what you need.

```bash
$TOOL propose --multisig $MS --kind rekey --voting-key $VK --keypair $KP --network $RPC
$TOOL show    $MS --network $RPC                                   # note the new index
$TOOL approve --multisig $MS --kind rekey --index <N> --voting-key $VK --keypair $KP --network $RPC
$TOOL execute --multisig $MS --kind rekey --index <N> --voting-key $VK --keypair $KP --network $RPC
```
`--yes` will not push a rekey through; config changes always need an interactive
decision.

---

## 0. Configuration Setup

The tool stores configuration in your OS config directory (shown below for Linux;
on macOS it is `~/Library/Application Support/feature-gate-multisig-tool/config.json`).
Run `feature-gate-multisig-tool config` to print the exact path.
```
~/.config/feature-gate-multisig-tool/config.json
```

### Create config manually (optional)

Pre-populate the config to skip interactive prompts:

```bash
mkdir -p ~/.config/feature-gate-multisig-tool
```

Create `~/.config/feature-gate-multisig-tool/config.json`:
```json
{
  "threshold": 3,
  "members": [
    "Pubkey1111111111111111111111111111111111111",
    "Pubkey2222222222222222222222222222222222222",
    "Pubkey3333333333333333333333333333333333333"
  ],
  "networks": [
    "https://api.mainnet-beta.solana.com",
    "https://api.devnet.solana.com"
  ],
  "fee_payer_path": "usb://ledger"
}
```

### Config fields

| Field | Type | Description |
|-------|------|-------------|
| `threshold` | number | Required approvals to execute proposals |
| `members` | string[] | Member public keys (get full permissions) |
| `networks` | string[] | RPC endpoints for deployment |
| `fee_payer_path` | string | Path to keypair file, `usb://ledger` or `usb://keystone` |

### View current config

```bash
feature-gate-multisig-tool config
```

---

## 1. Creating a Feature Gate Multisig

Use interactive mode (preferred):
```bash
feature-gate-multisig-tool
# Select: "Create new feature gate multisig"
```

The CLI `create` in the [quick reference](#cli-quick-reference) runs the same
flow non-interactively: members and networks come from the saved config,
`--threshold` overrides the saved value, and `--keypair` skips the fee payer
prompt.

### What happens:
1. Prompts for members (public keys with Vote/Execute permissions)
2. Prompts for threshold (required signatures)
3. Prompts for networks to deploy to
4. Creates the multisig with:
   - **Index 1**: Feature Activation proposal (Vault Transaction)

### Output:
```
Feature Gate Multisig: <MULTISIG_ADDRESS>
Feature Gate ID: <VAULT_PDA> (this is the feature ID)
```

---

## 2. Activating a Feature (Non multisig Voting)

For direct voting with an externally owned account (Non multisig).

### Step 1: Approve the activation proposal
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network (asked only when several are configured)
# Select: "Approve"
# Select: the activation proposal from the list (kind and index are read on-chain)
# Confirm: the action summary
# Enter: Voting key (your pubkey)
```

The fee payer resolves from the saved config; you are only prompted for a path
when none is saved.

Repeat for each member until threshold is met.

### Step 2: Execute the activation
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network
# Select: "Execute"
# Select: the approved activation proposal from the list
# Confirm: the action summary
# Enter: Voting key (your pubkey)
```

**Note**: Executing the activation does not change the multisig threshold.

---

## 3. Activating a Feature (Parent Multisig Voting)

For voting through a parent multisig (programmatic voting).

### Prerequisites:
1. The child multisig must have the **parent vault PDA** (not multisig address) as a member with Vote/Execute permissions.

```
Parent vault PDA = get_vault_pda(parent_multisig_address, 0)
```

2. The **fee payer keypair** must be a member of the parent multisig with full permissions. The fee payer's signature is used to create/approve/execute proposals on the parent multisig.

### Step 1: Create parent proposal to approve child
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Child feature gate multisig address
# Select: Network
# Select: "Approve"
# Select: the activation proposal from the list
# Confirm: the action summary
# Enter: Voting key (parent multisig address)
```

The fee payer resolves from the saved config and must be a parent multisig
member.

This creates a proposal on the parent multisig. When executed, it approves the child proposal.

### Step 2: Approve parent proposal 
Members of the parent multisig approve the parent proposal. 

### Step 3: Execute parent proposal if needed
Executes the parent proposal, which triggers the child approval. Some parent multisig configurations can auto-execute once enough approvals are present.

### Step 4: Repeat until child threshold is met

### Step 5: Execute child activation
```bash
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Child feature gate multisig address
# Select: Network
# Select: "Execute"
# Select: the approved activation proposal from the list
# Confirm: the action summary
# Enter: Voting key (parent multisig address)
```

**Note**: Executing the activation does not change the multisig threshold.

---

## 4. Emergency Revocation

To revoke a pending feature activation:

### Step 1: Create revocation proposal
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network
# Select: "Create (Activate / Revoke / Rekey)"
# Select: "Revoke Feature Gate"
# Enter: Voting key (your pubkey)
```

### Step 2: Approve the revocation proposal
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network
# Select: "Approve"
# Select: the revocation proposal from the list
# Confirm: the action summary
# Enter: Voting key (your pubkey)
```

### Step 3: Execute the revocation
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network
# Select: "Execute"
# Select: the approved revocation proposal from the list
# Confirm: the action summary
# Enter: Voting key (your pubkey)
```

Revocation uses the current multisig threshold. Activation does not downgrade the threshold.

---

## 5. Rejecting a Proposal

To reject a proposal (prevents execution):

```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Multisig address
# Select: Network
# Select: "Reject"
# Select: the proposal from the list (kind and index are read on-chain)
# Confirm: the action summary
# Enter: Voting key
```

A proposal is rejected when rejections >= (members - threshold + 1).

---

## 6. Rekey (Bricking the Multisig)

**Warning**: This permanently disables the multisig by removing all members and adding an unusable dummy member.

### When to use:
- After a feature is activated and no longer needs governance
- Emergency lockdown

### Steps:
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute/Rekey/Revoke)"
# Enter: Feature gate multisig address
# Select: Network
# Select: "Create (Activate / Revoke / Rekey)"
# Select: "Rekey Multisig (this will brick the multisig)"
# Enter: Voting key
```

Then approve and execute with required threshold.

### Result:
- All members removed
- Dummy member (Pubkey::default()) added
- Threshold set to 1
- Multisig is permanently unusable

---

## Flow Diagram

```
Create Multisig
      │
      └─► Index 1: Activation Proposal
                │
                ├─► Approve (threshold times)
                └─► Execute ─► Feature Activated
                              │
                              └─► Create Revoke Proposal
                                        │
                                        ├─► Approve (threshold times)
                                        └─► Execute ─► Feature Revoked
```
