# Feature Gate Multisig Workflows

Step-by-step examples for common operations.

## Table of Contents
- [0. Configuration Setup](#0-configuration-setup)
- [1. Creating a Feature Gate Multisig](#1-creating-a-feature-gate-multisig)
- [2. Activating a Feature (EOA Voting)](#2-activating-a-feature-eoa-voting)
- [3. Activating a Feature (Parent Multisig Voting)](#3-activating-a-feature-parent-multisig-voting)
- [4. Emergency Revocation](#4-emergency-revocation)
- [5. Rejecting a Proposal](#5-rejecting-a-proposal)
- [6. Rekey (Bricking the Multisig)](#6-rekey-bricking-the-multisig)

---

## 0. Configuration Setup

The tool stores configuration at:
```
~/.feature-gate-multisig-tool/config.json
```

### Create config manually (optional)

Pre-populate the config to skip interactive prompts:

```bash
mkdir -p ~/.feature-gate-multisig-tool
```

Create `~/.feature-gate-multisig-tool/config.json`:
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
| `fee_payer_path` | string | Path to keypair file or `usb://ledger` |

### View current config

```bash
feature-gate-multisig-tool config
```

---

## 1. Creating a Feature Gate Multisig

Use interactive mode:
```bash
feature-gate-multisig-tool
# Select: "Create new feature gate multisig"
```

### What happens:
1. Prompts for members (public keys with Vote/Execute permissions)
2. Prompts for threshold (required signatures)
3. Prompts for networks to deploy to
4. Creates the multisig with:
   - **Index 1**: Feature Activation proposal (Vault Transaction)
   - **Index 2**: Lower Threshold to 1 proposal (Config Transaction)

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
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Feature gate multisig address
# Enter: Fee payer keypair path
# Enter: Voting key (your pubkey)
# Select: "Activate Feature Gate"
# Select: "Approve"
# Enter: Proposal index (1)
```

Repeat for each member until threshold is met.

### Step 2: Execute the activation
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Feature gate multisig address
# Enter: Fee payer keypair path
# Enter: Voting key (your pubkey)
# Select: "Activate Feature Gate"
# Select: "Execute"
# Enter: Proposal index (1)
```

**Note**: Executing the activation also automatically executes Index 2 (threshold change to 1), making future revocations easier with single-approval.

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
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Child feature gate multisig address
# Enter: Fee payer keypair path (must be parent multisig member)
# Enter: Voting key (parent multisig address)
# Select: "Activate Feature Gate"
# Select: "Approve"
# Enter: Proposal index (1)
```

This creates a proposal on the parent multisig. When executed, it approves the child proposal.

### Step 2: Approve parent proposal 
Members of the parent multisig approve the parent proposal. 

### Step 3: Execute parent proposal (if not 1/n)
Executes the parent proposal, which triggers the child approval. If its 1/n parent multisig, the approval is auto executed.

### Step 4: Repeat until child threshold is met

### Step 5: Execute child activation
```bash
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Child feature gate multisig address
# Enter: Fee payer keypair path (must be parent multisig member)
# Enter: Voting key (parent multisig address)
# Select: "Activate Feature Gate"
# Select: "Execute"
# Enter: Proposal index (1)
```

**Note**: Executing the activation also automatically executes Index 2 (threshold change to 1), making future revocations easier with single-approval.

---

## 4. Emergency Revocation

To revoke a pending feature activation (threshold is already 1 after activation):

### Step 1: Create revocation proposal
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Feature gate multisig address
# Enter: Fee payer keypair path
# Enter: Voting key (your pubkey)
# Select: "Revoke Feature Gate"
# Select: "Create"
```

### Step 2: Approve the revocation proposal
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Feature gate multisig address
# Enter: Fee payer keypair path
# Enter: Voting key (your pubkey)
# Select: "Revoke Feature Gate"
# Select: "Approve"
# Enter: Proposal index
```

### Step 3: Execute the revocation
```bash
feature-gate-multisig-tool
# Select: "Proposal Actions (Approve/Reject/Execute)"
# Enter: Feature gate multisig address
# Enter: Fee payer keypair path
# Enter: Voting key (your pubkey)
# Select: "Revoke Feature Gate"
# Select: "Execute"
# Enter: Proposal index
```

With threshold at 1, only a single member needs to approve before execution.

**Note**: Once the revocation is executed, the threshold is restored to its original value.

---

## 5. Rejecting a Proposal

To reject a proposal (prevents execution):

```bash
feature-gate-multisig-tool
# Select: "Proposal Actions"
# Enter: Multisig address
# Select: Transaction type (Activate/Revoke/Rekey)
# Select: "Reject"
# Enter: Proposal index
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
# Select: "Proposal Actions"
# Select: "Rekey Multisig (this will brick the multisig)"
# Select: "Create"
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
      ├─► Index 1: Activation Proposal
      │         │
      │         ├─► Approve (threshold times)
      │         └─► Execute ─► Feature Activated
      │
      └─► Index 2: Lower Threshold Proposal
                │
                ├─► Approve (threshold times)
                └─► Execute ─► Threshold = 1
                              │
                              └─► Create Revoke Proposal
                                        │
                                        ├─► Approve (1 time)
                                        └─► Execute ─► Feature Revoked
```
