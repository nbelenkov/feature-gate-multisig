# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-09-23

### Security

- `E2E_TEST_MODE`, which auto-confirms every prompt including irreversible
  config changes, is now behind the `e2e-harness` cargo feature and compiled
  out of release builds. Builds that carry it warn on every run, whether or not
  the variable is set.
- Environment flags are enabled by value rather than by presence, so
  `FEATURE_GATE_MULTISIG_ASSUME_YES=false` no longer enables `--yes` behaviour.
- RPC endpoints are checked on the parsed host instead of a substring of the
  whole URL. A typo like `https://ssolana.com/mainnet` used to pass silently
  because the string contained "solana.com".
- Plain `http://` is refused unless the host is the loopback interface. A
  governance action should not be sent, nor its reply trusted, over a
  connection anything on the path can rewrite. Both the CLI and the interactive
  prompt apply the same rule.
- The member-set check is no longer inert: when no `KNOWN_SIGNERS` set is
  vendored into the build, the configured `members` list is used instead, and
  `verify` names which expectation it checked. With no expectation at all it
  refuses on mainnet.
- `rustls` 0.23.45 for RUSTSEC-2026-0285.

### Added

- `check-signer`: resolve a keypair path (including `usb://ledger`) to its
  public key and report whether it can act on a given multisig, and what it may
  do. Signs nothing, so signers can confirm their setup before an activation
  depends on it. Takes `--network` for scripted runs.
- Revoke and Rekey appear in the interactive menus, rather than being reachable
  only from the CLI.
- `propose`, `approve`, `reject`, and `execute` print the on-chain action,
  multisig, feature gate, and network before signing; `--yes` does not
  suppress it.
- `show`: the proposal table shows vote progress against cutoffs and how long
  ago each proposal changed state; the member count breaks out voting vs
  non-voting; time locks render with units.

### Changed

- Addresses and `--network` values are parsed when the command starts, so a
  malformed one is reported before any prompt or network call rather than by
  whichever call site happened to check it.
- `verify` exits non-zero for a rekeyed multisig or an unexpected member set,
  so `verify && approve` cannot proceed past either. Both previously only
  warned.
- A multisig rekeyed on every configured network is reported as DECOMMISSIONED
  rather than as a failed correctness check. It is a deliberate end state, and
  the exit code stays non-zero.
- A rekeyed multisig's feature gate is marked permanent, since no proposal can
  activate or revoke it again.
- The owner check is skipped on a rekeyed multisig instead of restating the
  rekey once per removed signer. `check-signer` warns on one too.
- `create` refuses a duplicate member before anything is signed.
- `show` checks owners against the configured set the same way `verify` does,
  and gives the same hint on how to populate it.
- A failed action in interactive mode is reported and returns to the menu. An
  unreachable endpoint or a rejected input is a reason to retry, not to end the
  session.

### Fixed

- Hardware wallets work at all: `solana-remote-wallet` is now a direct
  dependency with `hidapi` compiled in. Previously every `usb://ledger` use
  failed with "hidapi crate compilation disabled in solana-remote-wallet".
- The non-interactive subcommands refuse an action the proposal's status or
  staleness cannot accept (matching the interactive picker), instead of sending
  a transaction the Squads program rejects with a raw `InvalidProposalStatus`.
- The interactive picker stops when it cannot list proposals, instead of
  offering an index derived from a failed read.
- A malformed entry in the configured `members` list can no longer match the
  rekeyed member key.
- DECOMMISSIONED is claimed only when every configured network was read. A
  network that did not answer holds a copy the run never saw.
- The deployment summary reported `Requires: <threshold>/<threshold> approvals`;
  the denominator is now the number of voting members.
- README and `docs/WORKFLOWS.md` accuracy: the revoke error name, `--kind`
  usage, the interactive step order, and which parent-member permissions each
  action needs.

## [0.4.0] - 2026-08-12

### Changed

- Cluster identity is established in a way the endpoint cannot relax. Answering
  "not mainnet" previously skipped the immutability and bytecode-hash
  assertions, letting the party being checked choose how strictly it was
  checked. A mainnet fork on a custom URL stays strict; a URL naming mainnet
  whose chain disagrees is refused. Governance actions establish the cluster
  before signing, since a signature is bound to a cluster only by the blockhash
  the endpoint supplies.
- `verify` fails when a check runs and reports a problem, not only when a check
  cannot run: a failed bytecode hash, a mutable program on mainnet, a
  non-autonomous multisig, or cross-network drift. A time lock and a completed
  rekey remain warnings, being intended states.
- A config transaction is labelled as one everywhere. It previously shared the
  "Vault transaction" label, which implies it cannot alter governance, and the
  action-list disclosure was selected by the caller's `--kind` rather than by
  the on-chain account type - so naming it `--kind activate` skipped it.
- `show` lists a bounded window of the newest proposals and says how many older
  ones it omitted, rather than sizing its work from an unbounded on-chain
  counter.
- The config file is written readable only by its owner.

### Fixed

- Every Squads account read behind a decision or a signer-facing disclosure is
  authenticated: the config-change disclosure, both execute paths, and the
  proposal listings in `show` and the interactive picker.
- Text originating outside the trust boundary has its control characters
  neutralised, so a remote error string cannot reposition the cursor and repaint
  locally derived output before a signing decision.
- A rekey proposal is refused when the endpoint's member set is missing a member
  saved locally, which would otherwise produce a "brick" leaving that member in
  sole control. The disclosure also warns when a config change leaves exactly
  one member able to sign.
- The rent-exemption amount funded from the fee payer is bounded by a locally
  computed ceiling instead of taken from the endpoint.
- `show` reports the feature account's state in both report layouts. One
  unapproved proposal referencing the Squads program used to switch layouts and
  suppress it entirely.
- `show` names networks it could not read and scopes its consistency and
  freeze verdicts to what was actually compared.
- "Permanently frozen" additionally requires the multisig to be autonomous; a
  config authority can restore quorum at any time.
- Account roles in the transaction drill-down are computed at a width that
  cannot wrap, so writable accounts are never displayed as read-only.
- CI verifies the surfpool download against a pinned digest.

## [0.3.1] - 2026-08-10

Hardens the path that decides what a proposal is and what a signer is told it
does. Supersedes 0.3.0, whose transaction classifier labels any decodable config
transaction a rekey and any all-System vault message an activation.

### Changed

- `--yes` no longer authorizes an action the tool cannot vouch for. It aborts on
  an unrecognized proposal, and refuses a config change outright rather than
  resolving the confirmation on the operator's behalf. Recognized activate,
  revoke, and rekey proposals are unaffected.
- `verify` exits non-zero when a check could not be completed. It still reports
  every problem in one run; only the exit code changed.
- An ambiguous `--network` name is an error naming the candidates, instead of
  resolving to whichever endpoint was configured first.
- `--threshold` parses at the on-chain width, so out-of-range values are
  rejected rather than truncated (65537 previously became 1, 65536 became 0).
- An explicit `--threshold` is honoured when the saved configuration is reused,
  instead of being silently discarded.
- Canonical rekeys are labelled as permanently disabling voting, and approving
  or executing one prints the resulting threshold and the number of members able
  to vote afterwards before asking.

### Fixed

- Squads accounts are authenticated, not just decoded: proposal classification,
  the approval-quorum read, the `show --index` detail views, and multisig reads
  require Squads ownership and a record naming the multisig and index being
  read. A multisig is bound to its address through the `create_key` PDA
  derivation, which proves the body was not lifted from a different multisig
  (it does not constrain the member set, threshold, or transaction index). Reads
  behind the config-change disclosure, the execute paths, and the proposal
  listings were not covered; see the next release.
- A failed multisig read no longer defaults the member list to empty. That
  baseline made a config change which only weakens the threshold identical to a
  canonical rekey, so it was certified as one.
- Proposal classification fails closed. A transaction that cannot be read or
  authenticated is refused rather than warned about.
- The parent multisig flow describes a child by what it is on-chain, rather than
  by the kind the caller passed.
- `show` sweeps the endpoint being inspected, so feature state and the rekey
  warning describe the cluster on screen rather than the saved network list.
- `show --index` prints instruction data in full. Truncation cut the owner
  pubkey out of a System `assign`, which is the field distinguishing an
  activation from a hijack.
- Proposal creation asks before sending, matching every other send path.
- Partial multi-network deployments name the networks that succeeded and warn
  about the ones that did not, instead of reporting completion without naming a
  cluster.
- Executing a proposal that loads accounts from address lookup tables reports
  why this tool cannot, instead of failing on-chain.
- Malformed ProgramData is rejected rather than read as an immutable program.
- A confirmation timeout says the transaction may still have landed, and
  creating a proposal warns when the newest one already matches it.
- Saving a voting key no longer drops the other configured networks when
  `--network` was passed.

## [0.3.0] - 2026-07-13

### Added

- `verify` command: checks, across every configured network, that the Squads
  program is the authentic immutable v4 (verified bytecode hash), reports the
  feature gate account state (fresh/pending/activated) and rent exemption,
  lists the multisig owners, threshold, autonomy, and time lock, and flags
  cross-network config drift. Cluster identity is detected from the genesis
  hash rather than the RPC URL.
- Pre-flight checks before feature gate actions: warn and confirm when the
  action does not match the on-chain feature state.
- Non-interactive proposal subcommands: `propose`, `approve`, `reject`,
  `execute`, with `--multisig`, `--kind`, `--index`, `--voting-key`,
  `--keypair`, `--network`, and `--yes` flags.
- Interactive proposal picker: live proposals are listed with what each one
  does (classified from the on-chain transaction shape), status, and vote
  counts; proposals the chosen action can no longer apply to are filtered out.
- Saved voting-key default; session memory for the multisig address; Esc
  returns to the menu instead of exiting.
- Wrong-address errors explain themselves, and pasting a feature gate account
  looks up and names its multisig from transaction history.
- Source-based release process: versions are git tags, installed via
  `cargo install --locked --git ... --tag <version>` or clone-and-build.

### Changed

- Config moved from the current working directory to the per-user OS config
  directory (`~/.config/feature-gate-multisig-tool/config.json` on Linux).
- Solana dependency stack migrated to the Agave 3.x line; the dependency tree
  shrank from 753 to 463 packages. Direct dependencies are pinned exactly.
- `show` validates account ownership before rendering, EOA voting paths
  enforce membership and permissions up front, and `voting_key` must match
  the fee payer in EOA mode.

## [0.2.0]

Initial public iteration: multisig provisioning across networks, interactive
proposal flows (activate/revoke/rekey), parent-multisig voting, and the
surfpool-backed E2E suite.
