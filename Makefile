SHELL := /bin/bash

# --- Surfpool-backed E2E using real BPF ---
.PHONY: surfpool-start
surfpool-start:
	@echo "Starting surfpool with Squads program cloned from mainnet..."
	@echo "Ensure surfpool is installed: curl -sL https://run.surfpool.run/ | bash"
	surfpool start --no-tui

.PHONY: test-surfpool
test-surfpool:
	@echo "Starting surfpool in background..."
	@(surfpool start --no-tui > artifacts/surfpool.log 2>&1 &)
	@sleep 5
	@echo "Running RPC E2E tests..."
	@RPC_URL=http://127.0.0.1:8899 cargo test rpc_e2e_ -- --test-threads=1 --nocapture || true
	@echo "Stopping surfpool..."
	@pkill -f surfpool || true
