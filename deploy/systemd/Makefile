# deposits-node systemd deployment.
#
# Wraps the multi-step install / upgrade / lifecycle dance with one
# entry point each. Run targets from this directory:
#
#   cd deploy/systemd
#   make install-all      # build + copy binaries + bootstrap
#   sudo editor /etc/deposits/deposits-node.env
#   make start            # systemctl enable --now
#
#   make logs             # journalctl -f
#   make upgrade          # git pull + rebuild + restart
#   make uninstall        # stop + remove binaries + unit files (preserves data)
#
# Most targets need sudo; the make recipe wraps that in. Plain `make`
# or `make help` lists every target.

SHELL    := /bin/bash
REPO_ROOT := $(shell git rev-parse --show-toplevel 2>/dev/null || (cd $(CURDIR)/../.. && pwd))
PREFIX   := /usr/local

.DEFAULT_GOAL := help

.PHONY: help build install bootstrap install-all check start stop restart status logs admin-token upgrade uninstall

help: ## Show this help
	@echo "deposits-node systemd deployment targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m  %s\n", $$1, $$2}'
	@echo
	@echo "REPO_ROOT = $(REPO_ROOT)"
	@echo "PREFIX    = $(PREFIX)"

build: ## Build deposits-node + deposits-signer (release)
	cd $(REPO_ROOT) && cargo build --release -p deposits-node -p deposits-signer

install: build ## build + copy binaries to $(PREFIX)/bin (requires sudo)
	sudo install -m 0755 $(REPO_ROOT)/target/release/deposits-node   $(PREFIX)/bin/deposits-node
	sudo install -m 0755 $(REPO_ROOT)/target/release/deposits-signer $(PREFIX)/bin/deposits-signer
	@echo "  → binaries installed at $(PREFIX)/bin/"

bootstrap: ## Run init.sh: users + dirs + seed + signer + unit files
	sudo $(CURDIR)/init.sh

install-all: install bootstrap ## install + bootstrap in one go
	@echo
	@echo "Next:"
	@echo "  sudo editor /etc/deposits/deposits-node.env   # network, relays, backend creds"
	@echo "  make start                                    # checks env, then systemctl enable --now"

check: ## Pre-flight sanity on /etc/deposits/deposits-node.env (auto-run by start)
	@$(CURDIR)/check-env.sh

start: check ## Enable + start both services (after env check)
	sudo systemctl enable --now deposits-signer deposits-node
	@$(MAKE) -s status

stop: ## Stop + disable both services
	sudo systemctl disable --now deposits-node deposits-signer

restart: check ## Restart both services after env check (signer first)
	sudo systemctl restart deposits-signer
	sudo systemctl restart deposits-node

status: ## systemctl status for both
	@systemctl --no-pager --lines=0 status deposits-signer deposits-node || true

logs: ## Tail journalctl for both (Ctrl+C to exit)
	@sudo journalctl -u deposits-node -u deposits-signer -f

admin-token: ## Print the admin-UI bearer token
	@sudo cat /var/lib/deposits/admin-token; echo

upgrade: ## git pull + rebuild + reinstall + restart
	cd $(REPO_ROOT) && git pull --ff-only
	$(MAKE) install
	$(MAKE) restart
	@echo "  → upgrade complete; logs: make logs"

uninstall: ## Stop services, remove binaries + unit files (data dirs preserved)
	@read -rp "Stop services + remove binaries + unit files? Data at /var/lib/{deposits,dsigner} is preserved. [y/N] " ok; \
	  [[ "$$ok" == "y" || "$$ok" == "Y" ]] || { echo "aborted"; exit 1; }
	sudo systemctl disable --now deposits-node deposits-signer 2>/dev/null || true
	sudo rm -f /etc/systemd/system/deposits-node.service /etc/systemd/system/deposits-signer.service
	sudo rm -f $(PREFIX)/bin/deposits-node $(PREFIX)/bin/deposits-signer $(PREFIX)/bin/deposits-node-wrapped
	sudo systemctl daemon-reload
	@echo
	@echo "  → binaries + unit files removed."
	@echo "  → preserved: /var/lib/deposits, /var/lib/dsigner, /etc/deposits/"
	@echo "  → to fully wipe (loses the seed!): sudo rm -rf /var/lib/deposits /var/lib/dsigner /etc/deposits"
