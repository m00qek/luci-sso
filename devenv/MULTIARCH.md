# Project Plan: Multi-Architecture Hybrid Workflow for Luci-SSO

This document outlines the roadmap to transition from a single-architecture local workflow to a high-performance, multi-architecture hybrid system.

---

## Milestone 1: Local Multi-Arch Capability

**Objective:** Enable the local development environment (Host) to build and test packages for any target architecture (Target) without file conflicts or manual variable configuration.

INITIALLY SUPPORTED ARCHS: host arch and aarch64_cortex-a53

### 1.1 Segregate Artifacts (The "Filesystem" Step)

**Goal:** Prevent binaries from different architectures (e.g., `mips` vs `arm64`) from overwriting each other on the host disk.

* **Target File:** `devenv/services/sdk/build.sh`
* **Action:** Modify the output logic.
  * **Current:** Outputs to `bin/lib/${CRYPTO_LIB}/...`
  * **New:** Output to `bin/lib/${SDK_ARCH}/${CRYPTO_LIB}/...`
* **Outcome:** Multiple architectures can coexist in the `bin/lib` folder (e.g., `bin/lib/x86-64/` and `bin/lib/mips_24kc/`).

### 1.2 Dynamic Volume Mounting (The "Compose" Step)

**Goal:** Ensure the Docker containers mount only the binaries that match their simulated CPU architecture.

* **Target File:** `devenv/docker-compose.yaml`
* **Action:** Update volume mounts for the `luci` service.
* **Logic:**
  * Change: `- ../bin/lib/${CRYPTO_LIB}/...`
  * To: `- ../bin/lib/${SDK_ARCH}/${CRYPTO_LIB}/...`
* **Outcome:** The runtime container receives the correct `.so` files for its architecture (preventing Exec format errors).

### 1.3 Intelligent Auto-Detection (The "Brain" Step)

**Goal:** Make `make test` work out-of-the-box on any hardware (Intel or Apple Silicon) without manual configuration.

* **Target File:** `devenv/Makefile`
* **Action:** Add an auto-detection block at the top of the file.
* **Logic:** Run `uname -m`.
  * If `arm64` (Apple Silicon) $\rightarrow$ Set `SDK_ARCH=aarch64_cortex-a53`.
  * If `x86_64` (Intel/AMD) $\rightarrow$ Set `SDK_ARCH=x86-64`.
* **Outcome:**
  * `make test` on Mac M1 uses native ARM containers (fast).
  * `make package SDK_ARCH=mips_24kc` forces a cross-compile (flexible).

---

## Milestone 2: CI "Smart Factory" Optimization

**Goal:** Reduce CI costs and build times by pre-building heavy dependencies and using intelligent caching.

### 2.1 Single Source of Truth (The "API" Step)

**Goal:** Prevent configuration drift by allowing CI to read variables directly from the codebase.

* **Target File:** `devenv/Makefile`
* **Action:** Add a generic "getter" rule (make print-env VAR=PKG_DEPENDS).
* **Outcome:** CI scripts can run `make print-env VAR=PKG_DEPENDS` to get the exact list of packages defined in the project configuration.

### 2.2 The "Factory" Workflow (New Action)

**Goal:** Create a workflow that builds and pushes Docker images to GHCR only when necessary.

* **Target File:** `.github/workflows/build-images.yml` (New)
* **Job 1: Traffic Control**
  * Use `dorny/paths-filter` to detect changes.
  * Trigger **SDK** rebuild if `devenv/services/sdk/**` changes.
  * Trigger **LuCI** rebuild if `devenv/services/luci/**` OR `devenv/Makefile` changes.
* **Job 2: Variable Extraction**
  * Run `make -s -C devenv print-env VAR=PKG_DEPENDS`.
  * Save output to `$GITHUB_ENV` to use as a Docker Build Argument.
* **Job 3: Build Core Images (Matrix)**
  * Matrix: `[x86-64, aarch64_cortex-a53, mips_24kc, mipsel_24kc, arm_cortex-a9]`
  * Pass `PKG_DEPENDS` as a build argument.
  * **Crucial:** Use `cache-from: type=registry` to reuse existing layers if `PKG_DEPENDS` has not changed.
* **Job 4: Build Helper Images**
  * Build `IdP` and `Browser` images once (x86-only).

### 2.3 The "Consumer" Workflow (Main CI)

**Goal:** Drastic speed improvement for per-commit tests.

* **Target File:** `.github/workflows/ci.yml`
* **Action:** Refactor to use the pre-built images.
* **Logic:**
  * Remove `runs-on` initialization steps (installing deps, etc.).
  * Use `container:` or `image:` directives pointing to `ghcr.io/${REPO}/luci-sso-luci:${ARCH}-${VERSION}`.
* **Outcome:** CI skips the 15-minute `mbedtls` compilation and immediately starts running `make test`.
