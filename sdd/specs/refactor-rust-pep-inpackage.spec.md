# SPEC: Refactor Rust PEP Extension Into Python Package

**ID:** FEAT-RUST-PEP-INPKG
**Status:** Draft
**Author:** Jesus Lara
**Date:** 2026-04-08
**Priority:** Critical (release-blocking)

---

## 1. Problem Statement

The Rust extension `navigator_auth_pep` lives in `rust/` at the repository root, **outside** the `navigator_auth/` Python package. When a release is built and published to PyPI, the Rust extension is **silently excluded** from the wheel because:

1. `setuptools` only packages what's inside `navigator_auth/` (per `find` config in `pyproject.toml`).
2. `MANIFEST.in` grafts `navigator_auth/` but not `rust/`.
3. `setup.py` calls `maturin develop --release` (development-only), which installs the `.so` into the **local virtualenv** but does **not** embed it in the wheel.
4. There is **no `[tool.maturin]` section** in `pyproject.toml` and **no `RustExtension`** in `setup.py`.
5. The CI workflow (`release.yml`) installs `maturin` but never calls `maturin build` — `cibuildwheel` runs `setuptools` which has no knowledge of the Rust crate.

**Result:** Releases are published to PyPI without the compiled Rust `.so`. The import fails silently at runtime because `__init__.py` catches `ImportError` and sets `navigator_auth_pep = None`. Users get a degraded (or broken) experience with no indication why.

### Reference: How DataModel Does It Correctly

`python-datamodel` uses **`setuptools-rust`** with the Rust crate **inside** the package:

```
DataModel/
├── Cargo.toml                          # workspace root
├── pyproject.toml                      # requires setuptools-rust>=1.10.2
├── setup.py                            # RustExtension("datamodel.rs_parsers", path="datamodel/rs_parsers/Cargo.toml")
├── MANIFEST.in                         # recursive-include datamodel/rs_parsers *
└── datamodel/
    ├── __init__.py
    ├── converters.pyx                  # import datamodel.rs_parsers as rc
    ├── rs_parsers/
    │   ├── Cargo.toml                  # [lib] name = "rs_parsers", crate-type = ["cdylib"]
    │   └── src/
    │       └── lib.rs
    ├── rs_core/
    │   ├── Cargo.toml
    │   └── src/lib.rs
    └── rs_validators/
        ├── Cargo.toml
        └── src/lib.rs
```

Key differences:
- Rust source is **inside** `datamodel/`, so `graft datamodel` captures it.
- `setup.py` declares `RustExtension(...)` → setuptools-rust compiles and embeds the `.so` in the wheel.
- **No maturin involved** — uses `setuptools-rust` which integrates natively with setuptools.

---

## 2. Goal

Move the Rust PEP extension inside the `navigator_auth/` package and switch from `maturin` to `setuptools-rust`, matching the proven DataModel pattern. The compiled `.so` must be **embedded in the wheel** on every release.

---

## 3. Current State (Before)

```
navigator-auth/
├── Cargo.toml                          # (does not exist at root)
├── pyproject.toml                      # requires maturin>=1.0, build-backend = setuptools
├── setup.py                            # maturin develop --release (dev only)
├── MANIFEST.in                         # graft navigator_auth (no rust/)
├── rust/
│   ├── Cargo.toml                      # [lib] name = "navigator_auth_pep", crate-type = ["cdylib"]
│   ├── Cargo.lock
│   └── src/
│       └── lib.rs                      # 705 lines, exports filter_resources_batch + evaluate_single
└── navigator_auth/
    ├── __init__.py                     # try: import navigator_auth_pep (top-level, wrong path)
    └── abac/policies/evaluator.py      # from navigator_auth_pep import evaluate_single, filter_resources_batch
```

### Problems Summary

| Issue | Impact |
|-------|--------|
| `rust/` outside `navigator_auth/` | Not included in wheel |
| `setup.py` uses `maturin develop` | Only works locally, not in `pip install` / `cibuildwheel` |
| No `RustExtension` in `setup.py` | setuptools doesn't know about Rust |
| `maturin>=1.0` in build-requires but unused | Dead dependency, misleading |
| `MANIFEST.in` doesn't include `rust/` | sdist also missing Rust source |
| `import navigator_auth_pep` (top-level) | Wrong module path after refactor |
| CI installs maturin but doesn't use it for build | Rust .so not in wheel |

---

## 4. Target State (After)

```
navigator-auth/
├── Cargo.toml                          # NEW: workspace root
├── pyproject.toml                      # CHANGED: setuptools-rust>=1.10.2 instead of maturin
├── setup.py                            # CHANGED: RustExtension("navigator_auth.rs_pep", ...)
├── MANIFEST.in                         # CHANGED: recursive-include navigator_auth/rs_pep *
├── rust/                               # REMOVED (or kept as symlink/empty README)
└── navigator_auth/
    ├── __init__.py                     # CHANGED: from navigator_auth.rs_pep import ...
    ├── rs_pep/                         # NEW: Rust crate inside package
    │   ├── Cargo.toml                  # [lib] name = "rs_pep", crate-type = ["cdylib"]
    │   ├── Cargo.lock
    │   └── src/
    │       └── lib.rs                  # Same 705 lines, module renamed
    └── abac/policies/evaluator.py      # CHANGED: from navigator_auth.rs_pep import ...
```

### Module Import Path Change

| Before | After |
|--------|-------|
| `import navigator_auth_pep` | `from navigator_auth import rs_pep` |
| `from navigator_auth_pep import evaluate_single` | `from navigator_auth.rs_pep import evaluate_single` |
| `from navigator_auth_pep import filter_resources_batch` | `from navigator_auth.rs_pep import filter_resources_batch` |

---

## 5. Detailed Changes

### 5.1 Create Workspace `Cargo.toml` (Root)

**File:** `Cargo.toml` (new, at repo root)

```toml
[workspace]
members = ["navigator_auth/rs_pep"]

[workspace.dependencies]
pyo3 = { version = "0.22", features = ["extension-module"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rayon = "1.10"
glob-match = "0.2"
regex = "1.10"
```

### 5.2 Move & Rename Rust Crate

**From:** `rust/` → **To:** `navigator_auth/rs_pep/`

```bash
mkdir -p navigator_auth/rs_pep
cp -r rust/src navigator_auth/rs_pep/
cp rust/Cargo.lock navigator_auth/rs_pep/
```

**File:** `navigator_auth/rs_pep/Cargo.toml` (new)

```toml
[package]
name = "rs_pep"
version = "0.1.0"
edition = "2021"
description = "High-performance PEP batch filter for navigator-auth PBAC"

[lib]
name = "rs_pep"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
rayon = { workspace = true }
glob-match = { workspace = true }
regex = { workspace = true }
```

**File:** `navigator_auth/rs_pep/src/lib.rs` — Change only the module name:

```rust
// Change from:
#[pymodule]
fn navigator_auth_pep(m: &Bound<'_, PyModule>) -> PyResult<()> {
// To:
#[pymodule]
fn rs_pep(m: &Bound<'_, PyModule>) -> PyResult<()> {
```

### 5.3 Update `pyproject.toml`

```diff
 [build-system]
 requires = [
   'setuptools>=74.0.0',
   'Cython>=3.0.11',
   'wheel>=0.44.0',
-  'maturin>=1.0'
+  'setuptools-rust>=1.10.2',
 ]
 build-backend = "setuptools.build_meta"
```

### 5.4 Update `setup.py`

```python
#!/usr/bin/env python
from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools_rust import RustExtension

COMPILE_ARGS = ["-O3"]

rust_extensions = [
    RustExtension(
        "navigator_auth.rs_pep",
        path="navigator_auth/rs_pep/Cargo.toml",
    ),
]

extensions = [
    Extension(
        name='navigator_auth.libs.json',
        sources=['navigator_auth/libs/json.pyx'],
        extra_compile_args=COMPILE_ARGS,
        language="c++"
    ),
    Extension(
        name='navigator_auth.libs.cipher',
        sources=['navigator_auth/libs/cipher.pyx'],
        extra_compile_args=COMPILE_ARGS,
        language="c++"
    ),
    Extension(
        name='navigator_auth.libs.parser',
        sources=['navigator_auth/libs/parser.pyx'],
        extra_compile_args=COMPILE_ARGS,
        language="c++"
    ),
    Extension(
        name='navigator_auth.libs.policy_eval',
        sources=['navigator_auth/libs/policy_eval.pyx'],
        extra_compile_args=COMPILE_ARGS,
        language="c"
    ),
]

setup(
    ext_modules=cythonize(extensions),
    zip_safe=False,
    rust_extensions=rust_extensions,
)
```

**Removed:** `BuildExtensions` class, `_try_build_rust_dev()`, subprocess maturin call. All unnecessary — `setuptools-rust` handles everything.

### 5.5 Update `MANIFEST.in`

```diff
 include LICENSE
 include CHANGES.rst
 include README.md
 include Makefile
 graft navigator_auth
 graft docs
 graft tests
+recursive-include navigator_auth/rs_pep *
+recursive-exclude navigator_auth/rs_pep/target *
 global-exclude *.pyc
 prune docs/_build
```

### 5.6 Update Python Imports

**`navigator_auth/__init__.py`:**

```diff
-# Try to import the Rust extension (navigator_auth_pep)
-try:
-    import navigator_auth_pep
-except ImportError:
-    navigator_auth_pep = None
+# Try to import the Rust PEP extension
+try:
+    from navigator_auth import rs_pep
+except ImportError:
+    rs_pep = None

-__all__ = ("AuthHandler", "navigator_auth_pep")
+__all__ = ("AuthHandler", "rs_pep")
```

**`navigator_auth/abac/policies/evaluator.py`:**

```diff
-from navigator_auth_pep import evaluate_single, filter_resources_batch
+from navigator_auth.rs_pep import evaluate_single, filter_resources_batch
```

### 5.7 Update CI Workflow (`.github/workflows/release.yml`)

```diff
     - name: Install dependencies
       run: |
-        uv pip install --system cibuildwheel twine cython maturin
+        uv pip install --system cibuildwheel twine cython setuptools-rust

     - name: Build wheels on Ubuntu
       if: matrix.os == 'ubuntu-latest'
       env:
         CIBW_ARCHS: x86_64
         CIBW_BUILD: "cp3{10,11,12,13}-*"
         CIBW_SKIP: "*-musllinux_*"
-        CIBW_BEFORE_BUILD: "pip install cython maturin"
+        CIBW_BEFORE_BUILD: "curl https://sh.rustup.rs -sSf | sh -s -- -y && pip install cython setuptools-rust"
+        CIBW_ENVIRONMENT: "PATH=/root/.cargo/bin:$PATH"
+        RUST_SUBPACKAGE_PATH: navigator_auth/rs_pep
       run: |
         cibuildwheel --platform linux --output-dir dist
```

**Key additions:**
- Install Rust toolchain inside cibuildwheel container (`curl https://sh.rustup.rs`)
- Export `PATH` so cargo is available
- Set `RUST_SUBPACKAGE_PATH` for discoverability

### 5.8 Delete Old `rust/` Directory

After verifying the new structure works:

```bash
rm -rf rust/
```

### 5.9 Update `.gitignore`

Add Rust build artifacts for the new location:

```
navigator_auth/rs_pep/target/
```

---

## 6. Task Breakdown

| # | Task | Depends On | Risk | Effort |
|---|------|------------|------|--------|
| 1 | Create root `Cargo.toml` workspace | — | Low | Small |
| 2 | Move `rust/` → `navigator_auth/rs_pep/`, update Cargo.toml | 1 | Low | Small |
| 3 | Rename `#[pymodule]` from `navigator_auth_pep` → `rs_pep` in `lib.rs` | 2 | Low | Small |
| 4 | Update `pyproject.toml`: replace `maturin` with `setuptools-rust` | — | Low | Small |
| 5 | Rewrite `setup.py`: add `RustExtension`, remove maturin subprocess | 4 | Medium | Small |
| 6 | Update `MANIFEST.in` to include `navigator_auth/rs_pep` | 2 | Low | Small |
| 7 | Update all Python imports (`__init__.py`, `evaluator.py`, any others) | 3 | Medium | Small |
| 8 | Update `.gitignore` for new target path | 2 | Low | Trivial |
| 9 | Build locally with `pip install -e .` and verify `.so` is in `navigator_auth/` | 1-8 | Medium | Medium |
| 10 | Run Rust tests (`cargo test` from root workspace) | 2-3 | Low | Small |
| 11 | Run Python tests (`pytest`) to verify PEP integration works | 9 | High | Medium |
| 12 | Update CI workflow (`.github/workflows/release.yml`) | 4 | Medium | Small |
| 13 | Verify `python -m build --wheel` produces a wheel containing `rs_pep*.so` | 9-12 | **Critical** | Medium |
| 14 | Remove old `rust/` directory | 9-11 | Low | Trivial |
| 15 | Update any SDD docs or worktree branches referencing `rust/` path | 14 | Low | Small |

---

## 7. Verification Checklist

### Local Build
- [ ] `pip install -e .` completes without errors
- [ ] `python -c "from navigator_auth.rs_pep import evaluate_single; print('OK')"` succeeds
- [ ] `python -c "from navigator_auth.rs_pep import filter_resources_batch; print('OK')"` succeeds
- [ ] `cargo test` from repo root passes all Rust tests

### Wheel Inspection
- [ ] `python -m build --wheel` produces a `.whl`
- [ ] `unzip -l dist/*.whl | grep rs_pep` shows the compiled `.so` inside the wheel
- [ ] Install the wheel in a clean venv: `pip install dist/*.whl`
- [ ] `python -c "from navigator_auth.rs_pep import evaluate_single"` works from the wheel

### Integration Tests
- [ ] `pytest tests/` passes (especially any ABAC/PEP-related tests)
- [ ] `evaluator.py` can call `evaluate_single()` and `filter_resources_batch()` correctly

### CI Dry Run
- [ ] Push to a test branch and trigger a manual workflow run
- [ ] Verify wheels contain `rs_pep*.so` in artifacts

---

## 8. Rollback Plan

If the refactor causes issues:
1. The old `rust/` directory is preserved in git history.
2. Revert the commit(s) and tag a new release.
3. For emergency: revert `setup.py` and `pyproject.toml` to maturin-based approach, manually run `maturin build --release` and include the `.so` in the wheel.

---

## 9. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `setuptools-rust` doesn't compile with current PyO3 version | Low | High | DataModel uses PyO3 0.23.3 successfully; navigator-auth uses 0.22 which is also supported |
| Import path change breaks downstream consumers | Medium | Medium | `navigator_auth_pep` was never reliably in wheels, so no external consumers depend on it |
| `cibuildwheel` doesn't find Rust toolchain | Medium | High | Proven pattern from DataModel CI; install Rust in `CIBW_BEFORE_BUILD` |
| Existing worktree branch (`feat-002`) has old `rust/` references | Low | Low | Update or rebase after merge |

---

## 10. Notes

- **Why not keep maturin?** Maturin expects to be the sole build backend (`maturin build`). navigator-auth also needs Cython, so the build backend must be `setuptools`. `setuptools-rust` integrates natively with setuptools, handling both Cython and Rust in one `pip install`.
- **PyO3 version:** Consider upgrading from `0.22` to `0.23.3` (same as DataModel) during this refactor for consistency and latest features. This is optional but recommended.
- **Module naming:** `rs_pep` follows the DataModel convention (`rs_parsers`, `rs_core`, `rs_validators`) — `rs_` prefix for Rust submodules.
