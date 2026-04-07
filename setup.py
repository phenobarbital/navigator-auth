#!/usr/bin/env python
"""Setup.py for Cython and Rust extension support.

Note: Rust extension (navigator_auth_pep) is built separately with maturin.
See .github/workflows/release.yml for the full build pipeline.
For local development, install the Rust extension with:
    cd rust && maturin develop --release
"""

import os
import subprocess
import sys
from Cython.Build import cythonize
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

COMPILE_ARGS = ["-O3"]

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

class BuildExtensions(build_ext):
    """Custom build_ext command to cythonize extensions."""

    def build_extensions(self):
        try:
            self.extensions = cythonize(self.extensions)
        except ImportError:
            print("Cython not found. Extensions will be compiled without cythonization!")
        super().build_extensions()

    def build(self):
        # Try to build Rust extension in development mode
        self._try_build_rust_dev()
        super().build()

    def _try_build_rust_dev(self):
        """Attempt to build Rust extension for development."""
        rust_dir = "rust"
        if not os.path.isdir(rust_dir):
            return

        # Only in development mode (pip install -e .)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "maturin", "develop", "--release"],
                cwd=rust_dir,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                print("✓ Rust extension built successfully")
            else:
                print(f"Note: Rust extension build skipped (maturin not available or build failed)")
                print(f"To build manually: cd rust && maturin develop --release")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Silently skip if maturin not available

if __name__ == "__main__":
    setup(
        ext_modules=cythonize(extensions),
        cmdclass={"build_ext": BuildExtensions},
        zip_safe=False,
    )
