#!/usr/bin/env python
"""Setup.py with Cython and Rust extension support."""

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
    """Custom build_ext command to compile Rust with maturin, then Cython."""

    def build_extensions(self):
        # Step 1: Compile Rust extension with maturin
        self._build_rust_extension()

        # Step 2: Cythonize and compile Cython extensions
        try:
            self.extensions = cythonize(self.extensions)
        except ImportError:
            print("Cython not found. Extensions will be compiled without cythonization!")
        super().build_extensions()

    def _build_rust_extension(self):
        """Compile Rust extension using maturin."""
        rust_dir = "rust"
        if not os.path.isdir(rust_dir):
            print(f"Rust directory '{rust_dir}' not found. Skipping Rust build.")
            return

        print(f"\n{'='*60}")
        print("Building Rust extension with maturin...")
        print(f"{'='*60}\n")

        try:
            # Compile with maturin develop (installs directly into current env)
            result = subprocess.run(
                [sys.executable, "-m", "maturin", "develop", "--release"],
                cwd=rust_dir,
                capture_output=False,
                text=True,
            )
            if result.returncode != 0:
                print(f"WARNING: Rust extension build failed with code {result.returncode}")
                print("Continuing with Cython-only build...")
        except FileNotFoundError:
            print("WARNING: maturin not found. Skipping Rust build.")
            print("To include Rust extension, install: pip install maturin")
        except Exception as e:
            print(f"WARNING: Error building Rust extension: {e}")
            print("Continuing with Cython-only build...")

if __name__ == "__main__":
    setup(
        ext_modules=cythonize(extensions),
        cmdclass={"build_ext": BuildExtensions},
        zip_safe=False,
    )
