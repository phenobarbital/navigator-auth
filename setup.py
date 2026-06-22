#!/usr/bin/env python
"""Setup.py for Cython and Rust extension support.

Rust extension (navigator_auth.rs_pep) is built via setuptools-rust
and compiled into the wheel automatically during `pip install`.
"""

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
