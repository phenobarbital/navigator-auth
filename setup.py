#!/usr/bin/env python
"""Navigator-Auth.

    Navigator-Auth is a python package that provides a simple an integrated way
    to authenticate using several authentication mechanisms.
See:
https://github.com/phenobarbital/navigator-auth
"""
import ast
from os import path

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup


def get_path(filename):
    return path.join(path.dirname(path.abspath(__file__)), filename)


def readme():
    with open(get_path('README.md'), 'r', encoding='utf-8') as rd:
        return rd.read()


version = get_path('navigator_auth/version.py')
with open(version, 'r', encoding='utf-8') as meta:
    # exec(meta.read())
    t = compile(meta.read(), version, 'exec', ast.PyCF_ONLY_AST)
    for node in (n for n in t.body if isinstance(n, ast.Assign)):
        if len(node.targets) == 1:
            name = node.targets[0]
            if isinstance(name, ast.Name) and \
                    name.id in (
                        '__version__',
                        '__title__',
                        '__description__',
                        '__author__',
                        '__license__', '__author_email__'
            ):
                v = node.value
                if name.id == '__version__':
                    __version__ = v.s
                elif name.id == '__title__':
                    __title__ = v.s
                elif name.id == '__description__':
                    __description__ = v.s
                elif name.id == '__license__':
                    __license__ = v.s
                elif name.id == '__author__':
                    __author__ = v.s
                elif name.id == '__author_email__':
                    __author_email__ = v.s

COMPILE_ARGS = ["-O3"]

extensions = [
    Extension(
        name='navigator_auth.exceptions',
        sources=['navigator_auth/exceptions.pyx'],
        extra_compile_args=COMPILE_ARGS,
        language="c"
    ),
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
]


setup(
    name="navigator-auth",
    py_modules=['navigator_auth'],
    version=__version__,
    python_requires=">=3.9.14",
    url="https://github.com/phenobarbital/navigator-auth",
    description=__description__,
    keywords=[
        'asyncio',
        'auth',
        'abac',
        'aiohttp',
        'authz',
        'authentication',
        'authorization'
    ],
    platforms=['POSIX'],
    long_description=readme(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: Apache Software License",
        "Environment :: Web Environment",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: AsyncIO",
        "Framework :: aiohttp",
    ],
    author=__author__,
    author_email=__author_email__,
    packages=find_packages(
        exclude=[
            'contrib', 'docs', 'tests', 'settings', 'resources', "examples"
        ]
    ),
    license=__license__,
    setup_requires=[
        'setuptools==74.0.0',
        'Cython==3.0.11',
        'wheel==0.44.0'
    ],
    install_requires=[
        "Cython==3.0.11",
        "PyNaCl==1.5.0",
        "aiohttp>=3.9.5",
        "alt-aiohttp-cors>=0.7.1",
        "PyJWT==2.9.0",
        "pycryptodome==3.21.0",
        "rncryptor==3.3.0",
        'msal>=1.28.0,<1.30.1',
        "aiogoogle==5.13.2",
        "okta-jwt-verifier==0.2.5",
        "python-slugify==8.0.1",
        "asyncdb>=2.8.0",
        "navconfig>=1.7.0",
        "navigator-session>=0.6.2",
    ],
    extras_require={
        "uvloop": [
            "uvloop>=0.20.0",
        ],
    },
    ext_modules=cythonize(extensions),
    project_urls={  # Optional
        "Source": "https://github.com/phenobarbital/navigator-auth",
        "Funding": "https://paypal.me/phenobarbital",
        "Tracker": "https://github.com/phenobarbital/navigator-auth/issues",
        "Documentation": "https://github.com/phenobarbital/navigator-auth",
        "Say Thanks!": "https://saythanks.io/to/phenobarbital",
    },
)
