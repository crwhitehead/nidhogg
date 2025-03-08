#!/usr/bin/env python3
"""
Setup script for Nidhogg - Python Bytecode Analysis and Malware Detection Tool.
"""

import os
from setuptools import setup, find_packages

# Read the long description from README.md
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="nidhogg",
    version="0.1.0",
    description="Python Bytecode Analysis and Malware Detection Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Cameron Whitehead",
    url="https://github.com/crwhitehead/nidhogg",  # Replace with actual URL
    packages=find_packages(),
    scripts=["scripts/nidhogg_scan.py"],
    entry_points={
        "console_scripts": [
            "nidhogg=nidhogg.cli:main",
        ],
    },
    install_requires=[
        "crosshair-tool>=0.0.84",
        "colorama>=0.4.4",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    keywords="security, malware, bytecode, analysis, detection, debugging",
    package_data={
        "nidhogg": ["rules/definitions/*.json"],
    },
)