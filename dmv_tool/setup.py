#!/usr/bin/env python3

# Copyright 2025 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys


def get_install_requires():
    """ """
    with open(os.path.realpath("requirements.txt")) as f:
        required = f.read().splitlines()
        return required


try:
    from setuptools import find_packages, setup
except ImportError:
    print("Package setuptools is missing from your Python installation. "
          "Please see the installation section in the esp-matter-dm-validator "
          "documentation for instructions on how to install it.")
    exit(1)

VERSION = "1.0.1"

long_description = """
====================================
esp-matter-data-model-validator Tool
====================================
A command-line utility for validating Matter device data model conformance
against the official Matter specification.

Source code for `esp-matter-data-model-validator` is
`hosted on github <https://github.com/espressif/esp-matter-tools/tree/main/dmv_tool>`_.

Documentation
-------------
Visit online `esp-matter-dm-validator documentation <https://github.com/espressif/esp-matter-tools/tree/main/dmv_tool>`_
or run ``esp-matter-dm-validator -h``.

License
-------
The License for the project can be found
`here <https://github.com/espressif/esp-matter-tools/tree/main/LICENSE>`_
"""

setup(
    name="esp-matter-dm-validator",
    version=VERSION,
    description=(
        "A command-line utility for validating Matter device data model "
        "conformance against the official Matter specification."
    ),
    long_description=long_description,  # noqa: E501
    long_description_content_type="text/markdown",
    url="https://github.com/espressif/esp-matter-tools/tree/main/dmv_tool",
    project_urls={
        "Documentation": (
            "https://github.com/espressif/esp-matter-tools/tree/main/"
            "dmv_tool/README.md"
        ),
        "Source":
        "https://github.com/espressif/esp-matter-tools/tree/main/dmv_tool",
    },
    author="Espressif Systems",
    author_email="",
    license="Apache-2.0",
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Software Development :: Embedded Systems",
    ],
    python_requires=">=3.10",
    setup_requires=(["wheel"] if "bdist_wheel" in sys.argv else []),
    install_requires=get_install_requires(),
    include_package_data=True,
    package_dir={"dmv_tool": "."},
    packages=["dmv_tool"] + [
        f"dmv_tool.{pkg}"
        for pkg in find_packages(exclude=["tests", "tests.*"])
    ],
    package_data={
        "dmv_tool.data": ["*.json"],
    },
    entry_points={
        "console_scripts": [
            "esp-matter-dm-validator=dmv_tool.cli.main:main"
        ],
    },
)
