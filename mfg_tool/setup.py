#-!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import pkg_resources

patch_list = [
{
    'package': 'deps',
    'file': 'patches/0001-mfg-gen-no-bin-and-replace-print-by-logging.patch'
}]

def is_patch_applied(patch_file):
    try:
        result = subprocess.run(["patch", "--dry-run", "-p2"], input=open(patch_file, "rb").read(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return b'previously applied' in result.stderr or result.returncode != 0
    except Exception as e:
        print(f"Error checking patch status: {e}")
        return False

def apply_patch(pkg_name, file_name):
    patch_file = pkg_resources.resource_filename(pkg_name, file_name)

    if is_patch_applied(patch_file):
        print("Patch already applied, skipping.")
        return

    try:
        subprocess.run(["patch", "-p2"], input=open(patch_file, "rb").read(), check=True)
        print("Patch applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying patch: {e}")
        sys.exit(1)

class CustomBuild(build_py):
    def run(self):
        for patch in patch_list:
            print(f" Applying patch {patch['file']} before building the package ")
            # Apply patch before building
            apply_patch(patch['package'], patch['file'])
        # Continue with normal build process
        super().run()


def get_install_requires():
    with open(os.path.realpath('requirements.txt')) as f:
        required = f.read().splitlines()
        return required

try:
    from setuptools import find_packages, setup
except ImportError:
    print(
        "Package setuptools is missing from your Python installation. "
        "Please see the installation section in the esp-matter-mfg-tool "
        "documentation for instructions on how to install it."
    )
    exit(1)

VERSION = "1.0.13"

long_description = """
====================
esp-matter-mfg-tool
====================
The python utility helps to generate the matter manufacturing partitions.

Source code for `esp-matter-mfg-tool` is
`hosted on github <https://github.com/espressif/esp-matter-tools/tree/main/mfg_tool>`_.

Documentation
-------------
Visit online `esp-matter-mfg-tool documentation <https://github.com/espressif/esp-matter-tools/tree/main/mfg_tool>`_
or run ``esp-matter-mfg-tool -h``.

License
-------
The License for the project can be found
`here <https://github.com/espressif/esp-matter-tools/tree/main/LICENSE>`_
"""

setup(
    name = "esp-matter-mfg-tool",
    version = VERSION,
    description = "A python utility which helps to generate matter manufacturing partitions",
    long_description = long_description,
    long_description_content_type = 'text/x-rst',
    url = "https://github.com/espressif/esp-matter-tools/tree/main/mfg_tool",

    project_urls = {
        "Documentation": "https://github.com/espressif/esp-matter-tools/tree/main/mfg_tool/README.md",
        "Source": "https://github.com/espressif/esp-matter-tools/tree/main/mfg_tool",
    },

    author = "Espressif Systems",
    author_email = "",
    license = "Apache-2.0",

    classifiers = [
        "License :: OSI Approved :: Apache Software License",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Software Development :: Embedded Systems",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],

    python_requires = ">=3.8",
    setup_requires = (["wheel"] if "bdist_wheel" in sys.argv else []),
    install_requires = get_install_requires(),
    include_package_data = True,
    packages = find_packages(),
    package_data = {
      'deps':['patches/*.patch'],
    },
    entry_points={
        'console_scripts': [
            'esp-matter-mfg-tool = sources.mfg_tool:main',
        ],
    },
    cmdclass={"build_py": CustomBuild},
)
