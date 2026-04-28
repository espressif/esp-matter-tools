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

"""
CLI wrapper to run one or more test cases from the integration test suite.

Modes:
- ``--test-num N``: run exactly the case with ``test_num == N``.
- ``--from-test-num N``: run every case with ``test_num >= N`` (in order).
- Neither: build a one-off Config from the other --command / --validate-*
  flags and run that.
"""

import logging

import click

from tests.test_integration import TestEspMatterMfgToolIntegration
from tests.utils import Config, load_test_data

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.command()
@click.option(
    "--test-num",
    type=int,
    default=None,
    help="Run the case whose test_num matches (1-based). "
    "Mutually exclusive with --from-test-num.",
)
@click.option(
    "--from-test-num",
    type=int,
    default=None,
    help="Run every case with test_num >= N, in order. "
    "Mutually exclusive with --test-num.",
)
@click.option(
    "--description", type=str, default="", help="Description of the test case"
)
@click.option(
    "--expected-output",
    type=str,
    default="Generated output files at:",
    help="Expected output of the test case",
)
@click.option("--command", type=str, required=False, help="Command to run")
@click.option(
    "--validate-cert", is_flag=True, default=False, help="Validate certificates"
)
@click.option(
    "--validate-cn-in-path", is_flag=True, default=False, help="Validate CN in path"
)
@click.option(
    "--validate-cn-not-in-path",
    is_flag=True,
    default=False,
    help="Validate CN not in path",
)
@click.option("--validate-no-bin", is_flag=True, default=False, help="Validate no bin")
@click.option(
    "--validate-csv-quoting", is_flag=True, default=False, help="Validate CSV quoting"
)
@click.option(
    "--validate-secure-cert", is_flag=True, default=False, help="Validate secure cert"
)
@click.option(
    "--validate-no-secure-cert-bin",
    is_flag=True,
    default=False,
    help="Validate no secure cert bin",
)
def main(
    test_num,
    from_test_num,
    description,
    expected_output,
    command,
    validate_cert,
    validate_cn_in_path,
    validate_cn_not_in_path,
    validate_no_bin,
    validate_csv_quoting,
    validate_secure_cert,
    validate_no_secure_cert_bin,
):
    if test_num is not None and from_test_num is not None:
        raise click.UsageError("--test-num and --from-test-num are mutually exclusive")

    test_suite = TestEspMatterMfgToolIntegration()
    test_suite.setup_class()

    if test_num is not None or from_test_num is not None:
        test_data = load_test_data(test_suite.test_data_dir)
        if test_num is not None:
            configs = [c for c in test_data if c.test_num == test_num]
            if not configs:
                raise click.UsageError(f"No test found with test_num={test_num}")
        else:
            configs = [c for c in test_data if c.test_num >= from_test_num]
            if not configs:
                raise click.UsageError(
                    f"No tests found with test_num >= {from_test_num}"
                )
            logger.info(
                f"Running {len(configs)} test(s) with test_num >= {from_test_num}"
            )
    else:
        logger.debug("Running test from command line")
        configs = [
            Config(
                test_num=0,
                description=description,
                expected_output=expected_output,
                command=command,
                validate_cert=validate_cert,
                validate_cn_in_path=validate_cn_in_path,
                validate_cn_not_in_path=validate_cn_not_in_path,
                validate_no_bin=validate_no_bin,
                validate_csv_quoting=validate_csv_quoting,
                validate_secure_cert=validate_secure_cert,
                validate_no_secure_cert_bin=validate_no_secure_cert_bin,
            )
        ]

    for config in configs:
        test_suite.run_single_test(config.test_num, config)
        test_suite.teardown_method()


if __name__ == "__main__":
    main()
