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
ESP Matter Data Model Validation (DMV) Tool

A command-line utility for validating Matter device data model conformance
against the official Matter specification.

This tool provides the following major capabilities:
  • check-conformance: checkdevice data model conformance from chip-tool
    wildcard logs
  • logs-to-json: parse and convert chip-tool wildcard logs into structured JSON
    for analysis
  • generate-reference-json: generate reference JSONs directly from
    connectedhomeip XML specifications
"""

import click
import sys
import logging
import os
from dmv_tool.configs.constants import (
    SUPPORTED_SPEC_VERSIONS,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PARSED_DATA_FILE,
    DEFAULT_REPORT_FILE,
)


def setup_logging(verbose):
    """Configure logging behavior based on verbosity."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s: %(filename)s:%(lineno)d - %(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(levelname)s: %(filename)s:%(lineno)d - %(message)s",
        )


@click.group()
def cli():
    """ESP Matter Data Model Validation (DMV) Tool

    A command-line utility for validating Matter device data model conformance
    against the official Matter specification.

    \b
    Common Use Cases:
      # Check device conformance using chip-tool wildcard logs
      esp-matter-dm-validator check-conformance device_wildcard.log

      # Convert chip-tool wildcard logs into structured JSON
      esp-matter-dm-validator logs-to-json device.log --output-path parsed.json

      # Generate reference JSONs from connectedhomeip sources
      esp-matter-dm-validator generate-reference-json \
        --chip-path /path/to/connectedhomeip --spec-version-dir 1.4

    For more details, visit:
    https://github.com/espressif/esp-matter-tools/dmv_tool/README.md
    """
    pass


@cli.command(name="check-conformance")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--spec-version",
    type=click.Choice(SUPPORTED_SPEC_VERSIONS, case_sensitive=False),
    help="Matter specification version to validate against "
         "(auto-detected if not provided)",
)
@click.option(
    "--output-path",
    type=click.Path(),
    help="Output path for the conformance report",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable detailed debug logging",
)
def check_conformance_command(file_path, spec_version, output_path, verbose):
    """Check Matter device data model conformance

    Analyzes chip-tool wildcard logs to verify whether a device's data model
    implementation aligns with the Matter specification definitions.

    If the specification version is not provided, it is automatically
    inferred from the logs.
    """
    setup_logging(verbose)

    from dmv_tool.validators.conformance_checker import validate_data_model_conformance

    if not output_path:
        output_path = os.path.join(
            os.getcwd(), DEFAULT_OUTPUT_DIR, DEFAULT_REPORT_FILE
        )

    is_compliant = validate_data_model_conformance(
        file_path, spec_version, output_path
    )
    if is_compliant:
        click.echo(click.style("DEVICE IS COMPLIANT", fg="green", bold=True))
    else:
        click.echo(click.style("DEVICE IS NOT COMPLIANT", fg="red", bold=True))


@cli.command(name="logs-to-json")
@click.argument("file_path", type=click.Path(exists=True))
@click.option(
    "--output-path",
    type=click.Path(),
    help="Path to save the parsed JSON output",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable detailed debug logging",
)
def logs_to_json_command(file_path, output_path, verbose):
    """Convert chip-tool wildcard logs into structured JSON

    Parses chip-tool wildcard logs and converts them into a structured
    JSON format that can be used for analysis, reporting, or conformance
    validation.
    """
    setup_logging(verbose)

    from dmv_tool.parsers.wildcard_logs import parse_wildcard_file

    if not output_path:
        output_path = os.path.join(
            os.getcwd(), DEFAULT_OUTPUT_DIR, DEFAULT_PARSED_DATA_FILE
        )

    try:
        parse_wildcard_file(file_path, output_path)
        click.echo(click.style("LOG PARSING COMPLETED", fg="green", bold=True))
    except ValueError as e:
        click.echo(
            click.style(f"Error parsing logs: {e}", fg="red", bold=True)
        )
        sys.exit(1)


@cli.command(name="generate-reference-json")
@click.option(
    "--chip-path",
    required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    help="Path to the connectedhomeip repository",
    callback=lambda ctx, param, value: validate_chip_path(value),
)
@click.option(
    "--spec-version-dir",
    type=click.Choice(SUPPORTED_SPEC_VERSIONS, case_sensitive=False),
    help="Specification version directory within connectedhomeip/data_model",
    callback=lambda ctx, param, value: validate_spec_version_dir(ctx, value),
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    help="Directory to save generated reference JSONs",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable detailed debug logging",
)
def generate_reference_command(
    chip_path, spec_version_dir, output_dir, verbose
):
    """Generate Matter reference JSONs from connectedhomeip XMLs

    Generates baseline Matter data model JSONs from the XML
    specifications in the connectedhomeip repository. These serve as
    reference data for validating device conformance.
    """
    setup_logging(verbose)

    from dmv_tool.generators.main import generate_chip_validation_data

    if not output_dir:
        output_dir = os.path.join(os.getcwd(), DEFAULT_OUTPUT_DIR)

    result = generate_chip_validation_data(
        chip_path, spec_version_dir, output_dir
    )
    if result:
        click.echo(
            click.style(
                "REFERENCE GENERATION COMPLETED", fg="green", bold=True
            )
        )
    else:
        click.echo(
            click.style("REFERENCE GENERATION FAILED", fg="red", bold=True)
        )
        sys.exit(1)


def validate_chip_path(value):
    """Ensure chip path exists and appears to be a connectedhomeip repo."""
    if not value:
        raise click.BadParameter("Chip path is required.")
    if not os.path.exists(value):
        raise click.BadParameter(f"Path does not exist: {value}")
    if os.path.basename(os.path.normpath(value)) != "connectedhomeip":
        raise click.BadParameter(
            f"The provided path does not appear to be a connectedhomeip repository \n"
            f"Path provided: {value} \n"
            f"Ideal path: /path/to/connectedhomeip/ \n"
        )
    return value


def validate_spec_version_dir(ctx, value):
    """Validate spec version directory exists under connectedhomeip/data_model."""  # noqa: E501
    if not value:
        raise click.BadParameter("Spec version directory is required.")

    chip_path = ctx.params.get("chip_path")
    if chip_path:
        spec_dir_path = os.path.join(chip_path, "data_model", value)
        if not os.path.exists(spec_dir_path):
            raise click.BadParameter(
                f"Spec version directory '{value}' not found in: {spec_dir_path}"
            )
    return value


def main():
    """Main entry point for esp-matter-dm-validator."""
    cli()


if __name__ == "__main__":
    main()
