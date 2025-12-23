# ESP Matter Data Model Validation (DMV) Tool

A Python utility for validating Matter device data model conformance against Matter specifications.

## Overview
The tool relies on pre-generated standard data model JSON files located in:
src/data/validation_data_{spec_version}.json

You can generate these files yourself using the generate-reference-json command See [Generate Validation JSONs](#3-generate-matter-specification-jsons) for more details.

## Directory Structure

```
dmv_tool/
├── cli/                        # Command-line interface
├── data/                       # Pre-generated validation data JSONs
├── generators/                 # XML specification parsing and JSON generation
├── parsers/                    # Log parsing functionality
├── utils/                      # utility functions
├── validators/                 # Core validation logic

```

## Installation

### From PyPI (Recommended)

```bash
pip install esp-matter-dm-validator
```

### From Source

```bash
git clone https://github.com/espressif/esp-matter-tools.git
cd esp-matter-tools/dmv_tool
pip install -e .
```

## Quick Start

### 1. Validate Device Conformance

Analyze chip-tool wildcard logs to check Matter conformance against the data model xml specifications in connectedhomeip.

If the `spec-version` is not provided, the tool automatically attempts to detect the version from the wildcard logs. If it cannot detect the version correctly, the default version is set to `1.5`.

It is recommended to explicitly provide the spec-version for accurate validation.

```bash
esp-matter-dm-validator check-conformance /path/to/wildcard.log
esp-matter-dm-validator check-conformance /path/to/wildcard.log --spec-version 1.4
esp-matter-dm-validator check-conformance /path/to/wildcard.log --spec-version 1.4.2 --output-path my_report.txt
```

### 2. Parse Logs Only

Extract structured data from chip-tool wildcard logs:

```bash
esp-matter-dm-validator logs-to-json /path/to/wildcard.log --output-path parsed_data.json
```

### 3. Generate Matter Specification JSONs

Create validation JSONs from Matter XML specifications in the ConnectedHomeIP repository:

```bash
esp-matter-dm-validator generate-reference-json \
  --chip-path /path/to/connectedhomeip \
  --spec-version-dir 1.4 \
  --output-dir .
```

## Use as a Python module

Once installed (via `pip install esp-matter-dm-validator` or `pip install -e .` from this directory), you can import its APIs directly inside Python programs.

```python
from validators.conformance_checker import validate_device_conformance
from parsers.wildcard_logs.parse_datamodel_logs import parse_datamodel_logs

parsed_data = parse_datamodel_logs(wildcard_file_data)
results = validate_device_conformance(parsed_data, spec_version="1.4.2")

```

## Supported Matter Spec Versions

- Matter 1.2
- Matter 1.3
- Matter 1.4
- Matter 1.4.1
- Matter 1.4.2
- Matter 1.5
