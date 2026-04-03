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

import json
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import List
import shlex
from sources.utils import (
    ProductFinish,
    ProductColor,
    calendar_types_to_uint32,
    get_fixed_label_dict,
    get_supported_modes_dict,
)

logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration for individual test case
    Test case json is converted into this class object for easier access and validation
    This class object is then used to run the test case and validate the output

    Args:
        description: Description of the test case
        command: Command to run the test case
        expected_output: Expected output of the test case
        validate_cert: Whether to validate the certificates generated from the test case output
        validate_path: Whether to validate the output paths generated from the test case output
        validate_no_bin: Whether to validate that no binary partition files are generated from the test case output
        validate_secure_cert: Whether to validate that secure cert partition files are generated from the test case output
        validate_no_secure_cert_bin: Whether to validate that no secure cert partition files are generated from the test case output
    """

    test_num: int
    description: str
    command: str
    expected_output: str
    validate_cert: bool = False
    validate_cn_in_path: bool = False
    validate_cn_not_in_path: bool = False
    validate_no_bin: bool = False
    validate_csv_quoting: bool = False
    validate_secure_cert: bool = False
    validate_no_secure_cert_bin: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        """
        Convert test case json into Config class object
        This is used to run the test case and validate the output
        This is class method to allow for easy conversion from json to Config class object

        Args:
            data: Test case json

        Returns:
            Config: Config class object
        """
        if "test_num" not in data:
            raise ValueError(
                f"test entry missing required 'test_num' field: "
                f"{data.get('description', '<no description>')!r}"
            )
        return cls(
            test_num=data["test_num"],
            description=data.get("description", ""),
            command=data.get("command", ""),
            expected_output=data.get("expected_output", ""),
            validate_cert=data.get("validate_cert", False),
            validate_cn_in_path=data.get("validate_cn_in_path", False),
            validate_cn_not_in_path=data.get("validate_cn_not_in_path", False),
            validate_no_bin=data.get("validate_no_bin", False),
            validate_csv_quoting=data.get("validate_csv_quoting", False),
            validate_secure_cert=data.get("validate_secure_cert", False),
            validate_no_secure_cert_bin=data.get("validate_no_secure_cert_bin", False),
        )


@dataclass
class ParsedOutput:
    """Parsed output of the esp-matter-mfg-tool command"""

    out_path: str = ""
    dac_cert: str = ""
    dac_key: str = ""
    dac_priv_key_bin: str = ""
    dac_pub_key: str = ""
    pai_cert: str = ""
    secure_cert_bin: str = ""
    partition_bin: str = ""


def load_test_data(test_data_dir) -> List[Config]:
    """Load test cases from ``<test_data_dir>/test_integration_inputs.json``."""
    test_data_file = Path(test_data_dir) / "test_integration_inputs.json"
    with open(test_data_file, "r") as f:
        data = json.load(f)
    return [Config.from_dict(test) for test in data.get("tests", [])]


def run_command(command):
    """Run a command and capture output"""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60
        )
        return result
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out: {e}")
        return e


def parse_mfg_tool_output(output: str) -> List[ParsedOutput]:
    """Parse the output of the esp-matter-mfg-tool command"""

    def get_uuid_from_path(path: str) -> str:
        import os

        return os.path.basename(path)

    parsed_output = []

    for line in output.split("\n"):
        if "Generated output files at:" in line:
            out_path = line.split("Generated output files at: ")[1].strip()

            uuid_dir = get_uuid_from_path(out_path)
            secure_cert_bin_path = f"{out_path}/{uuid_dir}_esp_secure_cert.bin"
            partition_bin_path = f"{out_path}/{uuid_dir}-partition.bin"

            parsed_output.append(
                ParsedOutput(
                    out_path=out_path,
                    dac_cert=f"{out_path}/internal/DAC_cert.der",
                    dac_key=f"{out_path}/internal/DAC_key.der",
                    dac_priv_key_bin=f"{out_path}/internal/DAC_private_key.bin",
                    dac_pub_key=f"{out_path}/internal/DAC_public_key.bin",
                    pai_cert=f"{out_path}/internal/PAI_cert.der",
                    secure_cert_bin=secure_cert_bin_path,
                    partition_bin=partition_bin_path,
                )
            )

    return parsed_output


def safe_read_bytes(path):
    p = Path(path)
    return p.read_bytes() if p.exists() else None


def any_base_int(val):
    try:
        return int(val, 0)
    except ValueError:
        return val


def normalize_key(token):
    SHORT_TO_LONG = {
        "-v": "vendor-id",
        "-p": "product-id",
        "-c": "cert",
        "-k": "key",
        "-cd": "cert-dclrn",
        "-cn": "cn-prefix",
        "-dm": "discovery-mode",
        "-cf": "commissioning-flow",
        "-ds": "ds-peripheral",
        "-lt": "lifetime",
        "-vf": "valid-from",
        "-n": "count",
        "-s": "size",
        "-e": "encrypt",
    }
    if token.startswith("--"):
        return token[2:]

    if token in SHORT_TO_LONG:
        return SHORT_TO_LONG[token]

    raise ValueError(
        f"unknown short flag {token!r} in test command — "
        f"add it to SHORT_TO_LONG in tests/utils.py::normalize_key"
    )


def parse_command_arguments(command: str) -> dict:
    tokens = shlex.split(command)

    if tokens and not tokens[0].startswith("-"):
        tokens = tokens[1:]

    result = {}
    i = 0

    while i < len(tokens):
        token = tokens[i]

        if token.startswith("-"):
            key = normalize_key(token)

            values = []
            j = i + 1

            while j < len(tokens):
                next_token = tokens[j]

                if next_token.startswith("-") and not next_token.lstrip("-").isdigit():
                    break

                values.append(any_base_int(next_token))
                j += 1

            if not values:
                value = True
            elif len(values) == 1:
                value = values[0]
            else:
                value = values

            if key in result:
                if not isinstance(result[key], list):
                    result[key] = [result[key]]
                if isinstance(value, list):
                    result[key].extend(value)
                else:
                    result[key].append(value)
            else:
                result[key] = value

            i = j
        else:
            i += 1

    return result


def parse_partition_bin(
    partition_bin_path: str, namespace: str = "chip-factory"
) -> dict:
    """Parse an NVS partition binary and return ``namespace``'s keys as a flat dict.

    Numeric entries become ints, strings become str (with NVS NUL padding preserved),
    blobs become bytes. Wraps :class:`deps.nvs_parser.NVS_Partition` (vendored from
    esp-idf ``components/nvs_flash/nvs_partition_tool``).
    """
    from tests.deps.nvs_parser import NVS_Partition

    with open(partition_bin_path, "rb") as f:
        partition = NVS_Partition("partition", bytearray(f.read()))

    pages = sorted(
        (p for p in partition.pages if p.header["status"] in ("Active", "Full")),
        key=lambda p: p.header["page_index"],
    )

    # Pass 1: build ns_index → name map from namespace 0 entries
    ns_index = {}
    for page in pages:
        for e in page.entries:
            if e.state == "Written" and e.metadata["namespace"] == 0 and e.key:
                ns_index[e.data["value"]] = e.key
    target_idx = next((i for i, n in ns_index.items() if n == namespace), None)
    if target_idx is None:
        return {}

    # Pass 2: collect entries for the target namespace
    result: dict = {}
    blob_chunks: dict = {}  # key -> {chunk_idx: bytes}
    blob_indexes: dict = {}  # key -> blob_index entry data
    for page in pages:
        for e in page.entries:
            if (
                e.state != "Written"
                or e.metadata["namespace"] != target_idx
                or not e.key
            ):
                continue
            t = e.metadata["type"]
            if t.endswith("_t"):  # numeric (uint8_t..int64_t)
                result[e.key] = e.data["value"]
            elif t == "string":
                payload = b"".join(c.raw for c in e.children)[: e.data["size"]]
                result[e.key] = payload.decode("ascii")
            elif t == "blob":  # legacy single-blob (no chunking)
                payload = b"".join(c.raw for c in e.children)[: e.data["size"]]
                result[e.key] = bytes(payload)
            elif t == "blob_data":
                chunk = b"".join(c.raw for c in e.children)[: e.data["size"]]
                blob_chunks.setdefault(e.key, {})[e.metadata["chunk_index"]] = chunk
            elif t == "blob_index":
                blob_indexes[e.key] = e.data

    # Reassemble chunked blobs
    for key, idx in blob_indexes.items():
        chunks = blob_chunks.get(key, {})
        start, count = idx["chunk_start"], idx["chunk_count"]
        result[key] = bytes(b"".join(chunks.get(start + i, b"") for i in range(count)))

    return result


def _short(v):
    """Render a value for log lines: truncate long bytes/strings."""
    if isinstance(v, (bytes, bytearray)):
        return f"<{len(v)} bytes>"
    r = repr(v)
    return r if len(r) <= 80 else r[:77] + "..."


def _validate_common_arg(cmd_args, partition_data, ck, pk=None, transform=None):
    """Direct equality check; skipped when either side is absent."""
    pk = pk or ck
    exp, act = cmd_args.get(ck), partition_data.get(pk)
    if exp is None or act is None:
        return
    if transform is not None:
        exp = transform(exp)
    assert act == exp, f"{ck}: expected {exp!r}, got {act!r}"
    logger.info(f"  ✓ {ck} = {_short(act)}")


def _validate_string_arg(cmd_args, partition_data, ck, pk=None):
    """String equality check (NUL padding stripped from actual)."""
    pk = pk or ck
    exp, act = cmd_args.get(ck), partition_data.get(pk)
    if exp is None or act is None:
        return
    act_clean = act.rstrip("\x00").strip()
    assert act_clean == exp.strip(), f"{ck}: expected {exp!r}, got {act!r}"
    logger.info(f"  ✓ {ck} = {act_clean!r}")


def _validate_locales(cmd_args, partition_data):
    locales = cmd_args.get("locales")
    if locales is None:
        return
    sz = partition_data.get("locale-sz")
    if sz is None:
        return
    assert sz == len(locales), f"locale-sz: expected {len(locales)}, got {sz}"
    logger.info(f"  ✓ locale-sz = {sz}")
    for i, exp in enumerate(locales):
        act = partition_data.get(f"locale/{i:x}")
        if act is None:
            continue
        act_clean = act.rstrip("\x00").strip()
        assert act_clean == exp.strip(), f"locale/{i}: expected {exp!r}, got {act!r}"
        logger.info(f"  ✓ locale/{i} = {act_clean!r}")


def _validate_fixed_labels(cmd_args, partition_data):
    fixed_labels = cmd_args.get("fixed-labels")
    if fixed_labels is None:
        return
    for endpoint, labels in get_fixed_label_dict(fixed_labels).items():
        ep = int(endpoint)
        fl_sz = partition_data.get(f"fl-sz/{ep:x}")
        if fl_sz is None:
            continue
        assert fl_sz == len(labels), f"fl-sz/{ep}: expected {len(labels)}, got {fl_sz}"
        logger.info(f"  ✓ fl-sz/{ep} = {fl_sz}")
        for i, label in enumerate(labels):
            [(k, v)] = label.items()
            act_k = partition_data.get(f"fl-k/{ep:x}/{i:x}")
            act_v = partition_data.get(f"fl-v/{ep:x}/{i:x}")
            if act_k is not None:
                assert act_k.rstrip("\x00").strip() == k, (
                    f"fl-k/{ep}/{i}: expected {k!r}, got {act_k!r}"
                )
                logger.info(f"  ✓ fl-k/{ep}/{i} = {k!r}")
            if act_v is not None:
                assert act_v.rstrip("\x00").strip() == v, (
                    f"fl-v/{ep}/{i}: expected {v!r}, got {act_v!r}"
                )
                logger.info(f"  ✓ fl-v/{ep}/{i} = {v!r}")


def _validate_supported_modes(cmd_args, partition_data):
    supported_modes = cmd_args.get("supported-modes")
    if supported_modes is None:
        return
    for endpoint, modes in get_supported_modes_dict(supported_modes).items():
        ep = int(endpoint)
        sm_sz = partition_data.get(f"sm-sz/{ep:x}")
        if sm_sz is None:
            continue
        assert sm_sz == len(modes), f"sm-sz/{ep}: expected {len(modes)}, got {sm_sz}"
        logger.info(f"  ✓ sm-sz/{ep} = {sm_sz}")
        for i, mode in enumerate(modes):
            act_label = partition_data.get(f"sm-label/{ep:x}/{i:x}")
            act_mode = partition_data.get(f"sm-mode/{ep:x}/{i:x}")
            if act_label is not None:
                assert act_label.rstrip("\x00").strip() == mode["Label"], (
                    f"sm-label/{ep}/{i}: expected {mode['Label']!r}, got {act_label!r}"
                )
                logger.info(f"  ✓ sm-label/{ep}/{i} = {mode['Label']!r}")
            if act_mode is not None:
                assert act_mode == mode["Mode"], (
                    f"sm-mode/{ep}/{i}: expected {mode['Mode']}, got {act_mode}"
                )
                logger.info(f"  ✓ sm-mode/{ep}/{i} = {act_mode}")
            tags = mode["Semantic_Tag"]
            sm_st_sz = partition_data.get(f"sm-st-sz/{ep:x}/{i:x}")
            if not tags or sm_st_sz is None:
                continue
            assert sm_st_sz == len(tags), (
                f"sm-st-sz/{ep}/{i}: expected {len(tags)}, got {sm_st_sz}"
            )
            for j, tag in enumerate(tags):
                act_v = partition_data.get(f"st-v/{ep:x}/{i:x}/{j:x}")
                act_mfg = partition_data.get(f"st-mfg/{ep:x}/{i:x}/{j:x}")
                if act_v is not None:
                    assert act_v == tag["value"], (
                        f"st-v/{ep}/{i}/{j}: expected {tag['value']}, got {act_v}"
                    )
                    logger.info(f"  ✓ st-v/{ep}/{i}/{j} = {act_v}")
                if act_mfg is not None:
                    assert act_mfg == tag["mfgCode"], (
                        f"st-mfg/{ep}/{i}/{j}: expected {tag['mfgCode']}, got {act_mfg}"
                    )
                    logger.info(f"  ✓ st-mfg/{ep}/{i}/{j} = {act_mfg}")


def validate_single_partition(cmd_args: dict, partition_data: dict):
    """Validate that the parsed partition matches the cmd-line args.

    Each entry below is ``(cmd_key, partition_key)``. They differ where the CLI
    flag and the NVS key drift (e.g. ``--hw-ver`` is stored as ``hardware-ver``).
    """
    logger.info("Validating partition fields:")
    COMMON_ARGS = [
        ("vendor-id", "vendor-id"),
        ("product-id", "product-id"),
        ("hw-ver", "hardware-ver"),
        ("discriminator", "discriminator"),
        ("iteration-count", "iteration-count"),
    ]
    STRING_ARGS = [
        ("vendor-name", "vendor-name"),
        ("product-name", "product-name"),
        ("hw-ver-str", "hw-ver-str"),
        ("serial-num", "serial-num"),
        ("mfg-date", "mfg-date"),
        ("product-label", "product-label"),
        ("product-url", "product-url"),
        ("part-number", "part-number"),
        # spake2p inputs land in NVS verbatim (base64 strings) when the user
        # supplies them; otherwise the tool generates them and the cmd-side is
        # absent, which makes the equality check a no-op via the None guard.
        ("salt", "salt"),
        ("verifier", "verifier"),
    ]
    TRANSFORMED_ARGS = [
        ("product-finish", "product-finish", lambda v: ProductFinish[v].value),
        ("product-color", "product-color", lambda v: ProductColor[v].value),
        ("calendar-types", "cal-types", calendar_types_to_uint32),
        ("rd-id-uid", "rd-id-uid", bytes.fromhex),
        ("cert-dclrn", "cert-dclrn", lambda p: Path(p).read_bytes()),
    ]

    for ck, pk in COMMON_ARGS:
        _validate_common_arg(cmd_args, partition_data, ck, pk=pk)

    for ck, pk in STRING_ARGS:
        _validate_string_arg(cmd_args, partition_data, ck, pk=pk)

    for ck, pk, transform in TRANSFORMED_ARGS:
        _validate_common_arg(cmd_args, partition_data, ck, pk=pk, transform=transform)

    # External cert/key bytes (skipped when DAC routed to secure_cert)
    if not cmd_args.get("dac-in-secure-cert"):
        for arg in ("dac-cert", "dac-key", "dac-pub-key", "pai-cert"):
            _validate_common_arg(cmd_args, partition_data, arg)

    # Flag-driven presence/absence assertions
    if cmd_args.get("enable-rotating-device-id"):
        assert partition_data.get("rd-id-uid") is not None, (
            "rd-id-uid missing while enable-rotating-device-id is set"
        )
        logger.info("  ✓ rd-id-uid present (enable-rotating-device-id)")
    if cmd_args.get("enable-dynamic-passcode"):
        assert partition_data.get("verifier") is None, (
            "verifier should be absent when enable-dynamic-passcode is set"
        )
        logger.info("  ✓ verifier absent (enable-dynamic-passcode)")

    # Structured (per-endpoint) fields
    _validate_locales(cmd_args, partition_data)
    _validate_fixed_labels(cmd_args, partition_data)
    _validate_supported_modes(cmd_args, partition_data)

    logger.info("Partition validation OK")
