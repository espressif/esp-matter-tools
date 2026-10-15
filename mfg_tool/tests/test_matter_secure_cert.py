#!/usr/bin/env python3

# Copyright 2026 Espressif Systems (Shanghai) PTE LTD
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
Unit tests for MatterSecureCert.

Generates a secure cert partition and parses the binary back with
esp_secure_cert.tlv_parser to verify every TLV entry round-trips.
"""

import os
import base64
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from sources.matter_secure_cert import MatterSecureCert, MATTER_TLV_TYPE_1
from esp_secure_cert.tlv_format import tlv_type_t
from esp_secure_cert.tlv_parser import (
    ESP_SECURE_CERT_TLV_MAGIC,
    get_padding_length,
    get_tlv_total_length,
    parse_tlv_footer,
    parse_tlv_header,
    verify_tlv_integrity,
)

TEST_DATA = Path(__file__).resolve().parent.parent / "test_data"

DAC_CERT_PEM = TEST_DATA / "Chip-Test-DAC-131B-5050-Cert.pem"
DAC_KEY_PEM = TEST_DATA / "Chip-Test-DAC-131B-5050-Key.pem"
PAI_CERT_PEM = TEST_DATA / "Chip-Test-PAI-131B-5050-Cert.pem"

DISCRIMINATOR = 0xABC
ITERATION_COUNT = 10000
SALT_B64 = base64.b64encode(os.urandom(32)).decode("utf-8")
VERIFIER_B64 = base64.b64encode(os.urandom(97)).decode("utf-8")
RD_ID_UID_B64 = base64.b64encode(os.urandom(16)).decode("utf-8")


def _cert_der(pem_path):
    with open(pem_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read()).public_bytes(
            serialization.Encoding.DER
        )


def _key_der(pem_path):
    with open(pem_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


DAC_CERT_DER = _cert_der(DAC_CERT_PEM)
DAC_KEY_DER = _key_der(DAC_KEY_PEM)
PAI_CERT_DER = _cert_der(PAI_CERT_PEM)


def parse_partition(bin_path):
    """Parse a secure cert partition into {(type, subtype): (data, crc_ok)}."""
    with open(bin_path, "rb") as f:
        data = f.read()

    entries = {}
    offset = 0
    while offset < len(data):
        header, header_size = parse_tlv_header(data, offset)
        if header["magic"] != ESP_SECURE_CERT_TLV_MAGIC:
            break
        body = data[offset + header_size : offset + header_size + header["length"]]
        footer_offset = (
            offset
            + header_size
            + header["length"]
            + get_padding_length(header["length"])
        )
        footer, _ = parse_tlv_footer(data, footer_offset)
        crc_ok, _ = verify_tlv_integrity(header, data[offset:], footer)
        entries[(header["type"], header["subtype"])] = (body, crc_ok)
        offset += get_tlv_total_length(header)
    return entries


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    # generate_partition() writes to ./esp_secure_cert_data/ in the cwd
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _generate_and_parse(msc):
    bin_path = msc.generate_partition()
    assert bin_path and os.path.exists(bin_path)
    return parse_partition(bin_path)


class TestAttestationPartition:
    def test_attestation_entries_round_trip(self, workdir):
        msc = MatterSecureCert(
            dac_cert=DAC_CERT_DER, dac_private_key=DAC_KEY_DER, pai_cert=PAI_CERT_DER
        )
        entries = _generate_and_parse(msc)

        assert len(entries) == 3
        assert all(crc_ok for _, crc_ok in entries.values())
        assert entries[(tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV, 0)][0] == DAC_CERT_DER
        assert entries[(tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV, 0)][0] == PAI_CERT_DER
        assert entries[(tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV, 0)][0] == DAC_KEY_DER

    def test_no_optional_entries_without_commissionable_data(self, workdir):
        msc = MatterSecureCert(
            dac_cert=DAC_CERT_DER, dac_private_key=DAC_KEY_DER, pai_cert=PAI_CERT_DER
        )
        entries = _generate_and_parse(msc)

        matter_entries = [k for k in entries if k[0] == MATTER_TLV_TYPE_1]
        assert matter_entries == []


class TestCommissionableDataPartition:
    def test_optional_entries_round_trip(self, workdir):
        msc = MatterSecureCert(
            dac_cert=DAC_CERT_DER,
            dac_private_key=DAC_KEY_DER,
            pai_cert=PAI_CERT_DER,
            discriminator=DISCRIMINATOR,
            iteration_count=ITERATION_COUNT,
            salt=SALT_B64,
            verifier=VERIFIER_B64,
            rd_id_uid=RD_ID_UID_B64,
        )
        entries = _generate_and_parse(msc)

        # 3 attestation + 5 commissionable + 2 random
        assert len(entries) == 10
        assert all(crc_ok for _, crc_ok in entries.values())

        subtype = MatterSecureCert.MatterTLVSubType
        disc_body = entries[(MATTER_TLV_TYPE_1, subtype.DISCRIMINATOR)][0]
        assert int.from_bytes(disc_body, "little") == DISCRIMINATOR

        iter_body = entries[(MATTER_TLV_TYPE_1, subtype.SPAKE2P_ITERATION_COUNT)][0]
        assert int.from_bytes(iter_body, "little") == ITERATION_COUNT

        assert entries[(MATTER_TLV_TYPE_1, subtype.SPAKE2P_SALT)][
            0
        ] == base64.b64decode(SALT_B64)
        assert entries[(MATTER_TLV_TYPE_1, subtype.SPAKE2P_VERIFIER)][
            0
        ] == base64.b64decode(VERIFIER_B64)
        assert entries[(MATTER_TLV_TYPE_1, subtype.RD_ID_UID)][0] == base64.b64decode(
            RD_ID_UID_B64
        )

        assert len(entries[(MATTER_TLV_TYPE_1, subtype.RANDOM1)][0]) == 32
        assert len(entries[(MATTER_TLV_TYPE_1, subtype.RANDOM2)][0]) == 32


class TestValidation:
    def test_missing_attestation_data_raises(self):
        with pytest.raises(ValueError, match="required"):
            MatterSecureCert(
                dac_cert=b"", dac_private_key=DAC_KEY_DER, pai_cert=PAI_CERT_DER
            )
        with pytest.raises(ValueError, match="required"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER, dac_private_key=b"", pai_cert=PAI_CERT_DER
            )
        with pytest.raises(ValueError, match="required"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER, dac_private_key=DAC_KEY_DER, pai_cert=b""
            )

    def test_partial_commissionable_data_raises(self):
        with pytest.raises(ValueError, match="provided together"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER,
                dac_private_key=DAC_KEY_DER,
                pai_cert=PAI_CERT_DER,
                discriminator=DISCRIMINATOR,
                salt=SALT_B64,
            )

    def test_ds_peripheral_without_efuse_key_id_raises(self):
        with pytest.raises(ValueError, match="ds-peripheral and efuse-key-id"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER,
                dac_private_key=DAC_KEY_DER,
                pai_cert=PAI_CERT_DER,
                ds_peripheral=True,
                target="esp32h2",
            )

    def test_efuse_key_id_without_ds_peripheral_raises(self):
        with pytest.raises(ValueError, match="ds-peripheral and efuse-key-id"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER,
                dac_private_key=DAC_KEY_DER,
                pai_cert=PAI_CERT_DER,
                efuse_key_id=0,
            )

    def test_ds_peripheral_without_target_raises(self):
        with pytest.raises(ValueError, match="target is required"):
            MatterSecureCert(
                dac_cert=DAC_CERT_DER,
                dac_private_key=DAC_KEY_DER,
                pai_cert=PAI_CERT_DER,
                ds_peripheral=True,
                efuse_key_id=0,
            )
