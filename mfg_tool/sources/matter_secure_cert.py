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
Helps generate the secure cert partition for Matter

Below is the data that may be stored in secure cert partition:
- Attestation data:
    - Device Attestation Certificate
    - Private Key corresponding to the Device Attestation Certificate
    - Product Attestation Intermediate Certificate
- Commissionable Data:
    - Discriminator
    - Iteration Count
    - Salt
    - Verifier
- Device Instance Information:
    - Unique Id for Rotating Device ID
"""

import sys
import io
import os
import enum
import click
import base64
import logging
import contextlib
from typing import Optional
from dataclasses import dataclass
from esp_secure_cert.tlv_format_construct import EspSecureCert
from esp_secure_cert.tlv_format import tlv_type_t

# Temporary workaround until esp-secure-cert-tool defines Matter-specific TLV values in tlv_format.py
MATTER_TLV_TYPE_1 = 201


@dataclass
class MatterSecureCert:
    dac_cert: bytes
    dac_private_key: bytes
    pai_cert: bytes
    ds_peripheral: bool = False
    efuse_key_id: Optional[int] = None
    discriminator: Optional[int] = None
    iteration_count: Optional[int] = None
    salt: Optional[str] = None
    verifier: Optional[str] = None
    rd_id_uid: Optional[str] = None

    def __post_init__(self):
        if not self.dac_cert or not self.dac_private_key or not self.pai_cert:
            raise ValueError("DAC cert, DAC private key, and PAI cert are required")

        if (self.ds_peripheral is False) != (self.efuse_key_id is None):
            raise ValueError("either both or none of ds-peripheral and efuse-key-id must be provided")

        # check if all the optional arguments are provided together
        required_args = [self.discriminator, self.iteration_count, self.salt, self.verifier, self.rd_id_uid]
        len_required_args = len(required_args)
        count_of_provided_args = sum(1 for v in required_args if v is not None)
        if count_of_provided_args != 0 and count_of_provided_args != len_required_args:
            raise ValueError("discriminator, iteration_count, salt, verifier, and rd_id_uid must be provided together")

        # set the flag to add optional entries
        self.add_optional_entries = count_of_provided_args == len_required_args

    class MatterTLVSubType(enum.IntEnum):
        DISCRIMINATOR = 0
        SPAKE2P_VERIFIER = 1
        SPAKE2P_SALT = 2
        SPAKE2P_ITERATION_COUNT = 3
        RD_ID_UID = 4
        # use 128 and onwards for random tlv subtypes
        RANDOM1 = 128
        RANDOM2 = 129

    @staticmethod
    def get_cert_entry_as_json(cert: bytes, is_pai: bool = False) -> dict:
        return {
            "tlv_type": tlv_type_t.ESP_SECURE_CERT_CA_CERT_TLV if is_pai else tlv_type_t.ESP_SECURE_CERT_DEV_CERT_TLV,
            "tlv_subtype": 0,
            "data_value": base64.b64encode(cert).decode("utf-8"),
            "data_type": "base64",
        }

    @staticmethod
    def get_private_key_entry_as_json(private_key: bytes, ds_peripheral: bool = False, efuse_key_id: Optional[int] = None) -> dict:
        entry = {
            "tlv_type": tlv_type_t.ESP_SECURE_CERT_PRIV_KEY_TLV,
            "tlv_subtype": 0,
            "data_value": base64.b64encode(private_key).decode("utf-8"),
            "data_type": "base64",
            "priv_key_type": "ecdsa_peripheral" if ds_peripheral else "plaintext",
            "ds_enabled": ds_peripheral,
            "key_size": 256,
            "efuse_key_file": None,  # should be auto-generated in lower layer
            "efuse_key": None,
            "efuse_id": efuse_key_id if efuse_key_id is not None else None,
            "algorithm": "ECDSA",
        }
        if efuse_key_id is not None:
            entry["efuse_key_id"] = efuse_key_id
        return entry

    @staticmethod
    def get_discriminator_entry_as_json(discriminator: int) -> dict:
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": MatterSecureCert.MatterTLVSubType.DISCRIMINATOR,
            "data_value": base64.b64encode(discriminator.to_bytes(2, "little")).decode("utf-8"),
            "data_type": "base64",
        }

    @staticmethod
    def get_spake2p_verifier_entry_as_json(verifier_b64: str) -> dict:
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": MatterSecureCert.MatterTLVSubType.SPAKE2P_VERIFIER,
            "data_value": verifier_b64,
            "data_type": "base64",
        }

    @staticmethod
    def get_spake2p_salt_entry_as_json(salt_b64: str) -> dict:
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": MatterSecureCert.MatterTLVSubType.SPAKE2P_SALT,
            "data_value": salt_b64,
            "data_type": "base64",
        }

    @staticmethod
    def get_spake2p_iteration_count_entry_as_json(iteration_count: int) -> dict:
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": MatterSecureCert.MatterTLVSubType.SPAKE2P_ITERATION_COUNT,
            "data_value": base64.b64encode(iteration_count.to_bytes(4, "little")).decode("utf-8"),
            "data_type": "base64",
        }

    @staticmethod
    def get_rd_id_uid_entry_as_json(rd_id_uid_b64: str) -> dict:
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": MatterSecureCert.MatterTLVSubType.RD_ID_UID,
            "data_value": rd_id_uid_b64,
            "data_type": "base64",
        }

    @staticmethod
    def get_random_entry_as_json(tlv_subtype: int) -> dict:
        random_len = 32
        return {
            "tlv_type": MATTER_TLV_TYPE_1,
            "tlv_subtype": tlv_subtype,
            "data_value": base64.b64encode(os.urandom(random_len)).decode("utf-8"),
            "data_type": "base64",
        }

    @staticmethod
    def get_random1_entry_as_json() -> dict:
        return MatterSecureCert.get_random_entry_as_json(MatterSecureCert.MatterTLVSubType.RANDOM1)

    @staticmethod
    def get_random2_entry_as_json() -> dict:
        return MatterSecureCert.get_random_entry_as_json(MatterSecureCert.MatterTLVSubType.RANDOM2)

    def generate_partition(self, port: Optional[int] = None) -> Optional[str]:
        """
        Generate the secure cert partition for Matter
        """

        secure_cert = EspSecureCert()
        secure_cert.add_entry(MatterSecureCert.get_cert_entry_as_json(self.dac_cert, is_pai=False))
        secure_cert.add_entry(MatterSecureCert.get_cert_entry_as_json(self.pai_cert, is_pai=True))
        secure_cert.add_entry(
            MatterSecureCert.get_private_key_entry_as_json(self.dac_private_key, self.ds_peripheral, self.efuse_key_id)
        )

        if self.add_optional_entries:
            logging.debug("Adding all optional entries")
            secure_cert.add_entry(MatterSecureCert.get_discriminator_entry_as_json(self.discriminator))
            secure_cert.add_entry(MatterSecureCert.get_spake2p_verifier_entry_as_json(self.verifier))
            secure_cert.add_entry(MatterSecureCert.get_spake2p_salt_entry_as_json(self.salt))
            secure_cert.add_entry(MatterSecureCert.get_spake2p_iteration_count_entry_as_json(self.iteration_count))
            secure_cert.add_entry(MatterSecureCert.get_rd_id_uid_entry_as_json(self.rd_id_uid))
            # add random entries only when we are adding optional entries
            secure_cert.add_entry(MatterSecureCert.get_random1_entry_as_json())
            secure_cert.add_entry(MatterSecureCert.get_random2_entry_as_json())

        # at the moment we only support esp32h2 for ds-peripheral
        target_chip = "esp32h2" if self.ds_peripheral else None

        output_buf = io.StringIO()
        output_stream = sys.stderr if logging.getLogger().level <= logging.DEBUG else output_buf
        try:
            with contextlib.redirect_stdout(output_stream), contextlib.redirect_stderr(output_stream):
                return secure_cert.generate_esp_secure_cert(target_chip, port)
        except SystemExit as e:
            logging.error(output_buf.getvalue())
            raise RuntimeError(f"ERROR: esp-secure-cert-tool exited with error:{e.code}")


# here onwards, cli functionality to test this script in a standalone manner
# TODO: Once the tlv_parse.py lands, we can use that to parse the secure cert partition
# and write some unit tests for the same


class AnyBaseInt(click.ParamType):
    name = "int (any base)"

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail(f"{value} is not a valid integer", param, ctx)


any_base_int = AnyBaseInt()


@click.command()
@click.option("--dac", type=click.File("rb"), required=True, help="Path to the DAC certificate")
@click.option("--dac-key", type=click.File("rb"), required=True, help="Path to the DAC private key")
@click.option("--pai", type=click.File("rb"), required=True, help="Path to the PAI certificate")
@click.option("--ds", is_flag=True, help="Whether the DAC private key is for DS peripheral")
@click.option("--efuse-key-id", type=int, help="EFUSE key id")
@click.option("--port", help="Port to flash the secure cert partition")
@click.option("--discriminator", type=any_base_int, help="Discriminator")
@click.option("--iterations", type=any_base_int, help="Iteration count")
@click.option("--salt", help="spake2p salt encoded as base64 string")
@click.option("--verifier", help="spake2p verifier encoded as base64 string")
@click.option("--rd-id-uid", help="unique id for rotating device id encoded as base64 string")
def main(dac, dac_key, pai, ds, efuse_key_id, port, discriminator, iterations, salt, verifier, rd_id_uid):
    dac = dac.read()
    dac_key = dac_key.read()
    pai = pai.read()
    obj = MatterSecureCert(dac, dac_key, pai, ds, efuse_key_id, discriminator, iterations, salt, verifier, rd_id_uid)
    secure_cert_bin_name = obj.generate_partition(port)
    print(f"Secure cert binary generated: {secure_cert_bin_name}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
