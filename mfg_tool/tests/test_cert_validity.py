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
Unit tests for certificate validity handling in ``validate_certificates``.

Regression coverage for the case where a user SUPPLIES their own DAC/PAI whose
validity window (here 2020 -> 2040) is shorter than the default ``--lifetime``
(100 years). The generation lifetime must NOT be applied to user-provided certs,
while it must still be enforced for certs the tool generates.
"""

from types import SimpleNamespace

import pytest

from sources.cert_utils import validate_certificates

# Real Espressif test credentials, VID 0x131B / PID 0x5050, valid 2020 -> 2040
# (shorter than the default 100-year lifetime).
PAI_CERT = "test_data/Chip-Test-PAI-131B-5050-Cert.pem"
DAC_CERT = "test_data/Chip-Test-DAC-131B-5050-Cert.pem"
DAC_KEY = "test_data/Chip-Test-DAC-131B-5050-Key.pem"

VID = 0x131B
PID = 0x5050


def _args(**overrides):
    base = dict(
        pai=True,
        paa=False,
        cert=PAI_CERT,
        key=None,
        dac_cert=None,
        dac_key=None,
        vendor_id=VID,
        product_id=PID,
        valid_from=None,
        lifetime=36500,  # default: 100 years
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class TestCertificateValidity:
    def test_supplied_dac_pai_shorter_than_lifetime_accepted(self):
        """User-supplied DAC+PAI valid until 2040 must be accepted even though
        their validity is shorter than the default 100-year --lifetime."""
        args = _args(dac_cert=DAC_CERT, dac_key=DAC_KEY)
        # Should not sys.exit(); returns normally.
        validate_certificates(args)

    def test_generate_path_still_enforces_lifetime(self):
        """When the tool GENERATES the DAC (no --dac-cert), the signing PAI must
        cover the generated cert's [now, now + lifetime] window. A PAI expiring
        in 2040 cannot cover a 100-year lifetime, so validation must fail."""
        args = _args(dac_cert=None, dac_key=None)
        with pytest.raises(SystemExit):
            validate_certificates(args)
