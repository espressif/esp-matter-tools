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

import os
import click
from click_option_group import optgroup, MutuallyExclusiveOptionGroup, GroupedOption
from types import SimpleNamespace
from sources.mfg_tool import main_internal, __LOG_LEVELS__
from sources.utils import CalendarTypes, ProductFinish, ProductColor

product_finish_choices = [finish.name for finish in ProductFinish]
product_color_choices = [color.name for color in ProductColor]
calendar_type_choices = [ct.name for ct in CalendarTypes]


def any_base_int(ctx, param, value):
    if isinstance(value, str):
        return int(value, 0)
    return value


def int_choice(choices):
    """Click callback that converts to int then validates against choices.
    Matches argparse's behavior where type conversion happens before choices check."""

    def callback(ctx, param, value):
        v = any_base_int(ctx, param, value)
        if v not in choices:
            raise click.BadParameter(
                "invalid choice: {}. (choose from {})".format(
                    v, ", ".join(str(c) for c in choices)
                )
            )
        return v

    return callback


class MultiValueOption(GroupedOption):
    """
    Click option that accepts multiple values separated by spaces.

    NOTE:
    This method relies on Click's private internals:
    - parser._long_opt
    - parser._short_opt
    - parser_obj.process

    These are not part of Click's public API and may break on upgrade.
    If upgrading Click, this behavior must be re-tested.

    This mimics argparse's `nargs='+'` behavior for options, which Click
    does not support natively. The option consumes values until the next
    CLI option is encountered.
    """

    def add_to_parser(self, parser, ctx):
        def parser_process(value, state):
            values = [value]

            # consume values until next option
            while state.rargs and not state.rargs[0].startswith("-"):
                values.append(state.rargs.pop(0))

            self._previous_parser_process(values, state)

        retval = super().add_to_parser(parser, ctx)

        for opt in self.opts:
            parser_obj = parser._long_opt.get(opt) or parser._short_opt.get(opt)
            if parser_obj:
                self._previous_parser_process = parser_obj.process
                parser_obj.process = parser_process

        return retval

    def type_cast_value(self, ctx, value) -> list:
        if value is None:
            return None
        values = list(value) if isinstance(value, (list, tuple)) else [value]
        if self.type and self.type != click.STRING:
            return [self.type.convert(v, self, ctx) for v in values]
        return values


@click.command(
    help="Manufacturing partition generator tool",
    context_settings=dict(help_option_names=["-h", "--help"]),
)
@optgroup.group("\nGeneral options")
@optgroup.option(
    "-n",
    "--count",
    type=str,
    callback=any_base_int,
    default=1,
    help="The number of manufacturing partition binaries to generate. Default is 1. "
    "If --csv and --mcsv are present, the number of lines in the mcsv file is used.",
)
@optgroup.option(
    "--target",
    default="esp32",
    help="The platform type of device. eg: one of esp32, esp32c3, etc.",
)
@optgroup.option(
    "-s",
    "--size",
    type=str,
    callback=any_base_int,
    default=0x6000,
    help="The size of manufacturing partition binaries to generate. Default is 0x6000.",
)
@optgroup.option(
    "-e",
    "--encrypt",
    is_flag=True,
    help="Encrypt the factory partition NVS binary",
)
@optgroup.option(
    "--log-level",
    default="info",
    type=click.Choice(list(__LOG_LEVELS__.keys())),
    show_default=True,
    help="Set the log level",
)
@optgroup.option(
    "--outdir",
    default=os.path.join(os.getcwd(), "out"),
    show_default=True,
    help="The output directory for the generated files",
)
@optgroup.option(
    "--no-bin",
    "generate_bin",
    flag_value=False,
    default=True,
    help="Do not generate the factory partition binary",
)
@optgroup.option(
    "--no-secure-cert-bin",
    is_flag=True,
    help="If provided, secure cert partition binary will not be generated. "
    "All the options related to secure cert partition will be ignored",
)
@optgroup.group("\nCommissioning options")
@optgroup.option(
    "--passcode",
    callback=any_base_int,
    help="The passcode for pairing. Randomly generated if not specified.",
)
@optgroup.option(
    "--discriminator",
    callback=any_base_int,
    help="The discriminator for pairing. Randomly generated if not specified.",
)
@optgroup.option(
    "-cf",
    "--commissioning-flow",
    default=0,
    type=str,
    callback=int_choice([0, 1, 2]),
    help="Device commissioning flow, 0:Standard, 1:User-Intent, 2:Custom. Default is Standard.",
)
@optgroup.option(
    "-dm",
    "--discovery-mode",
    default=2,
    type=str,
    callback=int_choice([2, 4, 6]),
    help="The discovery mode for commissionable device discovery. "
    "2: BLE, 4: On-network, 6: BLE + On-network. Default is BLE.",
)
@optgroup.option(
    "--enable-dynamic-passcode",
    is_flag=True,
    help="Enable dynamic passcode. If enabling this option, the generated binaries will "
    "not include the spake2p verifier. so this option should work with a custom "
    "CommissionableDataProvider which can generate random passcode and corresponding verifier",
)
@optgroup.option(
    "--salt",
    type=str,
    help="The salt for SPAKE2+ verifier generation, provided as base64 encoded string. "
    "Must be used together with --verifier and --passcode.",
)
@optgroup.option(
    "--verifier",
    type=str,
    help="The SPAKE2+ verifier, provided as base64 encoded string. "
    "Must be used together with --salt and --passcode.",
)
@optgroup.option(
    "--iteration-count",
    type=str,
    callback=any_base_int,
    default=10000,
    help="The iteration count for SPAKE2+ verifier generation. "
    "Valid range: 1000 to 100000. Default is 10000.",
)
@optgroup.option(
    "--commissionable-data-in-secure-cert",
    is_flag=True,
    help="Store commissionable data in secure cert partition. "
    "By default, commissionable data is stored in nvs factory partition. "
    "This option is only valid when --no-secure-cert-bin is not provided.",
)
@optgroup.group("\nDevice attestation credential options")
@optgroup.option(
    "--dac-in-secure-cert",
    is_flag=True,
    help="Store DAC in secure cert partition. By default, DAC is stored in nvs factory partition.",
)
@optgroup.option(
    "-lt",
    "--lifetime",
    type=str,
    default=36500,
    callback=any_base_int,
    help="Lifetime of the generated certificate. Default is 100 years if not specified, "
    "this indicate that certificate does not have well defined expiration date.",
)
@optgroup.option(
    "-vf",
    "--valid-from",
    help="The start date for the certificate validity period in format <YYYY>-<MM>-<DD> [ <HH>:<MM>:<SS> ]. Default is current date.",
)
@optgroup.option(
    "-cn",
    "--cn-prefix",
    default="ESP32",
    help="The common name prefix of the subject of the PAI certificate.",
)
@optgroup.option("-c", "--cert", help="The input certificate file in PEM format.")
@optgroup.option("-k", "--key", help="The input key file in PEM format.")
@optgroup.option(
    "-cd", "--cert-dclrn", help="The certificate declaration file in DER format."
)
@optgroup.option("--dac-cert", help="The input DAC certificate file in PEM format.")
@optgroup.option("--dac-key", help="The input DAC private key file in PEM format.")
@optgroup.option(
    "-ds",
    "--ds-peripheral",
    is_flag=True,
    help="Use DS Peripheral in generating secure cert partition.",
)
@optgroup.option(
    "--efuse-key-id",
    type=click.IntRange(min=-1, max=5),
    default=-1,
    help="Provide the efuse key_id which contains/will contain HMAC_KEY, default is -1",
)
@optgroup.option("--port", help="UART com port to which the ESP device is connected")
@optgroup.option(
    "--pwd",
    "--password",
    "priv_key_pass",
    help="The password associated with the private key",
)
@optgroup.group("\nInput certificate type", cls=MutuallyExclusiveOptionGroup)
@optgroup.option(
    "--paa", is_flag=True, help="Use input certificate as PAA certificate."
)
@optgroup.option(
    "--pai", is_flag=True, help="Use input certificate as PAI certificate."
)
@optgroup.group("\nDevice instance information options")
@optgroup.option(
    "-v", "--vendor-id", required=True, callback=any_base_int, help="Vendor id"
)
@optgroup.option("--vendor-name", help="Vendor name")
@optgroup.option(
    "-p", "--product-id", required=True, callback=any_base_int, help="Product id"
)
@optgroup.option("--product-name", help="Product name")
@optgroup.option("--hw-ver", callback=any_base_int, help="Hardware version")
@optgroup.option("--hw-ver-str", help="Hardware version string")
@optgroup.option("--mfg-date", help="Manufacturing date in format YYYY-MM-DD")
@optgroup.option("--serial-num", help="Serial number")
@optgroup.option(
    "--enable-rotating-device-id",
    is_flag=True,
    help="Enable Rotating device id in the generated binaries",
)
@optgroup.option(
    "--rd-id-uid",
    help="128-bit unique identifier for generating rotating device identifier, provide 32-byte hex string",
)
@optgroup.option(
    "--product-finish",
    type=click.Choice(product_finish_choices),
    help="Product finishes choices for product appearance",
)
@optgroup.option(
    "--rd-id-uid-in-secure-cert",
    is_flag=True,
    help="Enable Rotating device id in the secure cert partition.",
)
@optgroup.option(
    "--product-color",
    type=click.Choice(product_color_choices),
    help="Product colors choices for product appearance",
)
@optgroup.option("--part-number", help="human readable product number")
@optgroup.group("\nDevice instance options")
@optgroup.option(
    "--calendar-types",
    cls=MultiValueOption,
    type=click.Choice(calendar_type_choices),
    help="List of supported calendar types. Space-separated, e.g. --calendar-types Gregorian Hebrew",
)
@optgroup.option(
    "--locales",
    cls=MultiValueOption,
    help="List of supported locales, Language Tag as defined by BCP47, eg. en-US en-GB",
)
@optgroup.option(
    "--fixed-labels",
    cls=MultiValueOption,
    help='List of fixed labels, eg: "0/orientation/up"',
)
@optgroup.option(
    "--supported-modes", cls=MultiValueOption, help="List of supported modes."
)
@optgroup.group("\nFew more Basic clusters options")
@optgroup.option("--product-label", help="Product label")
@optgroup.option("--product-url", help="Product URL")
@optgroup.group("\nExtra information options using csv files")
@optgroup.option(
    "--csv", help="CSV file containing the partition schema for extra options."
)
@optgroup.option(
    "--mcsv",
    help="Master CSV file containing optional/extra values specified by the user.",
)
def main(**kwargs):
    main_internal(SimpleNamespace(**kwargs))


if __name__ == "__main__":
    main()
