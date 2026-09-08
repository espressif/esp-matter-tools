# [1.0.25] - (8-September-2026)

* `--discovery-mode` now accepts the discovery capability bits added in Matter 1.6:
  `8` (Wi-Fi Public Action Frame), `16` (NFC) and `32` (Thread), in addition to `2` (BLE)
  and `4` (On-Network). Bits may be combined; at least one capability bit must be set
  (`0` is rejected) and reserved bits (0 and 6-7) must be 0. Previously only `2`, `4`
  and `6` were accepted.

# [1.0.24] - (9-June-2026)

* Added `--mqtt-host` option to specify the MQTT broker hostname for RainMaker credentials.
  The value is stored in the `rmaker_creds` NVS namespace as `mqtt_host`.

# [1.0.23] - (30-April-2026)

### CLI migration from argparse to Click

* The CLI is now decoupled from core mfg-tool logic and implemented using [Click](https://click.palletsprojects.com/) instead of argparse.
  Existing command-line invocations are compatible.

* **[NOTE]** `--discovery-mode` now strictly validates input to the three values defined by the Matter spec:
  `2` (BLE), `4` (On-Network), `6` (BLE + On-Network). Previously any integer was accepted.

##### Edits
- The module invocation path has changed from `python3 -m sources.mfg_tool` to `python3 -m sources.cli`.
  If you invoke the tool programmatically, update your invocation accordingly.

# [1.0.22] - (17-February-2026)
* Removed pkg_resources dependency

# [1.0.20] - (12-January-2026)

* Added support for specifying custom SPAKE2+ parameters:
    * `--salt`: Specify the salt for SPAKE2+ verifier generation.
    * `--verifier`: Specify the SPAKE2+ verifier.
    * `--iteration-count`: Specify the iteration count for SPAKE2+ verifier generation.

# [1.0.18] - (17-November-2025)

* ci: Added Support for Python versions 3.8, 3.9, 3.10, 3.11, 3.12, and 3.13.
- dependencies: Updated esp-secure-cert-tool to v2.3.6.

# [1.0.17] - (15-October-2025)

* Added debug log level and made the output less chatty.

# [1.0.16] - (1-October-2025)

* Support to add the Matter unique data in the esp-secure-cert partition.
* Newly added options:
    * `--commissionable-data-in-secure-cert`
    * `--rd-id-uid-in-secure-cert`

With this change, commissionable-data: discriminator, iteration-count, salt, verifier, and the unique identifier for
rotating device identifier can be stored in the esp-secure-cert partition.

# [1.0.15] - (17-September-2025)

* Downgrade cryptography to v44.x to align with esp-idf dependency.

# [1.0.14] - (15-September-2025)

* Fix the deprecated warnings from datetime module.
* Bump the cryptography version to 45.0.1 to fix the fancy Python version parsing.
* Update the dependency, mfg-gen, which now supports Python 3.12.

# [1.0.8] - (17-March-2025)

* Added `--no-bin` option to skip generating factory partition binary.
* Added `--log-level` option to limit the verbosity of logging.
* Added `--outdir` option to store the artefacts at different location.

# [1.0.7] - (28-February-2025)
### Breaking Changes

Change in `--discovery-mode` input argument.

Earlier `--discovery-mode` argument was only supporting one transport. Since there can be more than one networking technologies this options is updated to support more than one transport.

Users can specify values between 0-7 to enable different discovery modes. The default value is now set to 2 (BLE).

Updated Values:
- 2 → BLE (Default)
- 4 → On-Network
- 6 → BLE + On-Network
