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
