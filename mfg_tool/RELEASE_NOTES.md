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
