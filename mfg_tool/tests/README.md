# esp-matter-mfg-tool Tests

Tests for `esp-matter-mfg-tool`. The current suite drives the installed CLI as a
subprocess and validates the generated factory partition and certificate
artifacts; additional test types may be added alongside it.

## Running

From the `mfg_tool/` directory:

```bash
pip install -r requirements.txt -r requirements-test.txt
pip install -e .
pytest tests/
```

`chip-cert` must be on `PATH` for certificate-chain validation; the test suite
also prepends `test_data/` to `PATH` so a local binary placed there is picked up
automatically.

## Integration Tests

`test_integration.py` is a parametrized pytest class that runs every case in
`../test_data/test_integration_inputs.json`. Each entry supplies a command,
expected output fragment, and validation flags consumed by
`tests/utils.py::Config`.

To run a single case outside of pytest — e.g. while iterating on a failure —
use the CLI in `run_tests_cli.py`:

```bash
# Run the case whose test_num matches N (from test_integration_inputs.json)
python -m tests.run_tests_cli --test-num 3

# Run every case with test_num >= N (resume/partial-suite)
python -m tests.run_tests_cli --from-test-num 10

# Or build a one-off Config from flags
python -m tests.run_tests_cli \
    --command "esp-matter-mfg-tool -v 0xFFF2 -p 0x8001 ..." \
    --validate-cert --validate-cn-in-path
```

## Dependencies

`tests/deps/nvs_parser.py` is from esp-idf:

- https://github.com/espressif/esp-idf/blob/20d1a480ab7acb2441a8dc60af3d9c8fc9336fea/components/nvs_flash/nvs_partition_tool/nvs_parser.py

It is used by `utils.parse_partition_bin()` to decode the generated NVS
partition binary and cross-check its contents against the CLI arguments that
produced it. Keep it in sync with upstream when the NVS on-disk format changes.
