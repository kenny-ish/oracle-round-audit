# oracle-round-audit

`oracle-round-audit` checks a Chainlink AggregatorV3 proxy for stale answers, missing round IDs, large consecutive moves, and recent `AggregatorUpdated` events using only EVM JSON-RPC calls. It has no package dependencies and does not use an explorer or an indexer.

## Example

This is an actual Ethereum mainnet run at block 26166047.

```text
$ python oracle_round_audit.py --rpc-url https://ethereum-rpc.publicnode.com --proxy 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419 --heartbeat 3600 --rounds 6 --max-move-pct 5 --lookback-blocks 5000
{
  "abnormal_moves": [],
  "age_seconds": 588,
  "aggregator": "0x7d4e742018fb52e48b08be73d041c18b21de6fb5",
  "aggregator_updates": [],
  "block": {
    "number": 26166047,
    "timestamp": 1791683627
  },
  "checks": {
    "freshness": "pass",
    "movement": "pass",
    "proxy_history": "pass",
    "round_continuity": "pass"
  },
  "decimals": 8,
  "heartbeat_seconds": 3600,
  "latest": {
    "answer": "250698054686",
    "answer_decimal": "2506.98054686",
    "answered_in_round": 129127208515966895815,
    "round_id": 129127208515966895815,
    "started_at": 1791683026,
    "updated_at": 1791683039
  },
  "missing_round_ids": [],
  "phase_id": 7,
  "proxy": "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419",
  "rounds_found": 6,
  "rounds_requested": 6,
  "stale": false,
  "status": "ok"
}
```

## Usage

```text
python oracle_round_audit.py --rpc-url RPC_URL --proxy PROXY [--heartbeat SECONDS] [--rounds N] [--max-move-pct PERCENT] [--lookback-blocks N] [--block-tag TAG]
```

`--rpc-url` and `--proxy` are required. The heartbeat compares the chain timestamp of the selected block with `updatedAt`. The round window is checked by calling `getRoundData` for each candidate ID, so a reverted call is reported as a missing round. `--lookback-blocks` limits the `AggregatorUpdated` log query.

## How it works

The program calls `aggregator()`, `decimals()`, `latestRoundData()`, and `getRoundData(uint80)` with `eth_call`. It compares the returned timestamps and signed answers, derives the proxy phase from the round ID, and scans `AggregatorUpdated(address,address)` logs with `eth_getLogs`. ABI words and EVM Keccak-256 are implemented in the file with the Python standard library only.

## Tests

`python -m unittest -v`
