#!/usr/bin/env python3
"""Audit Chainlink AggregatorV3 proxy rounds using only JSON-RPC."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, getcontext
from typing import Any, Callable, Iterable

MASK64 = (1 << 64) - 1
RATE = 136


def _rotation_offsets() -> list[list[int]]:
    offsets = [[0 for _ in range(5)] for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        offsets[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _round_constants() -> list[int]:
    def lfsr_bit(index: int) -> int:
        state = 0x01
        for _ in range(index % 255):
            state = ((state << 1) ^ 0x71) & 0xFF if state & 0x80 else (state << 1) & 0xFF
        return state & 1

    constants = []
    for round_index in range(24):
        value = 0
        for j in range(7):
            if lfsr_bit(7 * round_index + j):
                value ^= 1 << ((1 << j) - 1)
        constants.append(value)
    return constants


ROTATION_OFFSETS = _rotation_offsets()
ROUND_CONSTANTS = _round_constants()


def _rotl64(value: int, amount: int) -> int:
    if amount == 0:
        return value & MASK64
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def _keccak_f(state: list[int]) -> None:
    for round_constant in ROUND_CONSTANTS:
        column_parity = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        correction = [column_parity[(x - 1) % 5] ^ _rotl64(column_parity[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= correction[x]

        rotated = [0] * 25
        for x in range(5):
            for y in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], ROTATION_OFFSETS[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = rotated[x + 5 * y] ^ ((~rotated[(x + 1) % 5 + 5 * y]) & rotated[(x + 2) % 5 + 5 * y])
        state[0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Return Keccak-256, not the standardized SHA3-256 variant."""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % RATE != RATE - 1:
        padded.append(0)
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), RATE):
        block = padded[offset : offset + RATE]
        for lane in range(RATE // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        _keccak_f(state)

    output = bytearray()
    while len(output) < 32:
        for lane in range(RATE // 8):
            output.extend(state[lane].to_bytes(8, "little"))
        if len(output) >= 32:
            break
        _keccak_f(state)
    return bytes(output[:32])


def selector(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii"))[:4].hex()


def _word(value: int) -> bytes:
    if value < 0:
        value &= (1 << 256) - 1
    return value.to_bytes(32, "big")


def _address_word(address: str) -> bytes:
    normalized = normalize_address(address)
    return bytes.fromhex(normalized[2:]).rjust(32, b"\x00")


def normalize_address(address: str) -> str:
    value = address.strip().lower()
    if not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"invalid EVM address: {address}")
    try:
        int(value[2:], 16)
    except ValueError as exc:
        raise ValueError(f"invalid EVM address: {address}") from exc
    return value


def _quantity(value: int) -> str:
    return hex(value)


def _int_from_word(word: bytes, signed: bool = False) -> int:
    value = int.from_bytes(word, "big")
    if signed and value & (1 << 255):
        value -= 1 << 256
    return value


def _decode_words(result: str) -> list[bytes]:
    raw = bytes.fromhex(result[2:] if result.startswith("0x") else result)
    if len(raw) % 32 != 0:
        raise ValueError("ABI response is not word-aligned")
    return [raw[index : index + 32] for index in range(0, len(raw), 32)]


@dataclass
class RoundData:
    round_id: int
    answer: int
    started_at: int
    updated_at: int
    answered_in_round: int

    def as_dict(self, decimals: int) -> dict[str, Any]:
        getcontext().prec = 80
        scaled = Decimal(self.answer) / (Decimal(10) ** decimals)
        return {
            "round_id": self.round_id,
            "answer": str(self.answer),
            "answer_decimal": format(scaled, "f"),
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "answered_in_round": self.answered_in_round,
        }


class RpcError(RuntimeError):
    pass


class JsonRpcClient:
    def __init__(self, url: str, timeout: float = 30.0, opener: Callable[..., Any] | None = None):
        self.url = url
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._next_id = 1

    def call(self, method: str, params: list[Any]) -> Any:
        request_body = json.dumps({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}).encode("utf-8")
        self._next_id += 1
        request = urllib.request.Request(
            self.url,
            data=request_body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "oracle-round-audit/0.1"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise RpcError(f"RPC request failed: {exc}") from exc
        if "error" in payload:
            error = payload["error"]
            raise RpcError(f"{method} failed: {error.get('message', error)}")
        return payload.get("result")


def call_contract(rpc: Any, address: str, data: bytes, block_tag: str = "latest") -> str:
    result = rpc.call("eth_call", [{"to": normalize_address(address), "data": "0x" + data.hex()}, block_tag])
    if not isinstance(result, str):
        raise RpcError("eth_call returned a non-hex result")
    return result


def read_address(rpc: Any, address: str, signature: str, block_tag: str) -> str:
    result = call_contract(rpc, address, bytes.fromhex(selector(signature)[2:]), block_tag)
    words = _decode_words(result)
    if not words:
        raise RpcError(f"{signature} returned no data")
    return "0x" + words[0][-20:].hex()


def read_uint(rpc: Any, address: str, signature: str, block_tag: str) -> int:
    result = call_contract(rpc, address, bytes.fromhex(selector(signature)[2:]), block_tag)
    words = _decode_words(result)
    if not words:
        raise RpcError(f"{signature} returned no data")
    return _int_from_word(words[0])


def read_round_data(rpc: Any, address: str, signature: str, round_id: int | None, block_tag: str) -> RoundData:
    data = bytearray.fromhex(selector(signature)[2:])
    if round_id is not None:
        data.extend(_word(round_id))
    words = _decode_words(call_contract(rpc, address, bytes(data), block_tag))
    if len(words) < 5:
        raise RpcError(f"{signature} returned fewer than five words")
    return RoundData(
        round_id=_int_from_word(words[0]),
        answer=_int_from_word(words[1], signed=True),
        started_at=_int_from_word(words[2]),
        updated_at=_int_from_word(words[3]),
        answered_in_round=_int_from_word(words[4]),
    )


def _block_tag_as_int(block_tag: str, block: dict[str, Any]) -> int:
    if block_tag in {"latest", "pending", "safe", "finalized"}:
        return int(block["number"], 16)
    return int(block_tag, 0)


def _event_topic(signature: str) -> str:
    return "0x" + keccak256(signature.encode("ascii")).hex()


def audit_proxy(
    rpc: Any,
    proxy: str,
    heartbeat: int | None = None,
    rounds: int = 12,
    max_move_pct: Decimal = Decimal("5"),
    lookback_blocks: int = 200_000,
    block_tag: str = "latest",
) -> dict[str, Any]:
    proxy = normalize_address(proxy)
    if rounds < 1:
        raise ValueError("rounds must be positive")
    if lookback_blocks < 0:
        raise ValueError("lookback_blocks must not be negative")

    block = rpc.call("eth_getBlockByNumber", [block_tag, False])
    if not isinstance(block, dict) or "number" not in block or "timestamp" not in block:
        raise RpcError("eth_getBlockByNumber returned an incomplete block")
    block_number = _block_tag_as_int(block_tag, block)
    block_timestamp = int(block["timestamp"], 16)

    aggregator = read_address(rpc, proxy, "aggregator()", block_tag)
    decimals = read_uint(rpc, proxy, "decimals()", block_tag)
    latest = read_round_data(rpc, proxy, "latestRoundData()", None, block_tag)

    observed: list[RoundData] = []
    missing: list[int] = []
    first_candidate = max(1, latest.round_id - rounds + 1)
    for candidate in range(latest.round_id, first_candidate - 1, -1):
        try:
            observed.append(read_round_data(rpc, proxy, "getRoundData(uint80)", candidate, block_tag))
        except RpcError:
            missing.append(candidate)

    observed_by_id = {item.round_id: item for item in observed}
    ordered = sorted(observed_by_id.values(), key=lambda item: item.round_id)
    movements: list[dict[str, Any]] = []
    for previous, current in zip(ordered, ordered[1:]):
        if previous.answer == 0:
            change = None
        else:
            change = abs(Decimal(current.answer - previous.answer) / Decimal(previous.answer) * Decimal(100))
        if change is None or change > max_move_pct:
            movements.append({
                "from_round": previous.round_id,
                "to_round": current.round_id,
                "change_pct": None if change is None else format(change, "f"),
            })

    age = max(0, block_timestamp - latest.updated_at)
    phase_id = latest.round_id >> 64
    logs: list[dict[str, Any]] = []
    if lookback_blocks >= 0:
        from_block = max(0, block_number - lookback_blocks)
        try:
            result = rpc.call(
                "eth_getLogs",
                [{
                    "address": proxy,
                    "fromBlock": _quantity(from_block),
                    "toBlock": block_tag,
                    "topics": [_event_topic("AggregatorUpdated(address,address)")],
                }],
            )
            if isinstance(result, list):
                for item in result:
                    topics = item.get("topics", [])
                    if len(topics) >= 3:
                        logs.append({
                            "block_number": int(item.get("blockNumber", "0x0"), 16),
                            "transaction_hash": item.get("transactionHash"),
                            "previous": "0x" + topics[1][-40:].lower(),
                            "current": "0x" + topics[2][-40:].lower(),
                        })
        except RpcError as exc:
            logs.append({"error": str(exc)})

    stale = heartbeat is not None and age > heartbeat
    status = "ok"
    if stale or missing or movements or logs:
        status = "warn"

    return {
        "status": status,
        "proxy": proxy,
        "aggregator": aggregator,
        "decimals": decimals,
        "block": {"number": block_number, "timestamp": block_timestamp},
        "latest": latest.as_dict(decimals),
        "age_seconds": age,
        "heartbeat_seconds": heartbeat,
        "stale": stale,
        "phase_id": phase_id,
        "rounds_requested": rounds,
        "rounds_found": len(observed),
        "missing_round_ids": sorted(missing),
        "abnormal_moves": movements,
        "aggregator_updates": logs,
        "checks": {
            "freshness": "warn" if stale else "pass",
            "round_continuity": "warn" if missing else "pass",
            "movement": "warn" if movements else "pass",
            "proxy_history": "warn" if logs else "pass",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit a Chainlink AggregatorV3 proxy through JSON-RPC")
    parser.add_argument("--rpc-url", required=True, help="EVM JSON-RPC URL")
    parser.add_argument("--proxy", required=True, help="Chainlink AggregatorV3 proxy address")
    parser.add_argument("--heartbeat", type=int, help="Expected update heartbeat in seconds")
    parser.add_argument("--rounds", type=int, default=12, help="Number of recent round IDs to inspect")
    parser.add_argument("--max-move-pct", type=Decimal, default=Decimal("5"), help="Flag a consecutive answer move above this percentage")
    parser.add_argument("--lookback-blocks", type=int, default=200_000, help="Block window for AggregatorUpdated logs")
    parser.add_argument("--block-tag", default="latest", help="Block tag or number such as latest or 0x1234")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = audit_proxy(
            JsonRpcClient(args.rpc_url),
            args.proxy,
            heartbeat=args.heartbeat,
            rounds=args.rounds,
            max_move_pct=args.max_move_pct,
            lookback_blocks=args.lookback_blocks,
            block_tag=args.block_tag,
        )
    except (ValueError, RpcError, InvalidOperation) as exc:
        parser.error(str(exc))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
