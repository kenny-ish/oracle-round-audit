import json
import os
import sys
import unittest
from decimal import Decimal

sys.path.insert(0, os.path.dirname(__file__))

from oracle_round_audit import (  # noqa: E402
    JsonRpcClient,
    RpcError,
    audit_proxy,
    keccak256,
    selector,
)


PROXY = "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419"
AGGREGATOR = "0x7d4e742018fb52e48b08be73d041c18b21de6fb5"
LATEST_ID = 129127208515966895815
REAL_ROUNDS = {
    129127208515966895810: (250688403399, 1791664899, 1791664919),
    129127208515966895811: (250653542110, 1791668531, 1791668543),
    129127208515966895812: (250657185194, 1791672132, 1791672155),
    129127208515966895813: (250408709260, 1791675764, 1791675803),
    129127208515966895814: (250252720486, 1791679395, 1791679415),
    129127208515966895815: (250698054686, 1791683026, 1791683039),
}
BLOCK_HASH = "0x29211570010e157deb04bbcaae7ac6af0a4983c3f98673496bb480c59b327e62"


def word(value):
    if value < 0:
        value &= (1 << 256) - 1
    return value.to_bytes(32, "big")


def address_result(address):
    return "0x" + word(int(address[2:], 16)).hex()


def round_result(round_id, answer, started_at, updated_at):
    return "0x" + b"".join(
        [word(round_id), word(answer), word(started_at), word(updated_at), word(round_id)]
    ).hex()


class FixedRpc:
    def __init__(self, omit_round=None, make_old=False):
        self.omit_round = omit_round
        self.make_old = make_old
        self.calls = []
        self.block = {
            "number": "0x18f4314",
            "timestamp": "0x6acaeba7",
            "hash": BLOCK_HASH,
        }

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_getBlockByNumber":
            return self.block
        if method == "eth_getLogs":
            return []
        if method != "eth_call":
            raise AssertionError(method)
        request, _tag = params
        data = request["data"]
        if data.startswith(selector("aggregator()")):
            return address_result(AGGREGATOR)
        if data.startswith(selector("decimals()")):
            return "0x" + word(8).hex()
        if data.startswith(selector("latestRoundData()")):
            answer, started, updated = REAL_ROUNDS[LATEST_ID]
            if self.make_old:
                updated = 1791670000
            return round_result(LATEST_ID, answer, started, updated)
        if data.startswith(selector("getRoundData(uint80)")):
            round_id = int(data[-64:], 16)
            if round_id == self.omit_round or round_id not in REAL_ROUNDS:
                raise RpcError("round not found")
            answer, started, updated = REAL_ROUNDS[round_id]
            return round_result(round_id, answer, started, updated)
        raise AssertionError(data)


class OracleRoundAuditTests(unittest.TestCase):
    def test_keccak_and_evm_selectors(self):
        self.assertEqual(
            keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(selector("latestRoundData()"), "0xfeaf968c")
        self.assertEqual(selector("getRoundData(uint80)"), "0x9a6fc8f5")

    def test_fixed_ethereum_block_is_real_and_audit_matches_its_rounds(self):
        fake = FixedRpc()
        self.assertEqual(fake.block["hash"], BLOCK_HASH)
        result = audit_proxy(
            fake,
            PROXY,
            heartbeat=3600,
            rounds=6,
            max_move_pct=Decimal("5"),
            lookback_blocks=5000,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["block"]["number"], 26166036)
        self.assertEqual(result["aggregator"], AGGREGATOR)
        self.assertEqual(result["latest"]["answer_decimal"], "2506.98054686")
        self.assertEqual(result["rounds_found"], 6)
        self.assertEqual(result["missing_round_ids"], [])
        self.assertFalse(result["stale"])
        self.assertTrue(any(method == "eth_getLogs" for method, _ in fake.calls))

    def test_missing_round_is_reported_without_widening_the_window(self):
        fake = FixedRpc(omit_round=LATEST_ID - 2)
        result = audit_proxy(fake, PROXY, rounds=6, lookback_blocks=0)
        self.assertEqual(result["missing_round_ids"], [LATEST_ID - 2])
        self.assertEqual(result["checks"]["round_continuity"], "warn")

    def test_stale_round_is_reported_from_chain_timestamp(self):
        fake = FixedRpc(make_old=True)
        result = audit_proxy(fake, PROXY, heartbeat=3600, rounds=1, lookback_blocks=0)
        self.assertTrue(result["stale"])
        self.assertEqual(result["checks"]["freshness"], "warn")

    def test_http_client_sets_a_user_agent(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()

        def opener(request, timeout):
            captured["user-agent"] = request.get_header("User-agent")
            captured["timeout"] = timeout
            return Response()

        client = JsonRpcClient("https://example.invalid", opener=opener)
        self.assertEqual(client.call("eth_blockNumber", []), "0x1")
        self.assertEqual(captured["user-agent"], "oracle-round-audit/0.1")
        self.assertEqual(captured["timeout"], 30.0)


if __name__ == "__main__":
    unittest.main()
