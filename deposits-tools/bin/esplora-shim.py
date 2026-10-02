#!/usr/bin/env python3
"""A minimal Esplora-compatible HTTP API over bitcoind RPC, for the devnet.

The reference deposits-node syncs its BDK wallet through Esplora no matter
which chain backend it is given; our private signet has none.  This serves
the endpoints esplora-client 0.11 calls, from an in-memory index built by
walking the (small) chain with getblock verbosity 3, refreshed on demand.
Requires txindex=1 (for /tx/:txid on arbitrary transactions)."""
import json, os, sys, hashlib, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLI = os.environ.get("ESPLORA_BITCOIN_CLI", "bitcoin-cli").split()
PORT = int(os.environ.get("ESPLORA_PORT", "3002"))

def rpc(*args):
    out = subprocess.run(CLI + list(args), capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip() or out.stdout.strip())
    s = out.stdout.strip()
    try: return json.loads(s)
    except Exception: return s

lock = threading.Lock()
txs = {}        # txid -> dict(tx=esplora json, spk set)
by_spk = {}     # spk hex -> [txid] in chain order
spends = {}     # "txid:vout" -> spending txid
blocks = {}     # height -> hash
indexed_height = -1

def scripthash(spk_hex):
    return hashlib.sha256(bytes.fromhex(spk_hex)).digest()

def to_esplora(tx, height=None, bhash=None, btime=None):
    vin, fee_in = [], 0
    for i in tx["vin"]:
        if "coinbase" in i:
            vin.append({"txid": "0"*64, "vout": 0xffffffff, "prevout": None, "scriptsig": i["coinbase"],
                        "scriptsig_asm": "", "witness": i.get("txinwitness", []), "is_coinbase": True, "sequence": i["sequence"]})
        else:
            po = i.get("prevout")
            prev = None
            if po:
                prev = {"scriptpubkey": po["scriptPubKey"]["hex"], "scriptpubkey_asm": "", "scriptpubkey_type": po["scriptPubKey"].get("type", ""),
                        "scriptpubkey_address": po["scriptPubKey"].get("address", ""), "value": int(round(po["value"] * 1e8))}
                fee_in += prev["value"]
            vin.append({"txid": i["txid"], "vout": i["vout"], "prevout": prev, "scriptsig": i["scriptSig"]["hex"],
                        "scriptsig_asm": "", "witness": i.get("txinwitness", []), "is_coinbase": False, "sequence": i["sequence"]})
    vout = [{"scriptpubkey": o["scriptPubKey"]["hex"], "scriptpubkey_asm": "", "scriptpubkey_type": o["scriptPubKey"].get("type", ""),
             "scriptpubkey_address": o["scriptPubKey"].get("address", ""), "value": int(round(o["value"] * 1e8))} for o in tx["vout"]]
    total_out = sum(o["value"] for o in vout)
    coinbase = any(v["is_coinbase"] for v in vin)
    status = {"confirmed": height is not None, "block_height": height, "block_hash": bhash, "block_time": btime}
    return {"txid": tx["txid"], "version": tx["version"], "locktime": tx["locktime"], "vin": vin, "vout": vout,
            "size": tx["size"], "weight": tx["weight"], "fee": 0 if coinbase else max(0, fee_in - total_out), "status": status}

def index_tx(e):
    txid = e["txid"]
    spks = {o["scriptpubkey"] for o in e["vout"]} | {v["prevout"]["scriptpubkey"] for v in e["vin"] if v["prevout"]}
    txs[txid] = {"tx": e, "spks": spks}
    for s in spks:
        lst = by_spk.setdefault(s, [])
        if txid not in lst: lst.append(txid)
    for v in e["vin"]:
        if not v["is_coinbase"]: spends[f'{v["txid"]}:{v["vout"]}'] = txid

def catch_up():
    global indexed_height
    with lock:
        tip = rpc("getblockcount")
        # reorg-safe enough for a devnet: re-index if the stored hash moved
        while indexed_height >= 0 and rpc("getblockhash", str(indexed_height)) != blocks.get(indexed_height):
            indexed_height -= 1
        for h in range(indexed_height + 1, tip + 1):
            bh = rpc("getblockhash", str(h))
            b = rpc("getblock", bh, "3")
            blocks[h] = bh
            for tx in b["tx"]:
                index_tx(to_esplora(tx, h, bh, b["time"]))
            indexed_height = h
        # mempool: re-scan each time (small)
        for txid in rpc("getrawmempool"):
            if txid not in txs or txs[txid]["tx"]["status"]["confirmed"] is False:
                try: index_tx(to_esplora(rpc("getrawtransaction", txid, "2"), None, None, None))
                except Exception: pass

def tx_json(txid):
    if txid in txs: return txs[txid]["tx"]
    t = rpc("getrawtransaction", txid, "2")
    h = None; bh = t.get("blockhash"); bt = None
    if bh:
        blk = rpc("getblockheader", bh); h = blk["height"]; bt = blk["time"]
    return to_esplora(t, h, bh, bt)

def spk_txs(spk):
    ids = by_spk.get(spk, [])
    lst = [txs[i]["tx"] for i in ids]
    # newest first, unconfirmed first (esplora order)
    lst.sort(key=lambda t: (-(t["status"]["block_height"] or 10**9)))
    return lst

def addr_spk(addr):
    return rpc("getaddressinfo", addr)["scriptPubKey"] if False else rpc("validateaddress", addr)["scriptPubKey"]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else str(body)).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(n).decode().strip()
        if self.path.rstrip("/") == "/tx":
            try: self.send(200, rpc("sendrawtransaction", raw), "text/plain")
            except Exception as e: self.send(400, str(e), "text/plain")
        else: self.send(404, "not found", "text/plain")
    def do_GET(self):
        try:
            catch_up()
            p = [x for x in self.path.split("?")[0].split("/") if x]
            if p[:3] == ["blocks", "tip", "height"]: return self.send(200, indexed_height, "text/plain")
            if p[:3] == ["blocks", "tip", "hash"]: return self.send(200, blocks[indexed_height], "text/plain")
            if p[0] == "block-height": return self.send(200, blocks[int(p[1])], "text/plain")
            if p[0] == "blocks":
                start = int(p[1]) if len(p) > 1 else indexed_height
                out = []
                for h in range(start, max(-1, start - 10), -1):
                    b = rpc("getblockheader", blocks[h]); out.append({"id": blocks[h], "height": h, "version": b["version"], "timestamp": b["time"], "tx_count": b["nTx"], "size": 0, "weight": 0, "merkle_root": b["merkleroot"], "previousblockhash": b.get("previousblockhash", "0"*64), "mediantime": b["mediantime"], "nonce": b["nonce"], "bits": int(b["bits"], 16), "difficulty": b["difficulty"]})
                return self.send(200, out)
            if p[0] == "block":
                bh = p[1]; b = rpc("getblockheader", bh)
                if len(p) == 3 and p[2] == "header": return self.send(200, rpc("getblockheader", bh, "false"), "text/plain")
                if len(p) == 3 and p[2] == "status": return self.send(200, {"in_best_chain": b.get("confirmations", -1) > 0, "height": b["height"], "next_best": b.get("nextblockhash")})
                if len(p) == 3 and p[2] == "raw": return self.send(200, bytes.fromhex(rpc("getblock", bh, "0")), "application/octet-stream")
                if len(p) == 4 and p[2] == "txid": return self.send(200, rpc("getblock", bh, "1")["tx"][int(p[3])], "text/plain")
            if p[0] == "fee-estimates": return self.send(200, {str(k): 1.0 for k in (1, 2, 3, 6, 10, 20, 144, 504, 1008)})
            if p[0] in ("scripthash", "address"):
                if p[0] == "scripthash":
                    want = p[1].lower()
                    spk = next((s for s in by_spk if scripthash(s).hex() == want or scripthash(s)[::-1].hex() == want), None)
                else:
                    spk = addr_spk(p[1])
                lst = spk_txs(spk) if spk else []
                if len(p) >= 3 and p[2] == "utxo":
                    out = []
                    for t in lst:
                        for i, o in enumerate(t["vout"]):
                            if o["scriptpubkey"] == spk and f'{t["txid"]}:{i}' not in spends:
                                out.append({"txid": t["txid"], "vout": i, "status": t["status"], "value": o["value"]})
                    return self.send(200, out)
                if len(p) >= 4 and p[2] == "txs" and p[3] == "chain":
                    conf = [t for t in lst if t["status"]["confirmed"]]
                    if len(p) >= 5:
                        ids = [t["txid"] for t in conf]
                        conf = conf[ids.index(p[4]) + 1:] if p[4] in ids else []
                    return self.send(200, conf[:25])
                if len(p) >= 3 and p[2] == "txs":
                    unconf = [t for t in lst if not t["status"]["confirmed"]]
                    conf = [t for t in lst if t["status"]["confirmed"]]
                    return self.send(200, (unconf + conf)[:25 + len(unconf)])
                return self.send(200, {"scripthash": p[1]})
            if p[0] == "tx":
                txid = p[1]; t = tx_json(txid)
                if len(p) == 2: return self.send(200, t)
                if p[2] == "status": return self.send(200, t["status"])
                if p[2] == "hex": return self.send(200, rpc("getrawtransaction", txid), "text/plain")
                if p[2] == "raw": return self.send(200, bytes.fromhex(rpc("getrawtransaction", txid)), "application/octet-stream")
                if p[2] == "outspend":
                    key = f"{txid}:{p[3]}"; sp = spends.get(key)
                    return self.send(200, {"spent": sp is not None, "txid": sp, "vin": None, "status": txs[sp]["tx"]["status"] if sp else None})
                if p[2] == "merkle-proof":
                    st = t["status"]; b = rpc("getblock", st["block_hash"], "1")
                    return self.send(200, {"block_height": st["block_height"], "merkle": [], "pos": b["tx"].index(txid)})
            self.send(404, "not found", "text/plain")
        except Exception as e:
            self.send(500, str(e), "text/plain")

if __name__ == "__main__":
    catch_up()
    print(f"esplora shim on http://127.0.0.1:{PORT} indexed to {indexed_height}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
