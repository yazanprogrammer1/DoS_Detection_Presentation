"""
mitigation.py - Simulated real-time DoS response driven by the ML model's predictions.

How it works
------------
1. Flows from data the model has NEVER seen (Wednesday test split or Friday DDoS) are
   replayed in time order as a "live stream", in micro-batches.
2. The trained Random Forest gives every flow an attack probability p.
3. The Response Engine turns p into an action (response POLICY on the model output;
   the detection itself is 100% the model):
        p >= 0.90          -> BLOCK_FLOW  (drop the connection) + strike for the source IP
        0.50 <= p < 0.90   -> ALERT       (send to SOC analyst, rate-limit the source)
        p <  0.50          -> ALLOW
   A source IP that reaches STRIKES_TO_BAN malicious flows is banned for BAN_SECONDS:
   a firewall rule is generated and later flows from that IP are dropped immediately.
   Whitelisted infrastructure IPs (DNS, gateway) are never banned, to avoid self-DoS.
4. Everything is logged: results/mitigation_log.csv, results/alerts.json,
   results/firewall_rules.txt, plus a summary of how well the response worked.

NOTE: CIC-IDS2017 "MachineLearningCSV" files contain no IP addresses, so source IPs are
SIMULATED (attack flows come from a small attacker pool, benign flows from office hosts).
Firewall commands are only written to a file - never executed.

Usage (from the dos-detection folder):
    python src/mitigation.py                      # Wednesday unseen test flows
    python src/mitigation.py --source friday      # Friday DDoS (attack never trained on)
    python src/mitigation.py --flows 5000 --quiet
"""
import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
RES = ROOT / "results"

BLOCK_P = 0.90
ALERT_P = 0.50
STRIKES_TO_BAN = 3
BAN_SECONDS = 600
BATCH = 250
WHITELIST = {"192.168.10.3"}               # internal DNS server - never ban

# ANSI colours for the console (work in Windows Terminal / VS Code)
C = {"BLOCK": "\033[91m", "BAN": "\033[95m", "ALERT": "\033[93m",
     "ALLOW": "\033[92m", "DROP": "\033[90m", "END": "\033[0m", "BOLD": "\033[1m"}

ATTACKER_POOL = {
    "DoS Hulk": ["205.174.165.73", "205.174.165.74"],
    "DoS GoldenEye": ["185.220.101.7"],
    "DoS slowloris": ["45.155.205.33"],
    "DoS Slowhttptest": ["91.240.118.2"],
    "DDoS": [f"103.77.{i}.{j}" for i in (12, 40) for j in range(10, 25)],   # botnet
}


def assign_ips(df, rng):
    """Simulated source IPs: benign -> 40 office hosts (+ DNS server), attacks -> attacker pool."""
    office = [f"192.168.10.{i}" for i in range(5, 45)] + ["192.168.10.3"]
    ips = np.empty(len(df), dtype=object)
    for label, idx in df.groupby("Label").indices.items():
        pool = ATTACKER_POOL.get(label, office)
        ips[idx] = rng.choice(pool, size=len(idx))
    return ips


def load_stream(source, n_flows, rng):
    path = PROC / ("wednesday_test.parquet" if source == "wednesday" else "friday_clean.parquet")
    df = pd.read_parquet(path)
    if n_flows and n_flows < len(df):
        # keep the class mix, then shuffle to interleave attacks with normal traffic
        df = df.groupby("Label", group_keys=False).sample(frac=n_flows / len(df), random_state=7)
    df = df.sample(frac=1, random_state=7).reset_index(drop=True)
    df["src_ip"] = assign_ips(df, rng)
    # simulated arrival time: one flow every ~5 ms
    start = datetime(2017, 7, 5, 9, 30)
    df["timestamp"] = [start + timedelta(milliseconds=5 * i) for i in range(len(df))]
    return df


class ResponseEngine:
    def __init__(self, model, features, verbose=True):
        self.model = model
        self.features = features
        self.verbose = verbose
        self.strikes = Counter()
        self.banned = {}                    # ip -> ban expiry time
        self.rules = []
        self.alerts = []
        self.log = []

    def _ban(self, ip, now, label):
        expiry = now + timedelta(seconds=BAN_SECONDS)
        self.banned[ip] = expiry
        self.rules.append({
            "time": now.isoformat(), "ip": ip, "expires": expiry.isoformat(),
            "iptables": f"iptables -I INPUT -s {ip} -j DROP -m comment --comment 'ML-DoS {now:%H:%M:%S}'",
            "windows": f'netsh advfirewall firewall add rule name="ML-DoS-{ip}" dir=in action=block remoteip={ip}',
        })
        if self.verbose:
            print(f"{C['BAN']}{C['BOLD']}[{now:%H:%M:%S.%f}"[:-3] + f"] *** BAN {ip:<16} "
                  f"after {self.strikes[ip]} malicious flows -> firewall rule added "
                  f"({BAN_SECONDS // 60} min){C['END']}")

    def process(self, batch):
        """Score a micro-batch with the model, then act on every flow in arrival order."""
        proba = self.model.predict_proba(batch[self.features])[:, 1]
        for row, p in zip(batch.itertuples(index=False), proba):
            ip, now = row.src_ip, row.timestamp
            if ip in self.banned and now < self.banned[ip]:
                action = "DROP_BANNED"          # fast path: firewall drops it, model not needed
            elif p >= BLOCK_P:
                action = "BLOCK_FLOW"
            elif p >= ALERT_P:
                action = "ALERT"
            else:
                action = "ALLOW"

            if action in ("BLOCK_FLOW", "ALERT"):
                self.strikes[ip] += 1
                self.alerts.append({"time": now.isoformat(), "src_ip": ip, "p_attack": round(float(p), 4),
                                    "action": action, "severity": "HIGH" if action == "BLOCK_FLOW" else "MEDIUM"})
                if self.verbose:
                    col = C["BLOCK"] if action == "BLOCK_FLOW" else C["ALERT"]
                    print(f"{col}[{now:%H:%M:%S.%f}"[:-3] + f"] {action:<11} {ip:<16} "
                          f"p(attack)={p:.3f}  strikes={self.strikes[ip]}{C['END']}")
                if (self.strikes[ip] >= STRIKES_TO_BAN and ip not in WHITELIST
                        and not (ip in self.banned and now < self.banned[ip])):
                    self._ban(ip, now, row.Label)

            self.log.append((now, ip, row.Label, int(row.is_attack), float(p), action))


def summarise(engine, elapsed):
    log = pd.DataFrame(engine.log, columns=["timestamp", "src_ip", "true_label", "is_attack",
                                            "p_attack", "action"])
    log.to_csv(RES / "mitigation_log.csv", index=False)
    (RES / "alerts.json").write_text(json.dumps(engine.alerts[:5000], indent=2))
    with open(RES / "firewall_rules.txt", "w", encoding="utf-8") as f:
        f.write("# Firewall rules generated by the ML response engine (NOT executed - simulation)\n")
        for r in engine.rules:
            f.write(f"\n# {r['time']}  ban {r['ip']} until {r['expires']}\n{r['iptables']}\n{r['windows']}\n")

    stopped = log.action.isin(["BLOCK_FLOW", "DROP_BANNED"])
    atk, ben = log.is_attack == 1, log.is_attack == 0
    attacker_ips = set(log.loc[atk, "src_ip"])
    banned_ips = {r["ip"] for r in engine.rules}

    print("\n" + "=" * 70 + f"\n{C['BOLD']} RESPONSE SUMMARY{C['END']}\n" + "=" * 70)
    print(f"Flows processed               : {len(log):,}  ({len(log) / elapsed:,.0f} flows/s)")
    print("Actions                       : " + ", ".join(f"{k}={v:,}" for k, v in log.action.value_counts().items()))
    print(f"Attack flows stopped          : {(stopped & atk).sum():,} / {atk.sum():,} "
          f"({(stopped & atk).sum() / max(atk.sum(), 1) * 100:.2f}%)")
    print(f"Attack flows alerted only     : {((log.action == 'ALERT') & atk).sum():,}")
    print(f"Attack flows missed (ALLOW)   : {((log.action == 'ALLOW') & atk).sum():,}")
    print(f"Benign flows wrongly stopped  : {(stopped & ben).sum():,} / {ben.sum():,} "
          f"({(stopped & ben).sum() / max(ben.sum(), 1) * 100:.3f}%)")
    print(f"Attacker IPs banned           : {len(banned_ips & attacker_ips)} / {len(attacker_ips)}")
    wrong = banned_ips - attacker_ips
    print(f"Innocent IPs banned           : {len(wrong)} {sorted(wrong) if wrong else ''}")
    print(f"Firewall rules written        : {len(engine.rules)} -> results/firewall_rules.txt")
    print("Logs                          : results/mitigation_log.csv, results/alerts.json")


def main():
    ap = argparse.ArgumentParser(description="ML-driven DoS response simulation")
    ap.add_argument("--source", choices=["wednesday", "friday"], default="wednesday")
    ap.add_argument("--flows", type=int, default=3000, help="number of flows to replay (0 = all)")
    ap.add_argument("--quiet", action="store_true", help="only print the summary")
    args = ap.parse_args()

    model = joblib.load(ROOT / "models" / "rf_dos_detector.joblib")
    features = json.loads((ROOT / "models" / "model_card.json").read_text())["features"]
    stream = load_stream(args.source, args.flows, np.random.default_rng(7))

    print(f"{C['BOLD']}ML DoS Response Engine{C['END']} | source={args.source} | flows={len(stream):,} | "
          f"policy: BLOCK p>={BLOCK_P}, ALERT p>={ALERT_P}, BAN after {STRIKES_TO_BAN} strikes\n")
    engine = ResponseEngine(model, features, verbose=not args.quiet)
    t = time.time()
    for start in range(0, len(stream), BATCH):
        engine.process(stream.iloc[start:start + BATCH])
    summarise(engine, time.time() - t)


if __name__ == "__main__":
    main()
