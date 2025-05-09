#!/usr/bin/env python3
"""
FirewallParser.py – scalable firewall-log analyser + condensed rule suggester
Run: python FirewallParser.py logs.csv --top 10 --ip_threshold 0.9 --port_threshold 0.9
"""

from __future__ import annotations
import argparse, csv, sys
from pathlib import Path
import ipaddress as _ip
import pandas as pd


# ══════════════════  core class  ═══════════════════════════════════════
class FirewallAnalyzer:
    def __init__(self,
                 ip_thresh: float = 0.9,
                 port_thresh: float = 0.9,
                 top_n: int = 10,
                 verbose: bool = False) -> None:
        self.ip_thresh   = ip_thresh
        self.port_thresh = port_thresh
        self.top_n       = top_n
        self.verbose     = verbose

        self._src_ip_counts = pd.Series(dtype="uint32")
        self._dst_ip_counts = pd.Series(dtype="uint32")
        self._src_ports     = pd.Series(dtype="uint32")
        self._dst_ports     = pd.Series(dtype="uint32")
        self._bad_rows      = 0

    # ── csv streaming ─────────────────────────────────────────────────
    @staticmethod
    def _row_to_dict(row: list[str]) -> dict[str, str]:
        rec = {}
        for field in row:
            if '=' in field:
                k, v = field.split('=', 1)
                rec[k.strip()] = v.strip('" ')
        return rec

    def consume_csv(self, csv_path: Path, chunksize: int = 100_000) -> None:
        head = pd.read_csv(csv_path, nrows=0)
        direct = {'srcip', 'dstip', 'srcport', 'dstport'}.issubset(head.columns)

        if direct:
            it = pd.read_csv(csv_path,
                             usecols=['srcip', 'dstip', 'srcport', 'dstport'],
                             chunksize=chunksize, dtype=str, na_filter=False)
            for chunk in it:
                self._update_counts(chunk)
        else:
            with csv_path.open(newline='') as fh:
                rdr, batch = csv.reader(fh, delimiter=',', quotechar='"'), []
                for i, row in enumerate(rdr, 1):
                    rec = self._row_to_dict(row)
                    if rec:
                        batch.append(rec)
                    else:
                        self._bad_rows += 1
                    if i % chunksize == 0:
                        self._update_counts(pd.DataFrame(batch)); batch.clear()
                if batch:
                    self._update_counts(pd.DataFrame(batch))

        if self.verbose and self._bad_rows:
            print(f"[!] skipped {self._bad_rows} malformed rows", file=sys.stderr)

    def _update_counts(self, df: pd.DataFrame) -> None:
        for col, store in [('srcip', '_src_ip_counts'),
                           ('dstip', '_dst_ip_counts'),
                           ('srcport', '_src_ports'),
                           ('dstport', '_dst_ports')]:
            if col in df.columns:
                setattr(self, store,
                        getattr(self, store).add(df[col].astype(str).value_counts(),
                                                 fill_value=0))

    # ── quick table for GUI / CLI display ────────────────────────────
    def top_table(self) -> dict[str, pd.Series]:
        return {
            "Source IP":        self._src_ip_counts.nlargest(self.top_n),
            "Destination IP":   self._dst_ip_counts.nlargest(self.top_n),
            "Source Port":      self._src_ports.nlargest(self.top_n),
            "Destination Port": self._dst_ports.nlargest(self.top_n),
        }

    # ── helper utilities ─────────────────────────────────────────────
    @staticmethod
    def _supernet(ip_list: list[str]) -> str | None:
        try:
            nets = [_ip.ip_network(ip) if '/' in ip else _ip.ip_network(ip + '/32')
                    for ip in ip_list]
            collapsed = list(_ip.collapse_addresses(nets))
            if len(collapsed) == 1:
                return str(collapsed[0])
            sup = collapsed[0]
            for net in collapsed[1:]:
                while not net.subnet_of(sup):
                    sup = sup.supernet(new_prefix=sup.prefixlen - 1)
            return str(sup)
        except ValueError:
            return None

    def _threshold_subset(self, s: pd.Series, t: float) -> tuple[list[str], float]:
        if s.empty:
            return [], 0.0
        total, cum, elems = s.sum(), 0, []
        for v, c in s.items():
            cum += c; elems.append(v)
            if cum / total >= t:
                break
        return elems, cum / total

    def _best_network(self, s: pd.Series, thresh: float, max_pref: int) -> tuple[str | None, float]:
        ips, cov = self._threshold_subset(s, thresh)
        net = self._supernet(ips) if ips else None
        return (net, cov) if net and _ip.ip_network(net).prefixlen >= max_pref else (None, cov)

    def _ip_to24(self, ip: str) -> str:
        o = ip.split('.'); return '.'.join(o[:3] + ['0']) + '/24'

    # ── rule generator (condensed) ───────────────────────────────────
    def rule_suggestions(self,
                         max_ports: int = 3,
                         min_port_share: float = 0.01,  # 1 % → shows port 123
                         max_rules: int = 10,
                         target_coverage: float = 0.80) -> list[str]:

        suggestions: list[str] = []

        # ---- source network (up to /21) ------------------------------
        src_net, src_cov = self._best_network(self._src_ip_counts, self.ip_thresh, 21)
        if not src_net:
            tops, src_cov = self._threshold_subset(self._src_ip_counts, self.ip_thresh)
            src_net = ', '.join(tops[:3]) + ('…' if len(tops) > 3 else '')

        # ---- dominant destination ports ------------------------------
        port_series = self._dst_ports.sort_values(ascending=False)
        ports = [p for p, c in port_series.items()
                 if c / port_series.sum() >= min_port_share][:max_ports]
        if not ports:
            return ["No destination port exceeds the minimum share threshold."]
        port_list_str = ", ".join(ports)

        # ---- /24 destination clustering ------------------------------
        cluster_bytes, per_cluster = {}, {}
        for ip, cnt in self._dst_ip_counts.items():
            cidr = self._ip_to24(ip)
            cluster_bytes[cidr] = cluster_bytes.get(cidr, 0) + cnt
            per_cluster.setdefault(cidr, pd.Series(dtype="uint32"))[ip] = cnt

        clusters_sorted = sorted(cluster_bytes.items(),
                                 key=lambda kv: kv[1], reverse=True)

        total_dst, covered, seen = self._dst_ip_counts.sum(), 0, set()

        # ---- emit concise rules (dst nets up to /20) -----------------
        for cidr, bytes_in in clusters_sorted:
            dst_net, dst_cov = self._best_network(per_cluster[cidr],
                                                  self.ip_thresh, 20)  # /20 supernet allowed
            if not dst_net or dst_net in seen:
                continue
            seen.add(dst_net)

            suggestions.append(
                f"Allow {src_net} ➜ {dst_net} on [{port_list_str}] "
                f"(src {src_cov:.0%}, dst {dst_cov:.0%})"
            )

            covered += bytes_in
            if covered / total_dst >= target_coverage or len(suggestions) >= max_rules:
                break

        # ---- anomaly hint -------------------------------------------
        rare = self._dst_ports[self._dst_ports < 5]
        if not rare.empty:
            suggestions.append("Rare destination ports (<5 hits): " +
                               ', '.join(map(str, rare.index[:10])) + ' …')

        return suggestions or ["No patterns met the thresholds."]


# ══════════════════  CLI wrapper  ═══════════════════════════════════════
def _run_cli() -> None:
    ap = argparse.ArgumentParser(description="Firewall log analyser → rule suggestions")
    ap.add_argument("csv_file", help="Path to CSV firewall log")
    ap.add_argument("--top", type=int, default=10, help="Top-N rows to show")
    ap.add_argument("--ip_threshold", type=float, default=0.9)
    ap.add_argument("--port_threshold", type=float, default=0.9)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    fa = FirewallAnalyzer(ip_thresh=args.ip_threshold,
                          port_thresh=args.port_threshold,
                          top_n=args.top,
                          verbose=args.verbose)
    fa.consume_csv(Path(args.csv_file))

    print("==== Top values ====")
    for cat, ser in fa.top_table().items():
        print(f"\n{cat}:\n{ser.to_string()}")

    print("\n==== Firewall rule suggestion(s) ====")
    for line in fa.rule_suggestions():
        print("•", line)


if __name__ == "__main__":
    _run_cli()
