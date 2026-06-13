#!/usr/bin/env python3
"""
bounty_radar.py — find REAL, payable, solvable open-source bounties on GitHub,
and quarantine the scams.

The raw GitHub "bounty" feed is mostly noise: crypto-token payouts that aren't
real money, synthetic bounty-farms, aggregator-bot spam, hardware-gated tasks
you can't do, and — increasingly — prompt-injection honeypots that try to make
AI agents leak their system prompt. This tool keeps only USD bounties that are
unassigned and software-only, ranks them by how likely they are to actually
pay, and flags the traps.

Free / MIT. Zero dependencies — uses the GitHub CLI (`gh`) you already have.

    pip-free.  Requires: `gh auth login` once.
    Usage:     python bounty_radar.py [--min 50] [--limit 80] [--json out.json]

The Pro Kit (curated funded-org allowlist, extended threat signatures, and the
Bounty Safety Field Guide) is a separate download — see README.
"""
from __future__ import annotations
import argparse
import datetime
import json
import re
import subprocess
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Threat signatures.  These are the core, openly-documented patterns. The Pro
# Kit ships a continuously-curated, much larger set plus a verified payer list.
# ─────────────────────────────────────────────────────────────────────────────

# Repos/owners known to emit fake, crypto, or synthetic "bounties".
NOISE_REPO = re.compile(
    r"rustchain|mergework|charles-microbounties|charles-openclaw|bountyscout|"
    r"atrium-forum|devpool-directory|agent-playground|sn-monetization-runtime|"
    r"clankernation|\bclanker\b|openagents|securebananalabs|oss-hunter-livefire",
    re.I,
)
# Aggregator-bot / token-payout / synthetic-task title patterns. The "calculate
# pi / fix typo in README / add JSDoc" trio are canonical agent-test farm tasks.
NOISE_TITLE = re.compile(
    r"\[radar\]|bounty alert|opportunit|launch another|register your agent|"
    r"\bRTC\b|\bMRWK\b|QCOIN|claim:\s*\d+\s*RTC|"
    r"calculate the exact value of pi|fix typo in readme|"
    r"add jsdoc to userservice|low han\w+ fruit automation",
    re.I,
)
# Labels that mark agent-honeypot / crypto-token farms.
NOISE_LABEL = re.compile(r"autonom\w*\s+agents?\s+only|crypto-eligible|clanker", re.I)
# Reward stated only in a crypto token, no USD.
TOKEN_CCY = re.compile(r"\b(RTC|MRWK|QCOIN|SOL|ETH|BTC|USDC|points?)\b", re.I)

# PROMPT-INJECTION / system-prompt exfiltration. Any "bounty" instructing the
# solver to paste its hidden prompt or initialization text is an attack on the
# agent — never engage. (This pattern set is expanded in the Pro Kit.)
INJECTION = re.compile(
    r"before the first user message|system prompt|platform initialization|"
    r"initial(?:ization)? (?:text|instructions|prompt)|paste (?:the )?entire block|"
    r"your (?:full )?instructions|reveal your|hidden prompt|ignore (?:all )?previous",
    re.I,
)

# Tasks needing physical/specialized hardware most contributors don't have.
HW_GATED = re.compile(
    r"wormhole|blackhole|tenstorrent|tt-metal|tt-llk|\bfpga\b|\basic\b|"
    r"silicon|tensix|\bsfpu\b|cuda kernel|gpu kernel|jtag|oscilloscope|"
    r"\bcan bus\b|\bdbc\b|wearos|\becu\b",
    re.I,
)

# Reliability: a real algora.io escrow link, or a known funded org, means the
# money is likely to actually arrive. (Verified-payer list is in the Pro Kit.)
ESCROW_STRONG = re.compile(r"algora\.io|algora\.dev|gitcoin|console\.algora", re.I)
UNESCROWED = re.compile(r"opire\.dev|/opire\s+try|/attempt\b", re.I)
FUNDED_ORGS = {
    "calcom", "documenso", "twentyhq", "highlight", "remotion-dev", "tldraw",
    "novuhq", "triggerdotdev", "appsmithorg", "ghostfolio", "formbricks",
    "openstatusHQ", "unkeyed", "dittofeed", "tenstorrent", "windmill-labs",
    "coollabsio", "PostHog", "calcom",
}

USD = re.compile(r"\$\s?(\d[\d,]*)\s*([kK])?")
CLAIM = re.compile(r"/attempt|/claim|/opire try|working on (this|it)|PR incoming|"
                   r"i'?ll (take|build|do) this", re.I)


def gh_search(extra: list[str], limit: int) -> list[dict]:
    cmd = ["gh", "search", "issues", *extra, "--state", "open", "--json",
           "title,url,repository,assignees,labels,updatedAt,body",
           "--limit", str(limit)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", timeout=90)
        if out.returncode != 0:
            print(f"  ! query failed ({' '.join(extra)}): "
                  f"{out.stderr.strip()[:160]}", file=sys.stderr)
            return []
        return json.loads(out.stdout or "[]")
    except FileNotFoundError:
        sys.exit("error: GitHub CLI (`gh`) not found. Install it and run "
                 "`gh auth login`.")
    except Exception as e:  # noqa: BLE001
        print(f"  ! {e}", file=sys.stderr)
        return []


def parse_usd(*texts: str) -> int:
    best = 0
    for t in texts:
        for m in USD.finditer(t or ""):
            n = int(m.group(1).replace(",", ""))
            if m.group(2):
                n *= 1000
            best = max(best, n)
    return best


def classify(it: dict, min_usd: int) -> dict | None:
    repo = (it.get("repository") or {}).get("nameWithOwner", "")
    owner = repo.split("/")[0] if "/" in repo else ""
    title = it.get("title", "") or ""
    body = (it.get("body", "") or "")[:4000]
    labels = " ".join(l.get("name", "") for l in (it.get("labels") or []))
    blob = f"{title}\n{body}\n{labels}"

    if NOISE_REPO.search(repo) or NOISE_TITLE.search(title) or NOISE_LABEL.search(labels):
        return None
    if INJECTION.search(blob):
        return {"_quarantine": "prompt-injection", "repo": repo,
                "title": title, "url": it.get("url")}
    if it.get("assignees"):
        return None

    amount = parse_usd(title, body)
    if amount == 0 and TOKEN_CCY.search(blob) and not USD.search(blob):
        return None
    if amount < min_usd:
        return None

    # The 💎 label alone is spoofable — honeypots copy it. Require a real escrow
    # link or a known funded org for the "escrowed/funded" tier.
    if ESCROW_STRONG.search(blob) or owner in FUNDED_ORGS:
        reliability, rscore = "escrowed/funded", 3
    elif UNESCROWED.search(blob):
        reliability, rscore = "unescrowed-board", 1
    else:
        reliability, rscore = "unknown", 2

    claimers = len(set(re.findall(r"@?\w+", " ".join(
        c for c in [body] if CLAIM.search(body)))) ) if CLAIM.search(body) else 0

    return {
        "repo": repo, "title": title, "url": it.get("url"),
        "amount_usd": amount, "reliability": reliability, "_rscore": rscore,
        "hardware_gated": bool(HW_GATED.search(blob)),
        "updated": it.get("updatedAt"), "labels": labels.strip(),
    }


def build_report(raw: dict[str, dict], min_usd: int) -> tuple[str, list, list]:
    classified = [c for c in (classify(it, min_usd) for it in raw.values()) if c]
    quarantined = [c for c in classified if c.get("_quarantine")]
    hits = [c for c in classified if not c.get("_quarantine")]
    hits.sort(key=lambda h: (h["_rscore"], not h["hardware_gated"],
                             h["amount_usd"], h["updated"] or ""), reverse=True)

    solvable = [h for h in hits if not h["hardware_gated"]]
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = [f"# Bounty radar — {ts}", "",
           f"Scanned **{len(raw)}** raw issues → **{len(hits)}** real-USD "
           f"unassigned bounties (**{len(solvable)}** solvable without special "
           f"hardware).", "",
           "Ranked by payout-reliability → solvability → amount → freshness. "
           "`escrowed/funded` = likely pays. `unescrowed-board` = goodwill, "
           "may not pay. Verify before investing hours.", "",
           "| $ | Reliability | Solvable | Repo | Task | Link |",
           "|---:|---|:---:|---|---|---|"]
    for h in hits[:40]:
        solv = "yes" if not h["hardware_gated"] else "hw-gated"
        title = h["title"].replace("|", "\\|")[:80]
        out.append(f"| ${h['amount_usd']:,} | {h['reliability']} | {solv} | "
                   f"{h['repo']} | {title} | [link]({h['url']}) |")
    if quarantined:
        out += ["", f"## Quarantined: {len(quarantined)} prompt-injection / "
                "honeypot listing(s) — do NOT engage", ""]
        for r in sorted({q["repo"] for q in quarantined}):
            n = sum(1 for q in quarantined if q["repo"] == r)
            out.append(f"- `{r}` — {n} listing(s) trying to extract your system "
                       "prompt / hidden instructions")
    return "\n".join(out) + "\n", hits, quarantined


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description="Find real, payable OSS bounties; "
                                             "quarantine the scams.")
    ap.add_argument("--min", type=int, default=50, help="minimum USD (default 50)")
    ap.add_argument("--limit", type=int, default=80, help="per-query fetch cap")
    ap.add_argument("--json", metavar="FILE", help="also write ranked hits as JSON")
    ap.add_argument("--md", metavar="FILE", help="also write the report as Markdown")
    args = ap.parse_args()

    queries = [["bounty in:title $"], ["bounty", "--label", "bounty"],
               ["bounty", "--label", "💎 Bounty"], ["reward in:title $"]]
    raw: dict[str, dict] = {}
    print("Scanning GitHub for real cash bounties...", file=sys.stderr)
    for q in queries:
        for it in gh_search(q, args.limit):
            url = it.get("url")
            if url and url not in raw:
                raw[url] = it

    report, hits, _ = build_report(raw, args.min)
    print(report)
    if args.md:
        open(args.md, "w", encoding="utf-8").write(report)
    if args.json:
        open(args.json, "w", encoding="utf-8").write(
            json.dumps(hits, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
