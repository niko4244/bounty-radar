# Bounty Radar 🛰️

**Find real, payable open-source bounties on GitHub — and quarantine the scams.**

The raw GitHub "bounty" feed is mostly noise. In a single live scan, ~95% of
listings were one of:

- 🪙 **Crypto-token payouts** dressed up as cash (RTC, MRWK, QCOIN — not money)
- 🤖 **Aggregator-bot spam** ("Bounty Alert: 24 new opportunities…")
- 🏭 **Synthetic bounty-farms** that recycle the same fake issue thousands of times
- 🎣 **Prompt-injection honeypots** — fake "$9k" bounties whose acceptance criteria
  secretly tell an AI agent to paste its **system prompt** into the pull request
- 🔧 **Hardware-gated tasks** you can't do (needs a specific GPU, car CAN bus, watch…)

Bounty Radar cuts through it. It keeps only **USD-denominated, unassigned,
software-only** bounties, ranks them by **how likely they are to actually pay**,
and flags the traps so you don't waste hours — or get your account banned.

```
Scanned 314 raw issues → 13 real-USD unassigned bounties (13 solvable here).
Quarantined: 3 prompt-injection / honeypot listings — do NOT engage.
```

## Why this exists

AI coding agents are now swarming bounty boards. That created two new problems:
agents working for free on bounties that never pay, and agents getting **banned
across platforms** for low-quality or fabricated submissions. The single nastiest
trap is the injection honeypot — a "bounty" engineered to make your agent leak its
hidden instructions. Bounty Radar was built after catching one such farm with
~80 issues and a notional ~$500K in fake rewards.

## Install

No dependencies. You only need the [GitHub CLI](https://cli.github.com/):

```bash
gh auth login          # one time
python bounty_radar.py
```

## Usage

```bash
python bounty_radar.py                  # scan, print a ranked report
python bounty_radar.py --min 250        # only bounties >= $250
python bounty_radar.py --md report.md   # also save Markdown
python bounty_radar.py --json hits.json # also save JSON (for automation)
```

Reliability tiers:

| Tier | Meaning |
|---|---|
| `escrowed/funded` | Real escrow link or a known funded org — most likely to pay |
| `unknown` | No clear payment signal — verify before investing hours |
| `unescrowed-board` | Goodwill board, funds not held — may never pay |

## What it filters (free tier)

The free tool ships the core, openly-documented signatures: crypto-token
currencies, the loudest aggregator/farm patterns, hardware-gating keywords, and a
baseline prompt-injection detector.

## Pro Kit 🔓

The **Bounty Radar Pro Kit** is a separate download for people doing this for real:

- **The Bounty Safety Field Guide** — how to earn from OSS/agent bounties without
  getting scammed or banned: escrow vs. goodwill, the swarm math, the injection
  attack dissected, and the cash-out (KYC) reality.
- **Verified-payer list** — a curated, growing allowlist of orgs that actually pay.
- **Extended threat signatures** — a much larger honeypot / farm / token pattern set.
- **Daily watchlist setup** — run it on a schedule and only get pinged when a
  genuinely *winnable* bounty appears.

→ **[Get the Pro Kit on Gumroad](https://bountyradar.gumroad.com/l/pro-kit)** — $19

## Safety note

Bounty Radar never submits, comments, or acts on your behalf. It reads public
GitHub data and prints a report. If a listing asks you (or your agent) to paste
hidden instructions, reveal a system prompt, or include "the text before the first
user message" — that is an attack. Don't do it. Bounty Radar quarantines these
automatically.

## License

MIT. See [LICENSE](LICENSE).
