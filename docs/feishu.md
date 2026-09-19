# Feishu (Lark) Notifications

VulnRadar can push critical vulnerability alerts to a Feishu group via a
custom bot webhook (自定义机器人).

## Setup

1. In Feishu, open the target group → **Settings → Group Bots → Add Bot → Custom Bot**.
2. Name the bot (e.g. `VulnRadar`) and copy the webhook URL
   (`https://open.feishu.cn/open-apis/bot/v2/hook/...`).
3. (Optional) If you enable **Signature Verification (签名校验)**, copy the
   signing secret as well.
4. In your fork: **Settings → Secrets and variables → Actions → New repository secret**:
   - `FEISHU_WEBHOOK_URL` — the webhook URL
   - `FEISHU_SECRET` — the signing secret (only if signature verification is on)

The `notify.yml` workflow picks these up automatically on the next run.

## Message formats

| Scenario | Card |
|----------|------|
| New critical CVE | Red/orange/blue interactive card with CVSS, EPSS, KEV, and exploit-intel fields plus a link to the CVE record |
| First-run baseline | Green card with your watchlist summary (no individual alerts) |
| Summary runs | Stats card with top critical findings |

## Local testing

```bash
export FEISHU_WEBHOOK_URL="https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
export FEISHU_SECRET="your-signing-secret"   # optional
python notify.py --in data/radar_data.json --dry-run   # preview
python notify.py --in data/radar_data.json            # send
```

CLI flags: `--feishu-webhook`, `--feishu-secret`, `--feishu-max`,
`--feishu-summary-only`.

## Per-severity routing

Multiple Feishu webhooks can be routed by severity via `watchlist.yaml`:

```yaml
notifications:
  feishu:
    - url: $FEISHU_CRITICAL_WEBHOOK
      filter: critical
      max_alerts: 25
    - url: $FEISHU_ALL_WEBHOOK
      filter: all
      max_alerts: 10
```

See [configuration.md](configuration.md) for the full routing reference.

## Troubleshooting

- **19021 (Signature verification failed)** — `FEISHU_SECRET` is missing or
  wrong, or the bot expects signing but none was sent.
- **9499 / Forbidden** — webhook URL revoked or bot removed from the group.
- No messages at all — check that findings are critical/new; the first run
  only establishes a baseline (see [troubleshooting.md](troubleshooting.md)).
