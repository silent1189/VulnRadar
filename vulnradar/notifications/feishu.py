"""Feishu (Lark) notification provider.

Sends VulnRadar alerts to a Feishu custom bot webhook
(https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN).
Supports optional signature verification via the bot's secret.
"""

import base64
import hashlib
import hmac
import time
from typing import Any

import requests

from ..state import Change
from .base import NotificationProvider

DEFAULT_TIMEOUT = (10, 60)


class FeishuProvider(NotificationProvider):
    """Send VulnRadar alerts via Feishu custom bot webhooks.

    Uses Feishu interactive cards for rich, color-coded notifications.

    Args:
        webhook_url: Feishu bot webhook URL
            (``https://open.feishu.cn/open-apis/bot/v2/hook/...``).
        max_alerts: Maximum individual alerts per run.
        secret: Optional signing secret if signature verification is
            enabled on the bot.
    """

    name = "feishu"
    rate_limit_delay = 0.5

    def __init__(self, webhook_url: str, max_alerts: int = 10, secret: str | None = None):
        self.webhook_url = webhook_url
        self.max_alerts = max_alerts
        self.secret = secret

    def _sign(self) -> dict[str, str]:
        """Build the ``timestamp``/``sign`` fields when a secret is configured.

        Feishu expects ``sign = base64(hmac_sha256(secret, "{timestamp}\\n{secret}"))``.
        """
        if not self.secret:
            return {}
        timestamp = str(int(time.time()))
        digest = hmac.new(
            self.secret.encode("utf-8"),
            f"{timestamp}\n{self.secret}".encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        return {"timestamp": timestamp, "sign": base64.b64encode(digest).decode("utf-8")}

    def _post(self, card: dict[str, Any]) -> None:
        """POST an interactive card to the Feishu webhook."""
        payload: dict[str, Any] = {"msg_type": "interactive", "card": card}
        payload.update(self._sign())
        r = requests.post(self.webhook_url, json=payload, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()

    @staticmethod
    def _field(label: str, value: str) -> dict[str, Any]:
        """Build a short card field entry."""
        return {"is_short": True, "text": {"tag": "lark_md", "content": f"**{label}**\n{value}"}}

    @staticmethod
    def _cve_link(cve_id: str) -> str:
        return f"[{cve_id}](https://www.cve.org/CVERecord?id={cve_id})"

    def send_alert(self, item: dict[str, Any], changes: list[Change] | None = None) -> None:
        """Send a Feishu card for a single CVE.

        Args:
            item: Radar data item dict.
            changes: Optional list of changes that triggered this alert.
        """
        cve_id = str(item.get("cve_id") or "")
        desc = str(item.get("description") or "")[:500]
        epss = item.get("probability_score")
        cvss = item.get("cvss_score")
        kev = bool(item.get("active_threat"))
        patch = bool(item.get("in_patchthis"))
        is_critical = bool(item.get("is_critical"))

        if is_critical:
            template, priority = "red", "🚨 CRITICAL"
        elif kev:
            template, priority = "orange", "⚠️ KEV"
        else:
            template, priority = "blue", "ℹ️ ALERT"

        if changes:
            change_str = " | ".join(str(c) for c in changes)
            desc = f"**Change:** {change_str}\n\n{desc}"

        fields = [
            self._field("EPSS", self._format_epss(epss)),
            self._field("CVSS", self._format_cvss(cvss)),
            self._field("KEV", "✅ Yes" if kev else "❌ No"),
            self._field("Exploit Intel", "✅ Yes" if patch else "❌ No"),
        ]
        kev_obj = item.get("kev")
        if isinstance(kev_obj, dict) and kev_obj.get("dueDate"):
            fields.append(self._field("KEV Due Date", str(kev_obj["dueDate"])))

        card: dict[str, Any] = {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": template,
                "title": {"tag": "plain_text", "content": f"{priority}: {cve_id}"},
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content": desc or "No description available."}},
                {"tag": "hr"},
                {"tag": "div", "fields": fields},
                {
                    "tag": "action",
                    "actions": [
                        {
                            "tag": "button",
                            "text": {"tag": "plain_text", "content": "View CVE Details"},
                            "type": "primary",
                            "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                        }
                    ],
                },
                {"tag": "note", "elements": [{"tag": "plain_text", "content": "VulnRadar Alert"}]},
            ],
        }
        self._post(card)

    def send_summary(
        self,
        items: list[dict[str, Any]],
        repo: str,
        changes_by_cve: dict[str, tuple] | None = None,
    ) -> None:
        """Send a summary card to Feishu.

        Args:
            items: All radar items.
            repo: GitHub repository slug.
            changes_by_cve: Optional dict of CVE ID to ``(item, [Change])``
                tuples.
        """
        total = len(items)
        critical_count = sum(1 for i in items if bool(i.get("is_critical")))
        kev_count = sum(1 for i in items if bool(i.get("active_threat")))
        patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))

        top_5 = self._top_critical(items, n=5)
        top_list = (
            "\n".join(
                f"• {self._cve_link(i.get('cve_id', ''))} (EPSS: {self._format_epss(i.get('probability_score'))})"
                for i in top_5
            )
            or "No critical findings."
        )

        changes_summary = self._build_changes_summary(changes_by_cve)

        elements: list[dict[str, Any]] = [
            {
                "tag": "div",
                "fields": [
                    self._field("Total CVEs", str(total)),
                    self._field("🚨 Critical", str(critical_count)),
                    self._field("⚠️ CISA KEV", str(kev_count)),
                    self._field("🔥 Exploit Intel", str(patch_count)),
                ],
            }
        ]
        if changes_summary:
            elements.append(
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": f"**📊 Changes Since Last Run**\n{changes_summary}"},
                }
            )
        elements.extend(
            [
                {"tag": "hr"},
                {"tag": "div", "text": {"tag": "lark_md", "content": f"**Top Critical Findings**\n{top_list}"}},
                {"tag": "note", "elements": [{"tag": "plain_text", "content": f"Repo: {repo}"}]},
            ]
        )

        card = {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": "red" if critical_count > 0 else "green",
                "title": {"tag": "plain_text", "content": "📊 VulnRadar Summary"},
            },
            "elements": elements,
        }
        self._post(card)

    def send_baseline(
        self,
        items: list[dict[str, Any]],
        critical_items: list[dict[str, Any]],
        repo: str,
        *,
        vendors: list[str] | None = None,
        products: list[str] | None = None,
    ) -> None:
        """Send a first-run baseline summary to Feishu.

        Args:
            items: All radar items.
            critical_items: Subset of items marked as critical.
            repo: GitHub repository slug.
            vendors: List of monitored vendors from watchlist.
            products: List of monitored products from watchlist.
        """
        total = len(items)
        critical_count = len(critical_items)
        kev_count = sum(1 for i in items if bool(i.get("active_threat")))
        patch_count = sum(1 for i in items if bool(i.get("in_patchthis")))

        sorted_critical = sorted(critical_items, key=lambda x: float(x.get("probability_score") or 0), reverse=True)[
            :10
        ]
        top_list = (
            "\n".join(
                f"{'🔴' if i.get('active_threat') else '⚪'} {self._cve_link(i.get('cve_id', ''))}"
                f" (EPSS: {self._format_epss(i.get('probability_score'))})"
                for i in sorted_critical
            )
            or "No critical findings."
        )

        monitoring_parts = []
        if vendors:
            monitoring_parts.append(f"**Vendors:** {', '.join(vendors)}")
        if products:
            monitoring_parts.append(f"**Products:** {', '.join(products)}")
        monitoring_text = "\n".join(monitoring_parts) if monitoring_parts else "_No watchlist configured_"

        description = (
            "**First run complete!** Your vulnerability baseline has been established.\n\n"
            "Going forward, you'll only receive alerts for:\n"
            "• 🆕 New CVEs matching your watchlist\n"
            "• ⚠️ CVEs added to CISA KEV\n"
            "• 🔥 CVEs added to PatchThis\n"
            "• 📈 Significant EPSS increases"
        )

        card = {
            "config": {"wide_screen_mode": True},
            "header": {
                "template": "green",
                "title": {"tag": "plain_text", "content": "🚀 VulnRadar Baseline Established"},
            },
            "elements": [
                {"tag": "div", "text": {"tag": "lark_md", "content": description}},
                {"tag": "hr"},
                {"tag": "div", "text": {"tag": "lark_md", "content": f"📋 **Monitoring**\n{monitoring_text}"}},
                {
                    "tag": "div",
                    "fields": [
                        self._field("Total CVEs", str(total)),
                        self._field("🚨 Critical", str(critical_count)),
                        self._field("⚠️ CISA KEV", str(kev_count)),
                        self._field("🔥 Exploit Intel", str(patch_count)),
                    ],
                },
                {"tag": "div", "text": {"tag": "lark_md", "content": f"**Top 10 Critical (by EPSS)**\n{top_list}"}},
                {"tag": "note", "elements": [{"tag": "plain_text", "content": repo}]},
            ],
        }
        self._post(card)
