"""Notification providers for VulnRadar.

This package implements the Strategy pattern for sending alerts
to different platforms. Each provider extends ``NotificationProvider``
and implements ``send_alert``, ``send_summary``, and ``send_baseline``.

Adding a new provider (e.g., Matrix, PagerDuty) requires only:
1. Create a new file in this package.
2. Subclass ``NotificationProvider``.
3. Register it in ``load_providers()``.
"""

from .base import NotificationProvider
from .feishu import FeishuProvider
from .github_issues import GitHubIssueProvider

__all__ = [
    "NotificationProvider",
    "FeishuProvider",
    "GitHubIssueProvider",
    "load_providers",
    "load_routed_providers",
    "filter_items_for_route",
]


def load_providers(
    *,
    feishu_webhook: str | None = None,
    feishu_max: int = 10,
    feishu_secret: str | None = None,
) -> list[NotificationProvider]:
    """Dynamically create notification providers based on configuration.

    Args:
        feishu_webhook: Feishu bot webhook URL.
        feishu_max: Max individual Feishu alerts per run.
        feishu_secret: Optional Feishu bot signing secret.
            Required if signature verification is enabled on the bot.

    Returns:
        List of active notification providers.
    """
    providers: list[NotificationProvider] = []
    if feishu_webhook:
        providers.append(
            FeishuProvider(webhook_url=feishu_webhook, max_alerts=feishu_max, secret=feishu_secret)
        )
    return providers


def filter_items_for_route(
    items: list[dict],
    route_filter: str,
) -> list[dict]:
    """Filter radar items based on a notification route filter.

    Args:
        items: Full list of radar items.
        route_filter: One of ``all``, ``critical``, ``kev``, ``watchlist``.

    Returns:
        Filtered list of items matching the route's criteria.
    """
    if route_filter == "all":
        return items
    if route_filter == "critical":
        return [i for i in items if bool(i.get("is_critical"))]
    if route_filter == "kev":
        return [i for i in items if bool(i.get("active_threat"))]
    if route_filter == "watchlist":
        return [i for i in items if bool(i.get("watchlist_hit"))]
    return items


def load_routed_providers(
    notifications_config: "NotificationsConfig",  # noqa: F821
) -> list[tuple[NotificationProvider, str]]:
    """Create providers from YAML-based notification routing config.

    Each route produces a separate provider instance with its own
    webhook URL, max alerts, and severity filter.

    Args:
        notifications_config: ``NotificationsConfig`` from the watchlist.

    Returns:
        List of ``(provider, filter_name)`` tuples.
    """
    routed: list[tuple[NotificationProvider, str]] = []

    for route in notifications_config.feishu:
        url = _resolve_env(route.url)
        if url:
            routed.append(
                (
                    FeishuProvider(webhook_url=url, max_alerts=route.max_alerts),
                    route.filter,
                )
            )

    return routed


def _resolve_env(value: str) -> str | None:
    """Resolve ``$ENV_VAR`` references in a string.

    If the value starts with ``$``, look it up in ``os.environ``.
    Otherwise return as-is.  Returns ``None`` if the env var is unset.
    """
    import os

    if value.startswith("$"):
        return os.environ.get(value[1:])
    return value if value else None
