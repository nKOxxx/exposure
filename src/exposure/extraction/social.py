"""Recognition of social-profile links and their usernames.

Deliberately narrow: recognizing a handful of well-known platforms is enough to
classify a link as a social profile and pull the username. We do not attempt to
discover unknown accounts (out of scope, spec section 23).
"""

from __future__ import annotations

from urllib.parse import urlsplit

# domain (registrable) -> platform label
_PLATFORMS = {
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "twitter.com": "Twitter/X",
    "x.com": "Twitter/X",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "mastodon.social": "Mastodon",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "medium.com": "Medium",
    "reddit.com": "Reddit",
    "t.me": "Telegram",
}

# Routing path segments that are never a handle, per platform. Platforms absent
# from this map (Telegram, Twitter/X, Instagram, …) address profiles as a bare
# first segment, so no segment is filtered for them.
_ROUTING_SEGMENTS: dict[str, frozenset[str]] = {
    "LinkedIn": frozenset({"in", "pub", "company", "school", "posts", "feed"}),
    "YouTube": frozenset({"channel", "user", "c", "watch", "playlist", "shorts", "feed"}),
    "Reddit": frozenset({"r", "u", "user", "comments"}),
    "Facebook": frozenset({"pages", "groups", "profile.php", "posts", "watch"}),
    "GitHub": frozenset({"orgs", "topics", "sponsors"}),
    "Medium": frozenset({"tag", "search"}),
    "TikTok": frozenset({"tag", "music"}),
}
_GENERIC_ROUTING = frozenset({"posts", "feed"})


def parse_social(url: str) -> tuple[str, str | None] | None:
    """Return ``(platform, username)`` if ``url`` is a known social profile."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host.startswith("www."):  # strip the prefix, not arbitrary leading w/./chars
        host = host[4:]
    # Match by suffix so subdomains still resolve to the platform.
    platform = None
    for domain, label in _PLATFORMS.items():
        if host == domain or host.endswith("." + domain):
            platform = label
            break
    if platform is None:
        return None
    routing = _ROUTING_SEGMENTS.get(platform, _GENERIC_ROUTING)
    segments = [s for s in parts.path.split("/") if s]
    username: str | None = None
    for seg in segments:
        if seg.lower() in routing:
            continue
        if seg.startswith("@"):
            seg = seg[1:]
        if seg and "." not in seg:
            username = seg
            break
    return platform, username
