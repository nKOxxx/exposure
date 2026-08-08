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

# Path segments that are not usernames.
_NON_USER_SEGMENTS = {
    "in", "pub", "company", "watch", "channel", "user", "u", "r", "feed", "posts",
}


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
    segments = [s for s in parts.path.split("/") if s]
    username: str | None = None
    for seg in segments:
        low = seg.lower()
        if low in _NON_USER_SEGMENTS:
            continue
        if seg.startswith("@"):
            seg = seg[1:]
        if seg and "." not in seg:
            username = seg
            break
    return platform, username
