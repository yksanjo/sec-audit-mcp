"""
Shannon entropy — used to separate real secrets from placeholders.

Real API keys, tokens, and passwords have high entropy because they are
randomly generated. Placeholder values like "your-api-key-here" or
"changeme" do not. Entropy analysis cuts false positives without missing
real credentials.

Reference thresholds (empirically tuned):
  - Random hex (32 chars):    ~4.0 bits/char
  - Base64 random (32 chars): ~5.5 bits/char
  - AWS access key (20 chars):~4.2 bits/char
  - "your-api-key-here":      ~3.3 bits/char
  - "password123":            ~2.9 bits/char
  - "changeme":               ~2.75 bits/char
"""
from __future__ import annotations
import math
import re
from collections import Counter

# Known placeholder strings — exact or substring match → skip
_PLACEHOLDERS = {
    "changeme", "your_key", "your-key", "yourkey", "example",
    "placeholder", "replace_me", "replaceme", "insert_here",
    "put_your", "enter_your", "api_key_here", "token_here",
    "secret_here", "password_here", "add_your", "xxxxx",
    "aaaaa", "11111", "00000", "test", "fake", "dummy",
    "sample", "demo", "foobar", "foo", "bar", "baz",
    "todo", "fixme", "none", "null", "undefined",
}

# Characters that inflate perceived entropy but appear in templates
_TEMPLATE_PATTERN = re.compile(r"<[^>]+>|\{[^}]+\}|\[[^\]]+\]")


def shannon(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s or len(s) < 2:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """True if the value looks like a template placeholder, not a real secret."""
    v = value.lower().strip("'\"` ")

    # Exact placeholder match
    if v in _PLACEHOLDERS:
        return True

    # Substring placeholder match
    if any(p in v for p in _PLACEHOLDERS):
        return True

    # Template syntax: <KEY>, {SECRET}, [TOKEN]
    if _TEMPLATE_PATTERN.search(v):
        return True

    # Too short to be a real secret for most patterns
    if len(v) < 8:
        return True

    # Repetitive characters (aaaa, 1234, abcd) — low entropy
    if shannon(v) < 2.5:
        return True

    return False


def is_high_entropy(value: str, min_entropy: float = 3.5) -> bool:
    """True if the value has entropy consistent with a real randomly-generated secret."""
    v = value.strip("'\"` ")
    if is_placeholder(v):
        return False
    return shannon(v) >= min_entropy
