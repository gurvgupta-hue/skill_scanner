import re
import time
import base64
import unicodedata
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import Optional

import regex

# ── Regex Patterns ─────────────────────────────────────────────────────────────

# §3.1 Tag Block Smuggling: U+E0001–U+E007F
TAG_BLOCK_RE = re.compile(r"[\U000E0001-\U000E007F]+")

# §3.1 Zero-Width characters: ZWSP / ZWNJ / ZWJ
ZW_RE = re.compile(r"[\u200B\u200C\u200D]+")

# §3.1 Sneaky Bits — invisible math operators
SNEAKY_BITS_RE = re.compile(r"[\u2062\u2064]+")

# §3.1 Variation Selectors
VARIATION_SELECTOR_RE = re.compile(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]+")

# §3.1 Bidi Override (Right-to-Left / Left-to-Right overrides only — isolates are separate)
BIDI_RE = re.compile(r"[\u202A-\u202E\u200E\u200F]+")

# §3.1 Emoji (BMP + supplemental ranges used in smuggling detection)
EMOJI_RE = re.compile(r"[\U0001F300-\U0001F9FF\u2600-\u27BF]")

# §3.4 Emoji ligature / modifier sequences — standard sequences to skip
#  skin-tone modifiers U+1F3FB–U+1F3FF, ZWJ family sequences (U+1F46A etc.)
EMOJI_MODIFIER_RE = re.compile(r"[\U0001F3FB-\U0001F3FF]")

# §new Directional Isolate characters (separate category from bidi overrides)
DIRECTIONAL_ISOLATES = re.compile(r"[\u2066\u2067\u2068\u2069]")

# §new Combining diacritical marks (flooding detection)
COMBINING_RE = re.compile(r"[\u0300-\u036F]+")

# §new Base64 payload heuristics — sequences of ≥20 base64 chars
BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")

# §AST04/AST08 ASCII control-character smuggling — non-printable control chars
# that markdown renderers / LLM tokenizers silently discard, making payload
# invisible to reviewers. Excludes standard whitespace: TAB(09), LF(0A), CR(0D).
ASCII_CTRL_RE = re.compile(r"[\x01-\x08\x0B\x0C\x0E-\x1F]+")

# All invisible chars combined — used for density scoring
ALL_INVISIBLE_RE = re.compile(
    r"[\u200B\u200C\u200D"
    r"\u2060\u2062\u2063\u2064"
    r"\uFE00-\uFE0F"
    r"\u202A-\u202E\u2066-\u2069\u200E\u200F"
    r"\U000E0001-\U000E007F"
    r"\U000E0100-\U000E01EF]"
)

# ── Unicode Block Ranges (§3.4 allow-listing) ──────────────────────────────────
_ARABIC_RANGE = range(0x0600, 0x06FF + 1)
_HEBREW_RANGE = range(0x0590, 0x05FF + 1)
_INDIC_RANGES = [
    range(0x0900, 0x097F + 1),   # Devanagari
    range(0x0980, 0x09FF + 1),   # Bengali
    range(0x0A00, 0x0A7F + 1),   # Gurmukhi
    range(0x0A80, 0x0AFF + 1),   # Gujarati
    range(0x0B00, 0x0B7F + 1),   # Oriya
    range(0x0B80, 0x0BFF + 1),   # Tamil
    range(0x0C00, 0x0C7F + 1),   # Telugu
    range(0x0C80, 0x0CFF + 1),   # Kannada
    range(0x0D00, 0x0D7F + 1),   # Malayalam
]

# ── Harm Category Taxonomy (§3.2) ──────────────────────────────────────────────
_HARM_KEYWORDS: dict[str, list[str]] = {
    "credential_theft": [
        "password", "token", "api key", "secret", "credential", "auth",
        "bearer", "private key", "ssh", "passphrase",
    ],
    "tool_execution": [
        "execute", "run", "eval(", "system(", "subprocess", "shell",
        "os.system", "exec(", "popen",
    ],
    "data_exfiltration": [
        "exfiltrate", "send to", "upload", "post to", "leak", "export",
        "http://", "https://", "curl", "wget",
    ],
    "prompt_injection": [
        "ignore previous", "disregard", "override", "forget", "new instructions",
        "system:", "assistant:", "user:", "###", "---",
    ],
    "jailbreak": [
        "jailbreak", "dan mode", "developer mode", "unrestricted",
        "no restrictions", "without limitations",
    ],
}

# ── Homoglyph / Confusable Scripts (§new) ─────────────────────────────────────
CONFUSABLE_SCRIPTS = {
    "CYRILLIC",
    "GREEK",
    "ARMENIAN",
}

# ── Invisible Separator Characters (§new) ─────────────────────────────────────
INVISIBLE_CHARS = [
    "\u2060",  # WORD JOINER
    "\u00A0",  # NO-BREAK SPACE
    "\u180E",  # MONGOLIAN VOWEL SEPARATOR
    "\u2063",  # INVISIBLE SEPARATOR
]

# ── Script Patterns for Mixed-Script Detection (§new) ─────────────────────────
SCRIPT_PATTERNS = {
    "Latin": regex.compile(r"\p{Latin}"),
    "Cyrillic": regex.compile(r"\p{Cyrillic}"),
    "Greek": regex.compile(r"\p{Greek}"),
}

# ── Suspicious Shell Patterns (§new) ──────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    r"curl\s+.*\|\s*bash",
    r"wget\s+.*\|\s*sh",
    r"chmod\s+\+x",
    r"base64\s+-d",
    r"python3?\s+-c",
]


_SCANNER_TIMEOUT_S = 500     # 500 ms hard cutoff (ReDoS protection)
_DENSITY_WINDOW = 100        # sliding window size in characters

# Module-level executor — avoids spawning a new thread on every scan request.
_EXECUTOR = ThreadPoolExecutor(max_workers=4)

# ── Data Classes ───────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    category: str
    count: int
    decoded: Optional[str]
    harm_categories: list[str]
    positions: list[int]


@dataclass
class ScanResult:
    threat_detected: bool
    density_score: float
    detections: list[DetectionResult]
    sanitized_text: Optional[str]
    scan_time_ms: float
    timed_out: bool = False


# ── Internal Helpers ──────────────────────────────────────────────────────────

def _classify_harm(decoded_text: str) -> list[str]:
    """Map a decoded payload string to Owner-Harm categories (§3.2)."""
    lower = decoded_text.lower()
    matched = [cat for cat, kws in _HARM_KEYWORDS.items() if any(kw in lower for kw in kws)]
    return matched or ["unknown_malicious"]


def _in_script_context(text: str, pos: int, match_len: int, window: int = 6) -> bool:
    """
    Returns True if the character at pos is surrounded by Arabic, Hebrew, or
    Indic script characters — indicating legitimate ZWJ/ZWNJ usage (§3.4).
    """
    before = text[max(0, pos - window): pos]
    after = text[pos + match_len: pos + match_len + window]
    for ch in before + after:
        cp = ord(ch)
        if cp in _ARABIC_RANGE or cp in _HEBREW_RANGE:
            return True
        if any(cp in r for r in _INDIC_RANGES):
            return True
    return False


def _is_standard_emoji_ligature(text: str, pos: int) -> bool:
    """
    Returns True if a ZWJ at pos is part of a standard emoji ligature
    (family / skin-tone sequences) and should be exempt (§3.4).
    """
    before_char = text[pos - 1] if pos > 0 else ""
    after_char = text[pos + 1] if pos + 1 < len(text) else ""
    # ZWJ between two emoji codepoints is a standard ligature
    return bool(
        before_char and EMOJI_RE.match(before_char)
        and after_char and EMOJI_RE.match(after_char)
    )


def _decode_tag_block(s: str) -> str:
    """Reverse Tag Block encoding: subtract 0xE0000 to recover ASCII."""
    return "".join(
        chr(ord(ch) - 0xE0000)
        for ch in s
        if 0xE0001 <= ord(ch) <= 0xE007F
    )


def _density_score(text: str) -> float:
    """
    Sliding-window density scoring (§4.1): returns the maximum ratio of
    invisible characters to total characters across any _DENSITY_WINDOW-char window.
    """
    if not text:
        return 0.0
    n = len(text)
    step = _DENSITY_WINDOW // 2
    max_density = 0.0
    for i in range(0, n, step):
        window = text[i: i + _DENSITY_WINDOW]
        if not window:
            break
        invisible = sum(1 for ch in window if ALL_INVISIBLE_RE.match(ch))
        density = invisible / len(window)
        if density > max_density:
            max_density = density
    return round(max_density, 4)


def _sanitize(text: str) -> str:
    """Strip all steganographic invisible Unicode characters (§3.3)."""
    return ALL_INVISIBLE_RE.sub("", text)


# ── Additional Detection Functions (§new) ─────────────────────────────────────

def detect_confusables(text: str) -> list[dict]:
    """Detect homoglyph/confusable characters from non-Latin scripts."""
    detections = []
    for idx, ch in enumerate(text):
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        if any(script in name for script in CONFUSABLE_SCRIPTS):
            detections.append({
                "category": "unicode_confusable",
                "char": ch,
                "unicode": hex(ord(ch)),
                "position": idx,
            })
    return detections


def detect_mixed_scripts(token: str) -> bool:
    """Return True if *token* contains characters from more than one script."""
    present = set()
    for script, pattern in SCRIPT_PATTERNS.items():
        if pattern.search(token):
            present.add(script)
    return len(present) > 1


def detect_invisible_chars(text: str) -> list[dict]:
    """Detect invisible separator characters."""
    results = []
    for idx, ch in enumerate(text):
        if ch in INVISIBLE_CHARS:
            results.append({
                "category": "invisible_separator",
                "char": repr(ch),
                "position": idx,
            })
    return results


def normalization_diff(text: str) -> Optional[dict]:
    """Detect Unicode normalization evasion via NFKC mismatch."""
    nfkc = unicodedata.normalize("NFKC", text)
    if text != nfkc:
        return {
            "category": "unicode_normalization_evasion",
            "original_len": len(text),
            "normalized_len": len(nfkc),
        }
    return None


def detect_combining_abuse(text: str) -> list[dict]:
    """Detect excessive combining diacritic marks used to obscure text."""
    detections = []
    for m in COMBINING_RE.finditer(text):
        if len(m.group()) >= 3:
            detections.append({
                "category": "combining_char_abuse",
                "count": len(m.group()),
                "position": m.start(),
            })
    return detections


def detect_base64_payloads(text: str) -> list[dict]:
    """Detect Base64-encoded shell commands embedded in text."""
    detections = []
    for m in BASE64_RE.finditer(text):
        s = m.group()
        # Pad to a multiple of 4 to avoid decode errors on truncated strings
        padding = (4 - len(s) % 4) % 4
        try:
            decoded = base64.b64decode(s + "=" * padding).decode("utf-8", errors="ignore")
            if any(cmd in decoded for cmd in ["curl", "wget", "bash", "sh ", "chmod"]):
                detections.append({
                    "category": "encoded_command",
                    "decoded": decoded,
                    "position": m.start(),
                })
        except Exception:
            pass
    return detections


def detect_shell_patterns(text: str) -> list[dict]:
    """Detect shell command injection patterns."""
    detections = []
    for pat in SUSPICIOUS_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            detections.append({
                "category": "suspicious_shell_pattern",
                "pattern": pat,
                "position": m.start(),
            })
    return detections


# ── Core Detection ─────────────────────────────────────────────────────────────

def _run_detections(text: str) -> tuple[list[DetectionResult], float]:
    """Execute all detectors and return (detections, density_score)."""
    detections: list[DetectionResult] = []

    print("Running detections on text of length", len(text))

    # 1. Tag Block Smuggling ─────────────────────────────────────────────────
    for m in TAG_BLOCK_RE.finditer(text):
        decoded = _decode_tag_block(m.group())
        detections.append(DetectionResult(
            category="tag_block_smuggling",
            count=len(m.group()),
            decoded=decoded,
            harm_categories=_classify_harm(decoded),
            positions=[m.start()],
        ))

    print(f"Tag Block Smuggling: found {len(detections)} detections so far")

    # 2. Zero-Width Characters (with script allow-listing) ───────────────────
    for m in ZW_RE.finditer(text):
        raw = m.group()
        # U+200B is never legitimate; ZWJ/ZWNJ require script context
        has_zwsp = "\u200B" in raw
        in_ligature = (
            "\u200D" in raw
            and not has_zwsp
            and _is_standard_emoji_ligature(text, m.start())
        )
        in_script = (
            not has_zwsp
            and not in_ligature
            and _in_script_context(text, m.start(), len(raw))
        )
        if in_ligature or in_script:
            continue
        detections.append(DetectionResult(
            category="zero_width_chars",
            count=len(raw),
            decoded=None,
            harm_categories=["unknown_malicious"],
            positions=[m.start()],
        ))

    print(f"Zero-Width Characters: found {len(detections)} detections so far")

    # 3. Sneaky Bits (invisible math operators) ───────────────────────────────
    for m in SNEAKY_BITS_RE.finditer(text):
        detections.append(DetectionResult(
            category="sneaky_bits",
            count=len(m.group()),
            decoded=None,
            harm_categories=["unknown_malicious"],
            positions=[m.start()],
        ))

    print(f"Sneaky Bits: found {len(detections)} detections so far")

    # 4. Variation Selectors ──────────────────────────────────────────────────
    for m in VARIATION_SELECTOR_RE.finditer(text):
        # VS1–VS16 (U+FE00–FE0F) are standard in emoji; only flag if anomalous
        raw = m.group()
        if all(0xFE00 <= ord(ch) <= 0xFE0F for ch in raw):
            # Standard VS next to an emoji — exempt
            before = text[max(0, m.start() - 1): m.start()]
            if before and EMOJI_RE.match(before):
                continue
        detections.append(DetectionResult(
            category="variation_selectors",
            count=len(raw),
            decoded=None,
            harm_categories=["unknown_malicious"],
            positions=[m.start()],
        ))

    print(f"Variation Selectors: found {len(detections)} detections so far")

    # 5. Bidi Override ────────────────────────────────────────────────────────
    for m in BIDI_RE.finditer(text):
        detections.append(DetectionResult(
            category="bidi_override",
            count=len(m.group()),
            decoded=None,
            harm_categories=["prompt_injection"],
            positions=[m.start()],
        ))

    print(f"Bidi Override: found {len(detections)} detections so far")

    # 6. Emoji Smuggling — ZW chars clustered around emoji (§3.1) ───────────
    emoji_positions = [m.start() for m in EMOJI_RE.finditer(text)]
    if emoji_positions:
        zw_near_emoji = 0
        for ep in emoji_positions:
            window = text[max(0, ep - 2): ep + 3]
            if ZW_RE.search(window) or SNEAKY_BITS_RE.search(window):
                # Exempt skin-tone modifiers following an emoji
                if not EMOJI_MODIFIER_RE.search(window):
                    zw_near_emoji += 1
        ratio = zw_near_emoji / len(emoji_positions)
        if zw_near_emoji > 0 and ratio > 0.3:
            detections.append(DetectionResult(
                category="emoji_smuggling",
                count=zw_near_emoji,
                decoded=None,
                harm_categories=["unknown_malicious"],
                positions=emoji_positions[:10],
            ))

    print(f"Emoji Smuggling: found {len(detections)} detections so far")

    # 7. Confusable / Homoglyph characters ───────────────────────────────────
    confusable_hits = detect_confusables(text)
    if confusable_hits:
        detections.append(DetectionResult(
            category="unicode_confusable",
            count=len(confusable_hits),
            decoded=None,
            harm_categories=["prompt_injection"],
            positions=[h["position"] for h in confusable_hits],
        ))

    print(f"Confusables: found {len(detections)} detections so far")

    # 8. Mixed-script tokens (identifiers, commands, URLs) ───────────────────
    mixed_positions = []
    for m in re.finditer(r"\S+", text):
        if detect_mixed_scripts(m.group()):
            mixed_positions.append(m.start())
    if mixed_positions:
        detections.append(DetectionResult(
            category="mixed_script",
            count=len(mixed_positions),
            decoded=None,
            harm_categories=["prompt_injection"],
            positions=mixed_positions,
        ))

    print(f"Mixed Script: found {len(detections)} detections so far")

    # 9. Invisible Separators ─────────────────────────────────────────────────
    invisible_hits = detect_invisible_chars(text)
    if invisible_hits:
        detections.append(DetectionResult(
            category="invisible_separator",
            count=len(invisible_hits),
            decoded=None,
            harm_categories=["unknown_malicious"],
            positions=[h["position"] for h in invisible_hits],
        ))

    print(f"Invisible Separators: found {len(detections)} detections so far")

    # 10. Unicode Normalization Mismatch ──────────────────────────────────────
    norm_result = normalization_diff(text)
    if norm_result:
        detections.append(DetectionResult(
            category="unicode_normalization_evasion",
            count=norm_result["original_len"] - norm_result["normalized_len"],
            decoded=None,
            harm_categories=["prompt_injection"],
            positions=[],
        ))

    print(f"Normalization Mismatch: found {len(detections)} detections so far")

    # 11. Directional Isolates ────────────────────────────────────────────────
    for m in DIRECTIONAL_ISOLATES.finditer(text):
        detections.append(DetectionResult(
            category="directional_isolate",
            count=1,
            decoded=None,
            harm_categories=["prompt_injection"],
            positions=[m.start()],
        ))

    print(f"Directional Isolates: found {len(detections)} detections so far")

    # 12. Combining Character Flooding ────────────────────────────────────────
    combining_hits = detect_combining_abuse(text)
    if combining_hits:
        detections.append(DetectionResult(
            category="combining_char_abuse",
            count=sum(h["count"] for h in combining_hits),
            decoded=None,
            harm_categories=["unknown_malicious"],
            positions=[h["position"] for h in combining_hits],
        ))

    print(f"Combining Abuse: found {len(detections)} detections so far")

    # 13. Base64 Encoded Commands ─────────────────────────────────────────────
    b64_hits = detect_base64_payloads(text)
    for hit in b64_hits:
        detections.append(DetectionResult(
            category="encoded_command",
            count=1,
            decoded=hit["decoded"],
            harm_categories=_classify_harm(hit["decoded"]),
            positions=[hit["position"]],
        ))

    print(f"Base64 Payloads: found {len(detections)} detections so far")

    # 14. Suspicious Shell Patterns ───────────────────────────────────────────
    shell_hits = detect_shell_patterns(text)
    if shell_hits:
        detections.append(DetectionResult(
            category="suspicious_shell_pattern",
            count=len(shell_hits),
            decoded=None,
            harm_categories=["tool_execution"],
            positions=[h["position"] for h in shell_hits],
        ))

    print(f"Shell Patterns: found {len(detections)} detections so far")

    # 15. ASCII Control Character Smuggling (AST04/AST08) ────────────────────
    # Snyk ToxicSkills confirmed these hide malicious instructions from human
    # reviewers while remaining visible to the LLM/agent prompt compiler.
    ascii_ctrl_hits = [
        (m.start(), len(m.group()))
        for m in ASCII_CTRL_RE.finditer(text)
    ]
    if ascii_ctrl_hits:
        detections.append(DetectionResult(
            category="ascii_ctrl_smuggling",
            count=sum(l for _, l in ascii_ctrl_hits),
            decoded=None,
            harm_categories=["prompt_injection", "unknown_malicious"],
            positions=[pos for pos, _ in ascii_ctrl_hits],
        ))

    print(f"ASCII Ctrl Smuggling: found {len(detections)} detections so far")

    density = _density_score(text)
    print(f"Density Score: {density}")
    return detections, density


# ── Public API ─────────────────────────────────────────────────────────────────

def scan(
    text: str,
    mode: str = "strict",
    density_threshold: float = 0.01,
) -> ScanResult:
    """
    Scan *text* for steganographic Unicode payloads.

    Parameters
    ----------
    text : str
        The content to scan.  Processed in-memory and never persisted (§4.2).
    mode : {"strict", "sanitize", "report"}
        - strict   : fail-closed — threat → blocked status
        - sanitize : strip invisible chars, return clean text
        - report   : scan and report, never block
    density_threshold : float
        Invisible-char ratio that independently triggers a threat flag (§4.1).

    Returns
    -------
    ScanResult
    """
    start = time.perf_counter()
    timed_out = False

    # §4.2 ReDoS Defence: enforce scanner timeout via thread future
    try:
        future = _EXECUTOR.submit(_run_detections, text)
        detections, density = future.result(timeout=_SCANNER_TIMEOUT_S)
    except FuturesTimeoutError:
        timed_out = True
        detections = []
        density = 0.0
        if mode == "strict":
            # Fail-closed: timeout itself is treated as a threat
            detections = [DetectionResult(
                category="scanner_timeout",
                count=0,
                decoded=None,
                harm_categories=["scanner_error"],
                positions=[],
            )]

    scan_time_ms = round((time.perf_counter() - start) * 1000, 3)
    threat_detected = bool(detections) or density > density_threshold

    sanitized_text: Optional[str] = None
    if mode == "sanitize" or (mode == "strict" and threat_detected):
        sanitized_text = _sanitize(text)

    return ScanResult(
        threat_detected=threat_detected,
        density_score=density,
        detections=detections,
        sanitized_text=sanitized_text,
        scan_time_ms=scan_time_ms,
        timed_out=timed_out,
    )
