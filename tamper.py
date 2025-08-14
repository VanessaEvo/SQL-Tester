"""
tamper.py - A module for payload tampering and evasion techniques.
"""

import random

def space_to_comment(payload: str) -> str:
    """
    Replaces spaces with comments.
    Example: 'SELECT id FROM users' -> 'SELECT/**/id/**/FROM/**/users'
    """
    return payload.replace(" ", "/**/")

def random_case(payload: str) -> str:
    """
    Applies random case to the payload.
    Example: 'SELECT' -> 'SeLeCt'
    """
    return "".join(random.choice([c.upper(), c.lower()]) for c in payload)

# Add more tamper scripts here in the future
# def another_tamper_script(payload: str) -> str:
#     ...

def get_tamper_scripts():
    """
    Returns a dictionary of available tamper scripts for the GUI.
    The key is the user-facing name, and the value is the function itself.
    """
    return {
        "None": None,  # Option to not use any script
        "Space to Comment": space_to_comment,
        "Random Case": random_case,
    }
