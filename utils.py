"""
This utility module provides helper functions for text cleaning, formatting, and
error handling used across the vulnerability analysis system.

Functions:
    - clean_text: Removes unnecessary whitespace and invisible characters from strings.
    - print_divider: Prints a horizontal divider line for console output formatting.
    - print_header: Prints a formatted header section for CLI interfaces.
    - github_stars_to_rating: Converts GitHub star count to a simple star rating.
    - handle_http_error: Centralized handler for HTTP errors from external APIs (e.g., GitHub, NVD).
"""

import re
import requests

def clean_text(text: str) -> str:
    # Removes leading/trailing whitespace and normalizes all whitespace sequences to a single space.
    text = re.sub(r"\s+", " ", text.strip())
    text = re.sub(r"[\u200b\xa0]", "", text)  # Remove invisible characters
    return text


def print_divider():
    print("-" * 100)


def print_header(title: str):
    print_divider()
    print(f"{title:^100}")
    print_divider()


def github_stars_to_rating(stars: int) -> str:
    if stars >= 1000:
        return "⭐⭐⭐"
    elif stars >= 200:
        return "⭐⭐"
    elif stars >= 50:
        return "⭐"
    else:
        return "-"


def handle_http_error(
        err: requests.exceptions.HTTPError,
        source: str,
        context: str,
        info: str = ""
) -> None:
    """
    Unified HTTP error handler for GitHub, NVD, and other APIs.

    :param err: The HTTPError instance from requests.
    :param source: A short identifier for the API source ('GitHub', 'NVD', etc.).
    :param context: Description of the action being performed ('search', 'metadata', etc.).
    :param info: Additional info like request parameters or URL.
    """
    status = err.response.status_code
    prefix = f"[{source} Error {status}]"

    if status == 400:
        print(f"{prefix} Bad request during {context}.")
        if info:
            print(f"→ Sent info: {info}")
            print(f"→ Please check your request parameters or consult the {source} API documentation.")
        raise ValueError()
    elif status == 401:
        print(f"{prefix} Unauthorized during {context}.")
        print(f"→ Please verify your authentication token or credentials for {source}.")
        raise PermissionError()
    elif status == 403:
        print(f"{prefix} Access denied during {context}.")
        print("→ This may be a temporary issue, rate-limiting, or permission problem.")
        print("Contact the development team if this persists.")
        raise PermissionError()
    elif status == 404:
        print(f"{prefix} Access denied or resource not found during {context} in {source}.")
        print(
            "This may indicate that your authentication token is invalid or lacks the necessary permissions.")
        print("→ Please ensure your token is valid and has the required scopes.")
        print("Contact the development team if this persists.")
        raise PermissionError()
    else:
        print(f"{prefix} Unexpected HTTP error during {context}: {err}")
        raise RuntimeError()
