"""Offline geolocation enrichment for proxy lists.

This module reads proxy inputs from JSON or plain text, resolves geolocation
(city/country) via IPInfo, and writes enriched JSON output.

High-level purpose:
- Convert raw proxy entries into structured ``{"proxy", "location"}`` records.
- Support interoperability with outputs from Socks5Guard.

Execution model:
- Standalone CLI utility.
- Synchronous, sequential processing of proxy entries.

Security considerations:
- Uses outbound API calls to IPInfo; errors degrade to "Unknown" values.
- No input execution or shell invocation.
- Reads local files and writes derived output beside input file.

Threading model:
- Single-threaded; no shared mutable state across threads.

Limitations:
- Blocking network I/O can be slow on large datasets.
- Requires ``IPINFO_API_KEY`` for reliable geolocation quality.
- Does not validate whether proxies are functional.

Production warning:
- Designed for offline enrichment workflows. For large-scale enrichment, add
  batching, retries with backoff, and explicit request throttling.
"""

import requests
import sys
import os
import json
from dotenv import load_dotenv
from typing import Any

load_dotenv()
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")


def get_proxy_location(ip: str) -> str:
    """Resolve proxy IP to ``"City, Country"`` using IPInfo.

    Args:
        ip (str): IP address extracted from a proxy entry.

    Returns:
        str: ``"City, Country"`` string, or ``"Unknown, Unknown"`` on failure.

    Raises:
        None. Network and JSON parsing issues are handled internally.

    Thread Safety:
        Thread-safe; no shared mutable state is touched.

    Side Effects:
        Performs outbound HTTP request to IPInfo.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}", timeout=5)
        data = response.json()
        city = data.get("city", "Unknown")
        country = data.get("country", "Unknown")
        return f"{city}, {country}"
    except (requests.RequestException, ValueError):
        return "Unknown, Unknown"


def load_proxy_list(input_file: str) -> list[str]:
    """Load proxy entries from JSON or line-delimited text.

    Accepted JSON forms:
    - List[str]
    - List[dict] with ``proxy`` or ``ip`` keys
    - Dict with ``proxy`` or ``ip`` key
    - String scalar containing a single proxy entry

    Args:
        input_file (str): Path to input data file.

    Returns:
        list[str]: Parsed proxy entries.

    Raises:
        OSError: If file read fails.

    Thread Safety:
        Thread-safe; operates on local variables only.

    Side Effects:
        Reads local input file content.
    """
    with open(input_file, "r") as infile:
        content = infile.read()

    stripped = content.strip()
    if not stripped:
        return []

    try:
        data: Any = json.loads(stripped)
    except json.JSONDecodeError:
        data = None

    if data is not None:
        if isinstance(data, list):
            proxies: list[str] = []
            for entry in data:
                if isinstance(entry, str):
                    proxies.append(entry)
                elif isinstance(entry, dict):
                    proxy_value = entry.get("proxy") or entry.get("ip")
                    if proxy_value:
                        proxies.append(proxy_value)
            return proxies
        if isinstance(data, dict):
            proxy_value = data.get("proxy") or data.get("ip")
            if isinstance(proxy_value, str) and proxy_value.strip():
                return [proxy_value.strip()]
            return []
        if isinstance(data, str):
            proxy_value = data.strip()
            if proxy_value:
                return [proxy_value]
            return []
        return []

    return [line.strip() for line in content.splitlines() if line.strip()]


def process_proxies(input_file: str) -> None:
    """Process input proxies and write enriched JSON output.

    Args:
        input_file (str): Path to input file containing proxy entries.

    Returns:
        None.

    Raises:
        SystemExit: If input file does not exist.
        OSError: If output write fails.

    Thread Safety:
        Thread-safe in current single-threaded execution model.

    Side Effects:
        - Reads input file.
        - Performs outbound geolocation requests.
        - Writes ``<input>_with_city.json`` output file.
        - Writes progress/status to stdout.
    """
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found!")
        sys.exit(1)

    output_file = f"{os.path.splitext(input_file)[0]}_with_city.json"
    proxy_data: list[dict[str, str]] = []
    proxy_list = load_proxy_list(input_file)
    if not proxy_list:
        print(f"No proxies found in '{input_file}'.")

    for proxy in proxy_list:
        if ":" in proxy:
            ip = proxy.split(":")[0]
            location = get_proxy_location(ip)
            proxy_entry = {"proxy": proxy, "location": location}
            proxy_data.append(proxy_entry)
            print(proxy_entry)
        else:
            print(f"Skipping invalid proxy entry: '{proxy}' (expected ip:port).")

    with open(output_file, "w") as outfile:
        json.dump(proxy_data, outfile, indent=4)

    print(f"Results saved in: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python Socks5GeoChecker.py <input_file.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    process_proxies(input_file)
