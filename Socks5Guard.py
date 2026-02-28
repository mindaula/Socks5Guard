"""Socks5Guard service: SOCKS5 proxy validation, abuse scoring, and API exposure.

This module runs a continuous validation loop over a configured proxy list,
classifies proxies as malicious/non-working, persists results to JSON files, and
exposes read endpoints via Flask.

High-level purpose:
- Validate SOCKS5 proxies with connectivity and HTTP forwarding checks.
- Query AbuseIPDB to classify high-confidence abusive proxies.
- Persist blacklist and non-working lists for downstream systems.
- Provide authenticated API access to current in-memory state.

Execution model:
- Loads environment configuration at import time.
- Starts Flask in a background daemon thread when executed as `__main__`.
- Runs a periodic worker loop in the main thread.
- Uses a ThreadPoolExecutor per batch for proxy checks.

Security considerations:
- API access is fail-closed when `API_KEY` is missing.
- API key validation is strict and constant-time compared.
- `/shutdown` is localhost-only and authenticated.
- AbuseIPDB lookup failures are treated as unknown reputation, not malicious.

Threading model:
- Shared mutable sets (`checked_proxies`, `blacklist`, `not_working`) are guarded
  by a single lock.
- Proxy validation uses bounded worker threads.
- External network concurrency is additionally constrained by a semaphore.

Limitations:
- Uses blocking network I/O.
- Uses Flask development server semantics when run directly.
- Proxy source is currently a static list in code.

Production warning:
- This module is suitable for controlled/internal environments. For internet-
  facing deployment, use a hardened WSGI stack, reverse proxy protections,
  structured logging, and rate limiting.
"""

import sys
import json
import logging
import os
import socket
import tempfile
from hmac import compare_digest
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import import_module
from threading import Event, Lock, Semaphore, Thread
from typing import Any, Optional


def require_module(name: str, package_name: Optional[str] = None) -> Any:
    """Import a required dependency and exit with a clear message if missing.

    Args:
        name (str): Import name passed to ``import_module``.
        package_name (Optional[str]): Installation package name shown in error
            output when different from import name.

    Returns:
        Any: Imported module object.

    Raises:
        SystemExit: Always raised if the import fails.

    Thread Safety:
        Thread-safe. Uses no shared mutable state.

    Side Effects:
        - Writes diagnostic output to stderr on missing dependency.
        - Terminates process startup on missing dependency.
    """
    try:
        return import_module(name)
    except ImportError as exc:
        pkg = package_name or name
        message = (
            f"Missing dependency '{name}'. Install it via 'pip install {pkg}' "
            "or 'pip install -r requirements.txt'."
        )
        print(message, file=sys.stderr)
        raise SystemExit(message) from exc


def parse_positive_int(env_key: str, default: int) -> int:
    """Parse a positive integer from environment, falling back safely.

    Args:
        env_key (str): Environment variable key.
        default (int): Fallback value when key is absent or invalid.

    Returns:
        int: Parsed positive integer, minimum ``1``, or ``default``.

    Raises:
        None.

    Thread Safety:
        Thread-safe. Reads process environment only.

    Side Effects:
        None.
    """
    variable = os.getenv(env_key)
    if variable is None:
        return default
    try:
        return max(1, int(variable))
    except ValueError:
        return default


requests = require_module("requests")
socks = require_module("socks", "PySocks")
flask_module = require_module("flask")
Flask = flask_module.Flask
jsonify = flask_module.jsonify
request = flask_module.request
dotenv_module = require_module("dotenv")
load_dotenv = dotenv_module.load_dotenv

# Load .env before reading any runtime configuration to avoid silent
# misconfiguration of security-sensitive values.
load_dotenv()

MAX_PROXY_LIMIT = parse_positive_int("MAX_PROXY_LIMIT", 5000)
MAX_THREAD_HARD_LIMIT = 200
MAX_PROXY_THREADS = min(
    parse_positive_int("MAX_PROXY_THREADS", 50),
    MAX_THREAD_HARD_LIMIT,
)
MAX_EXTERNAL_CONCURRENCY = parse_positive_int("MAX_EXTERNAL_CONCURRENCY", 4)
API_KEY = os.getenv("API_KEY")
external_semaphore = Semaphore(MAX_EXTERNAL_CONCURRENCY)
stop_event = Event()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

app = Flask(__name__)

checked_proxies: set[str] = set()
blacklist: set[str] = set()
not_working: set[str] = set()
# Single lock prevents races while mutating or snapshotting shared sets used by
# concurrent worker threads and API request handlers.
data_lock = Lock()


def snapshot_set(target_set: set[str]) -> list[str]:
    """Create a deterministic snapshot of a shared proxy set.

    Args:
        target_set (set[str]): Shared mutable set to snapshot.

    Returns:
        list[str]: Sorted list copy of entries.

    Raises:
        None.

    Thread Safety:
        Acquires ``data_lock`` while reading shared state.

    Side Effects:
        None.
    """
    with data_lock:
        # Sorting guarantees deterministic API and file outputs, which is
        # important for reproducible automation and stable diffs.
        return sorted(target_set)


def register_proxy(proxy: str) -> bool:
    """Register a proxy as processed for the current worker pass.

    Args:
        proxy (str): Proxy endpoint in ``ip:port`` format.

    Returns:
        bool: ``True`` if newly registered; ``False`` if already seen.

    Raises:
        None.

    Thread Safety:
        Acquires ``data_lock`` to mutate ``checked_proxies`` safely.

    Side Effects:
        Mutates global ``checked_proxies``.
    """
    with data_lock:
        if proxy in checked_proxies:
            return False
        checked_proxies.add(proxy)
        return True


def reset_checked_proxies() -> None:
    """Clear per-run de-duplication state.

    Args:
        None.

    Returns:
        None.

    Raises:
        None.

    Thread Safety:
        Acquires ``data_lock`` to clear shared state safely.

    Side Effects:
        Clears global ``checked_proxies``.
    """
    with data_lock:
        checked_proxies.clear()


def mark_blacklist(entry: str) -> None:
    """Add a proxy entry to the global blacklist set.

    Args:
        entry (str): Proxy entry to classify as malicious.

    Returns:
        None.

    Raises:
        None.

    Thread Safety:
        Acquires ``data_lock`` to mutate shared set safely.

    Side Effects:
        Mutates global ``blacklist``.
    """
    with data_lock:
        blacklist.add(entry)


def mark_not_working(entry: str) -> None:
    """Add a proxy entry to the global non-working set.

    Args:
        entry (str): Proxy entry that failed validation.

    Returns:
        None.

    Raises:
        None.

    Thread Safety:
        Acquires ``data_lock`` to mutate shared set safely.

    Side Effects:
        Mutates global ``not_working``.
    """
    with data_lock:
        not_working.add(entry)


logging.basicConfig(
    filename="proxy_log.txt",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def debug(msg: str) -> None:
    """Emit debug diagnostics to log file and stdout.

    Args:
        msg (str): Debug message.

    Returns:
        None.

    Raises:
        None.

    Thread Safety:
        Relies on logging module thread safety for output serialization.

    Side Effects:
        - Writes to ``proxy_log.txt``.
        - Writes to standard output.
    """
    logging.debug(msg)
    print(f"[DEBUG] {msg}")


# Security commentary:
# Abuse intelligence is advisory; network/API failures must not be interpreted as
# confirmed maliciousness. Returning "unknown" (None) avoids outage-driven false
# positives that can poison downstream blocklists.
def check_abuseipdb(ip: str) -> Optional[bool]:
    """Query AbuseIPDB for abuse confidence classification.

    Args:
        ip (str): IP address to query.

    Returns:
        Optional[bool]:
            - ``True`` if abuse confidence score > 50.
            - ``False`` if score <= 50.
            - ``None`` if lookup cannot be trusted (missing key/error).

    Raises:
        None. Operational exceptions are converted into ``None``.

    Thread Safety:
        Thread-safe for shared state. Uses semaphore to cap outbound query
        concurrency.

    Side Effects:
        Performs outbound HTTP request to AbuseIPDB.
    """
    if not ABUSEIPDB_API_KEY:
        debug("Missing API key for AbuseIPDB. Reputation is unknown.")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        with external_semaphore:
            response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        abuse_score = data["data"].get("abuseConfidenceScore", 0)

        if abuse_score > 50:
            debug(f"Proxy {ip} is highly abusive ({abuse_score}%).")
        elif abuse_score > 10:
            debug(f"Proxy {ip} has a moderate abuse probability ({abuse_score}%).")
        else:
            debug(f"Proxy {ip} appears clean ({abuse_score}%).")

        return abuse_score > 50
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        debug(f"AbuseIPDB query failed for {ip}: {e}. Reputation is unknown.")
        return None


def check_proxy(proxy: str) -> Optional[str]:
    """Validate proxy connectivity, forwarding behavior, and abuse status.

    Args:
        proxy (str): Proxy endpoint in ``ip:port`` format.

    Returns:
        Optional[str]: Proxy string when functional and not blacklisted,
        otherwise ``None``.

    Raises:
        RuntimeError: Unexpected errors from called routines are propagated.

    Thread Safety:
        Uses lock-guarded helpers when mutating shared state.

    Side Effects:
        - Mutates ``checked_proxies``, ``blacklist``, and ``not_working``.
        - Opens and closes outbound sockets.
        - Performs outbound HTTP requests.
    """
    if not register_proxy(proxy):
        return None

    try:
        ip, port = proxy.split(":")
    except ValueError as exc:
        debug(f"Proxy {proxy} failed - {exc}")
        mark_not_working(proxy)
        return None

    if not port.isdigit():
        debug(f"Invalid port format for proxy {proxy}")
        mark_not_working(proxy)
        return None
    port = int(port)

    s = socks.socksocket()
    try:
        s.set_proxy(socks.SOCKS5, ip, port)
        s.settimeout(10)
        with external_semaphore:
            s.connect(("1.1.1.1", 80))
    except OSError as exc:
        debug(f"Proxy {proxy} failed - Cannot establish connection ({exc}).")
        mark_not_working(proxy)
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass

    test_url = "https://httpbin.org/ip"
    proxies = {"http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"}
    try:
        with external_semaphore:
            response = requests.get(test_url, proxies=proxies, timeout=10)
    except requests.exceptions.RequestException as exc:
        debug(f"Proxy {proxy} failed - HTTP forwarding check failed ({exc}).")
        mark_not_working(proxy)
        return None

    if response.status_code == 200 and ip in response.text:
        is_malicious = check_abuseipdb(ip)
        if is_malicious is True:
            debug(f"Proxy {proxy} is confirmed malicious.")
            mark_blacklist(proxy)
        elif is_malicious is False:
            debug(f"Proxy {proxy} works and is not marked as malicious.")
            return proxy
        else:
            debug(f"Proxy {proxy} works but AbuseIPDB status is unknown.")
            return proxy
    else:
        debug(f"Proxy {proxy} does not properly forward traffic.")
        mark_not_working(proxy)
    return None


def atomic_write_json(path: str, payload: list[str]) -> None:
    """Persist JSON payload atomically to avoid partial file readers.

    Args:
        path (str): Destination file path.
        payload (list[str]): Serializable list payload.

    Returns:
        None.

    Raises:
        OSError: Propagated if temp file creation or replace fails.

    Thread Safety:
        Safe for concurrent callers at filesystem level for single target path,
        but callers should avoid write contention to the same file.

    Side Effects:
        - Creates a temporary file in destination directory.
        - Writes JSON data and fsyncs.
        - Atomically replaces destination file.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as tmp_file:
            json.dump(payload, tmp_file, indent=4)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
            tmp_path = tmp_file.name
        os.replace(tmp_path, path)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def save_lists() -> None:
    """Write blacklist and non-working snapshots to disk.

    Args:
        None.

    Returns:
        None.

    Raises:
        OSError: Propagated from file write operations.

    Thread Safety:
        Snapshot acquisition is lock-protected; file writes are independent.

    Side Effects:
        Writes ``blacklist.json`` and ``not_working.json``.
    """
    blacklist_snapshot = snapshot_set(blacklist)
    not_working_snapshot = snapshot_set(not_working)

    atomic_write_json("blacklist.json", blacklist_snapshot)
    atomic_write_json("not_working.json", not_working_snapshot)


# Security commentary:
# The API is fail-closed by design. If `API_KEY` is absent, endpoints return
# 503 rather than exposing data without authentication. This prevents accidental
# open access during deployment misconfiguration.
def enforce_api_key() -> Optional[Any]:
    """Enforce strict API key authentication for protected endpoints.

    Args:
        None. Reads request headers from Flask context.

    Returns:
        Optional[Any]: ``None`` when authorized; Flask response tuple otherwise.

    Raises:
        None.

    Thread Safety:
        Safe for concurrent requests; reads immutable configuration only.

    Side Effects:
        None.
    """
    if not API_KEY:
        return jsonify({"error": "Service unavailable: API key not configured"}), 503
    provided = request.headers.get("X-API-KEY")
    # Constant-time comparison reduces side-channel leakage for key matching.
    if provided and compare_digest(provided, API_KEY):
        return None
    return jsonify({"error": "Unauthorized"}), 401


def is_local_request() -> bool:
    """Check whether the request originated from localhost.

    Args:
        None. Reads Flask request context.

    Returns:
        bool: ``True`` for loopback source addresses, else ``False``.

    Raises:
        None.

    Thread Safety:
        Safe for concurrent requests.

    Side Effects:
        None.
    """
    return request.remote_addr in {"127.0.0.1", "::1"}


@app.route("/blacklist", methods=["GET"])
def get_blacklist() -> Any:
    """Return current blacklist entries.

    Args:
        None.

    Returns:
        Any: Flask JSON response containing a list of proxy strings.

    Raises:
        None.

    Thread Safety:
        Uses lock-protected snapshot helper.

    Side Effects:
        None.
    """
    auth_response = enforce_api_key()
    if auth_response:
        return auth_response
    return jsonify(snapshot_set(blacklist))


@app.route("/not_working", methods=["GET"])
def get_not_working() -> Any:
    """Return current non-working proxy entries.

    Args:
        None.

    Returns:
        Any: Flask JSON response containing a list of proxy strings.

    Raises:
        None.

    Thread Safety:
        Uses lock-protected snapshot helper.

    Side Effects:
        None.
    """
    auth_response = enforce_api_key()
    if auth_response:
        return auth_response
    return jsonify(snapshot_set(not_working))


# Security commentary:
# Shutdown is a sensitive control-plane operation with DoS risk. It is guarded
# by both API key authentication and a localhost source check. It also signals
# `stop_event` so background work exits consistently.
@app.route("/shutdown", methods=["POST"])
def shutdown() -> Any:
    """Request service shutdown from an authenticated local caller.

    Args:
        None.

    Returns:
        Any: Flask JSON response with shutdown status.

    Raises:
        None.

    Thread Safety:
        Safe; toggles thread-safe event and uses request-local context.

    Side Effects:
        - Sets ``stop_event``.
        - May stop Werkzeug server if shutdown hook is available.
    """
    auth_response = enforce_api_key()
    if auth_response:
        return auth_response
    if not is_local_request():
        return jsonify({"error": "Forbidden"}), 403
    # Coordinate API and worker lifecycles through a shared stop signal.
    stop_event.set()
    func = request.environ.get("werkzeug.server.shutdown")
    if not func:
        return jsonify({"status": "shutdown_requested"}), 202
    func()
    return jsonify({"status": "shutdown"}), 200


# Security commentary:
# Threaded validation improves throughput but increases attack surface for
# resource exhaustion. Chunking plus hard thread caps bound CPU/memory pressure
# and prevent complete processing bypass from oversized inputs.
def worker(proxy_list: Optional[list[str]]) -> None:
    """Process proxies in bounded batches using a thread pool.

    Args:
        proxy_list (Optional[list[str]]): Proxy entries to validate.

    Returns:
        None.

    Raises:
        Exception: Propagates unexpected exceptions from worker futures.

    Thread Safety:
        Uses thread-safe helper functions for shared state mutation.

    Side Effects:
        - Clears per-run ``checked_proxies``.
        - Performs network I/O via ``check_proxy``.
        - Emits log output.
    """
    if not proxy_list:
        debug("No proxies provided to worker.")
        return
    reset_checked_proxies()
    if len(proxy_list) > MAX_PROXY_LIMIT:
        debug(
            f"Proxy list size {len(proxy_list)} exceeds the chunk size of {MAX_PROXY_LIMIT}; processing in chunks."
        )
    # Chunking avoids all-or-nothing behavior for large inputs.
    for start in range(0, len(proxy_list), MAX_PROXY_LIMIT):
        batch = proxy_list[start:start + MAX_PROXY_LIMIT]
        max_threads = min(MAX_PROXY_THREADS, len(batch))
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_proxy, proxy): proxy for proxy in batch}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    debug(f"Successfully verified proxy: {result}")


def send_shutdown_signal() -> None:
    """Send an internal shutdown request to the local API server.

    Args:
        None.

    Returns:
        None.

    Raises:
        None. Request failures are logged and suppressed.

    Thread Safety:
        Thread-safe; uses immutable config and local request state.

    Side Effects:
        Performs local HTTP POST to ``/shutdown``.
    """
    headers = {"X-API-KEY": API_KEY} if API_KEY else {}
    try:
        requests.post("http://127.0.0.1:5000/shutdown", headers=headers, timeout=5)
    except requests.RequestException as exc:
        debug(f"Shutdown signal failed: {exc}")


if __name__ == "__main__":
    api_thread = Thread(
        target=lambda: app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,
    )
    api_thread.start()
    stop_event.wait(timeout=1)
    if not api_thread.is_alive():
        debug("API thread failed to start. Stopping service.")
        stop_event.set()

    try:
        while not stop_event.is_set():
            proxy_list = ["123.45.67.89:1080", "98.76.54.32:1080"]
            debug("Starting proxy validation...")
            worker(proxy_list)
            save_lists()
            stop_event.wait(timeout=30)
    except KeyboardInterrupt:
        debug("Shutdown requested by user.")
        stop_event.set()
        send_shutdown_signal()

    api_thread.join(timeout=5)
    debug("Service stopped.")
