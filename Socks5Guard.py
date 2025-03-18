import sys
import requests
import socket
import socks
import random
import time
import json
import logging
import os
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify
from dotenv import load_dotenv


load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

app = Flask(__name__)

checked_proxies = set()
blacklist = set()
not_working = set()


logging.basicConfig(filename="proxy_log.txt", level=logging.DEBUG, 
                    format="%(asctime)s - %(levelname)s - %(message)s")

def debug(msg):
    logging.debug(msg)
    print(f"[DEBUG] {msg}")

def get_random_user_agent():
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        debug("Missing API key for AbuseIPDB!")
        return False

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        abuse_score = data["data"].get("abuseConfidenceScore", 0)

        if abuse_score > 50:
            debug(f"Proxy {ip} is highly abusive ({abuse_score}%). Adding to blacklist.")
            blacklist.add(ip)
        elif abuse_score > 10:
            debug(f"Proxy {ip} has a moderate abuse probability ({abuse_score}%).")
        else:
            debug(f"Proxy {ip} appears clean ({abuse_score}%).")
        
        return abuse_score > 50
    except requests.exceptions.RequestException as e:
        debug(f"AbuseIPDB query failed for {ip}: {e}")
        return False

def check_proxy(proxy):
    if proxy in checked_proxies:
        return None
    
    checked_proxies.add(proxy)
    
    try:
        ip, port = proxy.split(":")
        if not port.isdigit():
            debug(f"Invalid port format for proxy {proxy}")
            return None
        port = int(port)
        
        socks.setdefaultproxy(socks.SOCKS5, ip, port)
        s = socks.socksocket()
        s.settimeout(10)
        
        try:
            s.connect(("1.1.1.1", 80))
        except socket.error:
            debug(f"Proxy {proxy} failed - Cannot establish connection.")
            not_working.add(proxy)
            return None
        s.close()
        
        test_url = "https://httpbin.org/ip"
        proxies = {"http": f"socks5h://{proxy}", "https": f"socks5h://{proxy}"}
        response = requests.get(test_url, proxies=proxies, timeout=10)
        
        if response.status_code == 200 and ip in response.text:
            is_malicious = check_abuseipdb(ip)
            if is_malicious:
                debug(f"Proxy {proxy} is confirmed malicious.")
                blacklist.add(proxy)
            else:
                debug(f"Proxy {proxy} works and is not marked as malicious.")
            return proxy
        else:
            debug(f"Proxy {proxy} does not properly forward traffic.")
            not_working.add(proxy)
    except Exception as e:
        debug(f"Proxy {proxy} failed - {e}")
        not_working.add(proxy)
    return None

def save_lists():
    with open("blacklist.json", "w") as f:
        json.dump(list(blacklist), f, indent=4)

    with open("not_working.json", "w") as f:
        json.dump(list(not_working), f, indent=4)

@app.route("/blacklist", methods=["GET"])
def get_blacklist():
    return jsonify(list(blacklist))

@app.route("/not_working", methods=["GET"])
def get_not_working():
    return jsonify(list(not_working))

def worker(proxy_list):
    max_threads = min(50, len(proxy_list)) 
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_proxy, proxy): proxy for proxy in proxy_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                debug(f"Successfully verified proxy: {result}")

if __name__ == "__main__":
    from threading import Thread
    api_thread = Thread(target=lambda: app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True))
    api_thread.start()

    while True:
        proxy_list = ["123.45.67.89:1080", "98.76.54.32:1080"]  
        debug("Starting proxy validation...")
        worker(proxy_list)
        save_lists()
        time.sleep(30)

