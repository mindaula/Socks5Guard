Proxy Scraping and Threat Intelligence Tool



Overview

This tool is specifically designed for cybersecurity purposes, allowing security researchers and system administrators to detect,
validate, and mitigate threats from malicious SOCKS5 proxies. It autonomously scrapes SOCKS5 proxies from various public sources,
validates their functionality, and checks their reputation against [AbuseIPDB](https://www.abuseipdb.com/). The resulting blacklist 
can be integrated into security systems such as firewalls, Intrusion Detection Systems (IDS), and Security Information and 
Event Management (SIEM) solutions to enhance network security.

Features

1. **Autonomous Proxy Scraping**
   - Automatically collects SOCKS5 proxies from multiple public sources without manual intervention.
   
2. **Proxy Validation**
   - Tests the functionality of proxies by attempting connections to a known test server.
   
3. **Threat Intelligence (AbuseIPDB Check)**
   - Compares each proxy's IP address against AbuseIPDB to determine if it has been reported for malicious activity.
   
4. **Flask-based API**
   - Exposes the collected blacklist and non-working proxies for integration with security systems.

5. **Automated Execution**
   - Runs continuously, updating proxy lists and threat intelligence data in real-time.

Requirements
To run this tool, install the following Python libraries:
```sh
pip install requests flask socks BeautifulSoup4 python-dotenv
```

Setup and Usage

1. Get an AbuseIPDB API Key
To use AbuseIPDB for threat intelligence, you need an API key. Follow these steps:

1. **Sign up on AbuseIPDB:**
   - Go to [AbuseIPDB](https://www.abuseipdb.com/) and create an account.
2. **Request an API Key:**
   - After logging in, go to the dashboard and find your API key under the API section.
3. **Insert API Key into `.env` file:**
   - Create a `.env` file in the same directory as the script and add:
   ```
   ABUSEIPDB_API_KEY=your_api_key_here
   ```

2. Running the Flask API
The API provides two endpoints:
- `/blacklist` - Returns all proxies marked as malicious.
- `/not_working` - Returns all proxies that failed validation.

To start the API server:
```sh
python script.py
```
Then access the API using:
```sh
curl http://localhost:5000/blacklist
curl http://localhost:5000/not_working
```

How It Works

1. Scraping Proxies
The script autonomously collects proxies from public sources, ensuring a diverse and extensive dataset.
```python
def scrape_proxies():
    proxy_sources = [
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://www.proxyscan.io/download?type=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://www.socks-proxy.net/"
    ]
```
The script extracts proxies from these sources and compiles them into a list for further processing.

2. Validating Proxies
Each proxy is tested by attempting to connect to a test server. If the connection is successful, the proxy is considered functional.
```python
def check_proxy(proxy):
    try:
        ip, port = proxy.split(":")
        s = socks.socksocket()
        s.settimeout(10)
        s.connect(("1.1.1.1", 80))
```
This step ensures that only working proxies proceed to the next stage.

3. Checking AbuseIPDB
If a proxy is functional, its IP address is checked against AbuseIPDB to determine if it has been flagged as malicious.
```python
def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
```
If an IP address is found to be associated with malicious activity, it is added to the blacklist.

4. Saving Results
Results are stored in JSON files to enable further analysis and integration.
```python
def save_lists():
    with open("blacklist.json", "w") as f:
        json.dump(list(blacklist), f, indent=4)
    with open("not_working.json", "w") as f:
        json.dump(list(not_working), f, indent=4)
```

Integration with Security Systems
Firewall & IDS Integration
The blacklist can be imported into:
- Firewalls (e.g., iptables, pfSense)
- Intrusion Detection Systems (e.g., Suricata, Snort)
- Security Information and Event Management (SIEM) solutions

Example: Blocking Malicious Proxies on Linux Firewall (iptables)
```sh
while read ip; do sudo iptables -A INPUT -s "$ip" -j DROP; done < blacklist.json
```

Real-World Use Cases

1. **Network Security:**
   - Protect corporate networks by blocking known malicious proxies.
2. **Threat Intelligence Research:**
   - Collect and analyze malicious proxy activity.
3. **Intrusion Prevention:**
   - Use blacklist data to prevent attacks from compromised servers.

Conclusion
This tool enables the automated detection and blocking of malicious SOCKS5 proxies, aiding in network security. 
It is intended for security professionals and should only be used for lawful cybersecurity research.
