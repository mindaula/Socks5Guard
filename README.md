Proxy Scraping and Threat Intelligence Tool with Geolocation Enrichment










Overview




This repository contains a comprehensive toolset designed for cybersecurity professionals and network administrators. It consists of two interrelated components:

    Main Tool (Socks5Guard.py):
        Purpose: Scrapes SOCKS5 proxies from various public sources, validates their functionality, checks their reputation against AbuseIPDB, and creates a blacklist of malicious or non-working proxies.
        Security Use-Case: Helps in detecting and blocking potentially dangerous proxies that might be used to circumvent security controls.

    Geo-Enrichment Tool (Socks5GeoChecker.py):
        Purpose: Enhances proxy data by retrieving geographical location details (city and country) using IPInfo. This data is then stored in a JSON file.
        Security Use-Case: Provides additional context by identifying the geographic origin of proxies, allowing administrators to implement region-based security policies or further analyze threat patterns.



Both components work seamlessly together. The main tool gathers and validates proxies, while the geo-enrichment module
enriches this data with location information. Additionally, a Flask-based API exposes the combined data for integration with firewalls,
Intrusion Detection Systems (IDS), and Security Information and Event Management (SIEM) solutions.
Features
Main Tool

    Autonomous Proxy Scraping
        Automatically collects SOCKS5 proxies from multiple public sources without manual intervention.
    Proxy Validation
        Tests the functionality of each proxy by establishing connections to a known test server.
    Threat Intelligence (AbuseIPDB Check)
        Compares each proxy’s IP against AbuseIPDB to identify reported malicious activity.
    Data Persistence
        Saves validated proxies, non-working proxies, and the blacklist to JSON files for further analysis.
    Automated Execution
        Designed to run continuously, ensuring the proxy data is kept up-to-date.



Geo-Enrichment Tool

    Geolocation Lookup
        Retrieves the geographical location (city, country) of each proxy using IPInfo.
    Data Enrichment
        Merges location data with the validated proxy list, creating a comprehensive view.
    Output Format
        Outputs enriched data in JSON format, making it easy to integrate into your security systems.

Combined API

    Flask-Based API Endpoints
        /blacklist: Returns all proxies marked as malicious.
        /not_working: Returns all proxies that failed validation.
        /proxy_locations: Returns the geolocation-enriched proxy data.
    Real-Time Data Access
        Access and integrate the data into existing security workflows with simple HTTP requests.




Requirements



To run this tool, install the following Python libraries. You can use the provided requirements.txt file for convenience.
requirements.txt Content

requests
flask
socks
beautifulsoup4
python-dotenv

Install all dependencies with:

pip install -r requirements.txt

Make sure you have Python 3 installed.
Setup and Usage
1. Configure API Keys
AbuseIPDB API Key




To check proxies against AbuseIPDB:

    Sign Up on AbuseIPDB:
        Visit AbuseIPDB and create an account.
    Request an API Key:
        Log in and find your API key in the dashboard.
    Configure the API Key:
        Create a .env file in the project directory and add:

        ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here




IPInfo API Key



To retrieve proxy geolocation data:

    Sign Up on IPInfo:
        Visit IPInfo and create an account.
    Get Your API Key:
        Retrieve your API token from the IPInfo dashboard.
    Configure the API Key:
        In the same .env file, add:

        IPINFO_API_KEY=your_ipinfo_api_key_here




2. Running the Combined Tools and API

Both components are integrated into a single system. To start the complete solution with the API, run:

python script.py

This will:

    Begin the proxy scraping, validation, and threat intelligence process.
    Enrich the proxy data with geolocation details.
    Start the Flask API server to expose the data.




3. Accessing the API

After starting the server, use the following endpoints:

    Retrieve the Blacklist:

curl http://localhost:5000/blacklist

Retrieve Non-Working Proxies:

curl http://localhost:5000/not_working

Retrieve Geolocation Data for Proxies:

    curl http://localhost:5000/proxy_locations




How It Works



Step 1: Proxy Scraping

The tool automatically scrapes SOCKS5 proxies from multiple sources, such as:

def scrape_proxies():
    proxy_sources = [
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://www.proxyscan.io/download?type=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://www.socks-proxy.net/"
    ]

It compiles these proxies into a list for further processing.
Step 2: Proxy Validation

Each proxy is tested by attempting to connect to a known server. If the connection is successful, the proxy is considered functional:

def check_proxy(proxy):
    try:
        ip, port = proxy.split(":")
        s = socks.socksocket()
        s.settimeout(10)
        s.connect(("1.1.1.1", 80))

This step filters out non-working proxies.
Step 3: AbuseIPDB Check

For every functional proxy, its IP is checked against AbuseIPDB:

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)




If malicious activity is reported, the proxy is added to the blacklist.
Step 4: Geolocation Enrichment

The second tool enriches proxy data with geolocation information:

def get_proxy_location(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}", timeout=5)
    data = response.json()
    city = data.get("city", "Unknown")
    country = data.get("country", "Unknown")
    return f"{city}, {country}"




Each proxy's IP is used to query IPInfo, and the location is merged with the proxy record.
Step 5: Saving and Integrating Data

The tool saves results in JSON format to allow easy integration into external systems:

def save_lists():
    with open("blacklist.json", "w") as f:
        json.dump(list(blacklist), f, indent=4)
    with open("not_working.json", "w") as f:
        json.dump(list(not_working), f, indent=4)
    with open("proxy_locations.json", "w") as f:
        json.dump(proxy_locations, f, indent=4)

Integration with Security Systems
Firewall & IDS Integration

The combined data can be imported into various security systems:

    Firewalls (iptables, pfSense):
        Use the blacklist JSON to drop traffic from malicious IPs.
    Intrusion Detection Systems (Suricata, Snort):
        Feed the validated proxy data into IDS for real-time threat analysis.
    SIEM Solutions:
        Correlate the proxy threat data with other security logs to enhance incident response.




Example: Blocking Proxies with iptables on Linux



while read ip; do sudo iptables -A INPUT -s "$ip" -j DROP; done < blacklist.json

Real-World Use Cases

    Network Security:
        Protect corporate networks by automatically detecting and blocking malicious proxies.
    Threat Intelligence:
        Continuously monitor proxy activity to identify emerging threats.
    Intrusion Prevention:
        Prevent unauthorized access by blocking IPs associated with suspicious behavior.
    Geolocation-Based Policies:
        Implement regional security policies by blocking proxies from high-risk areas.
    SIEM Integration:
        Enrich SIEM data with threat intelligence to enhance situational awareness.




Detailed Workflow and How the Tools Work Together


    Data Collection:
        The main tool scrapes proxies autonomously from several public sources.
    Functionality Verification:
        Each scraped proxy undergoes a connectivity test to ensure it is operational.
    Threat Intelligence Check:
        Operational proxies are then cross-referenced with AbuseIPDB to identify potentially malicious ones.
    Geolocation Enrichment:
        The geo-enrichment module processes the working proxies, retrieving detailed location information via IPInfo.
    Data Consolidation:
        The enriched data (including validated proxies, non-working proxies, and blacklist) is saved as JSON files.
    API Exposure:
        A Flask-based API is started, which exposes endpoints for retrieving the consolidated data:
            /blacklist: Returns proxies flagged as malicious.
            /not_working: Returns proxies that failed validation.
            /proxy_locations: Returns the enriched proxy data, including location details.
    Security Integration:
        The data can be fed directly into security systems (firewalls, IDS, SIEM) to enforce network security policies and monitor threats in real time.




How to Use the API from the Geo-Enrichment Tool

The enriched proxy data is combined with the main tool’s data and exposed via the API. To retrieve the geolocation details:

    Start the Combined System:




python script.py

    Access the Geolocation Endpoint:




curl http://localhost:5000/proxy_locations

This returns a JSON object containing each proxy and its associated location, making it easy to integrate this data into your security infrastructure.
Deployment and Automation

For long-term deployment, consider the following:

    Dockerization:
        Create a Dockerfile to containerize the application, ensuring consistent deployments.
    Scheduled Execution:
        Use a process manager (like systemd or pm2) or a cron job to run the tool continuously.
    Logging and Alerts:
        Implement detailed logging and possibly integrate with an alerting system to notify you of significant changes in proxy threat levels.




Conclusion



This repository provides a robust, automated solution for proxy threat detection and mitigation:

    It continuously scrapes, validates, and enriches proxy data.
    It performs threat intelligence checks to flag malicious proxies.
    It augments proxy data with geolocation details for enhanced security analysis.
    The Flask API makes it easy to integrate this data into various security systems.




This tool is ideal for network security teams, threat intelligence researchers, and anyone needing real-time
data to protect their infrastructure against malicious proxies. It is intended for lawful cybersecurity research
and should be used in compliance with all applicable laws and regulations.









For further questions, contributions, or support, 
please refer to the repository’s issue tracker or contact the maintainers.
