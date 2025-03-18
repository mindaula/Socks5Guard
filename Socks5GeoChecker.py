import requests
import sys
import os
import json
from dotenv import load_dotenv

load_dotenv()
IPINFO_API_KEY = os.getenv("IPINFO_API_KEY")


def get_proxy_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}", timeout=5)
        data = response.json()
        city = data.get("city", "Unknown")
        country = data.get("country", "Unknown")
        return f"{city}, {country}"
    except requests.RequestException:
        return "Unknown, Unknown"


def process_proxies(input_file):
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found!")
        sys.exit(1)

    output_file = f"{os.path.splitext(input_file)[0]}_with_city.json"
    proxy_data = []

    with open(input_file, "r") as infile:
        for line in infile:
            proxy = line.strip()
            if ":" in proxy:
                ip = proxy.split(":")[0]
                location = get_proxy_location(ip)
                proxy_entry = {"proxy": proxy, "location": location}
                proxy_data.append(proxy_entry)
                print(proxy_entry)

    with open(output_file, "w") as outfile:
        json.dump(proxy_data, outfile, indent=4)

    print(f"Results saved in: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python catalogizer.py <input_file.txt>")
        sys.exit(1)

    input_file = sys.argv[1]
    process_proxies(input_file)
