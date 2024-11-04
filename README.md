
# NetRecon

**NetRecon** is an IP reconnaissance tool designed to gather comprehensive intelligence on one or multiple IP addresses. It supports single IPs, comma-separated lists, and CIDR blocks, allowing for detailed reconnaissance across a network range. NetRecon collects data from various modules, including WHOIS, geolocation, DNS records, open ports, threat intelligence, and more.

## Features

- IP and Domain WHOIS Lookup
- Geolocation Information
- DNS Record Retrieval
- Open Ports Scanning
- Blacklist and Threat Intelligence Checks
- Proxy/VPN Detection
- Supports CIDR Blocks for Network-Wide Reconnaissance
- Optional JSON Output for Individual IPs

## Requirements

- Python 3.x
- https://abuseipdb.com API KEY

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/woodyk/netrecon.git
   cd netrecon
   ```

2. Install the required Python packages:
   ```bash
   python3 -m venv .venv
   . .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Add the Abuseipdb API KEY
   ```bash
   export ABUSEIPDB_API_KEY="<your_api_key>"
   ```

## Usage

The `netrecon.py` script accepts IP addresses, domain names, and CIDR blocks for scanning. It prints detailed results for each IP address and optionally saves them as JSON files.

### Basic Commands

- **Single IP Reconnaissance**:
  ```bash
  python3 netrecon.py 8.8.8.8
  ```

- **Multiple IPs (comma-separated)**:
  ```bash
  python3 netrecon.py 8.8.8.8,1.1.1.1
  ```

- **CIDR Block Reconnaissance**:
  ```bash
  python3 netrecon.py 192.168.1.0/24
  ```

- **Saving Output as JSON Files**:
  Use the `--save` flag to save each IP’s data to a JSON file.
  ```bash
  python3 netrecon.py 8.8.8.8 --save
  ```

## Output

- The script prints detailed JSON data for each IP in a readable format.
- If `--save` is specified, JSON files are created for each IP in the working directory with filenames based on the IP address (e.g., `8.8.8.8.json`).

## Modules

The following modules are used for data collection:

1. **WHOIS Lookup**: Provides registrant and domain/IP registration details.
2. **Geolocation**: Returns geographical location data (country, city, ISP).
3. **DNS Records**: Retrieves A, MX, TXT, and other DNS records.
4. **Open Ports**: Scans for open ports and service information.
5. **Blacklist**: Checks if the IP is listed on blacklists.
6. **Proxy/VPN Detection**: Detects if the IP is associated with VPN or proxy services.
7. **Threat Intelligence**: Provides threat and risk scores based on AbuseIPDB data.

## Example

```bash
python3 netrecon.py 192.168.1.1,8.8.8.8,example.com --save
```

This command will perform reconnaissance on `192.168.1.1`, `8.8.8.8`, and `example.com`, printing each result to `stdout` and saving each result to a JSON file in the current directory.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
