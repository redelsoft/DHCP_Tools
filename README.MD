# Infoblox DHCP Lease Management Toolkit

This toolkit consists of two Python scripts designed to help network administrators and engineers test, manage, and clean up DHCP leases within an Infoblox NIOS environment (and underlying Kea DHCP engines). 

It provides tools to intentionally simulate (abandoned) leases for testing purposes and a robust API client to query and delete leases directly from the Infoblox Grid.

---

## Prerequisites

Ensure you have Python 3.x installed. You will also need to install the required third-party Python packages. 

```bash
pip install scapy requests
```

*Note: `create_leases.py` requires raw socket access to send crafted network packets. It must be run with root/Administrator privileges.*

---

## 1. `create_leases.py`

### Overview
This script acts as a rogue DHCP client. It intentionally requests an IP address (or a range of IPs) from the DHCP server, completes the full DORA (Discover, Offer, Request, Acknowledge) handshake to secure the lease, and immediately issues a `DHCPDECLINE` packet. This forces the DHCP server to mark the IP address as **Abandoned** (or placed in a decline-probation state in Kea).

**Primary Use Case:** Generating test data in non-production environments to verify automation pipelines, alerting, or cleanup scripts related to abandoned IP addresses.

### How It Works
1. Parses the target IP, IP range, or CIDR block.
2. Loops through the target IPs.
3. Generates a spoofed, random MAC address and Client Identifier for each request.
4. Uses the `scapy` library to broadcast a `DHCPDISCOVER`.
5. Listens for the `DHCPOFFER` and formally accepts it with a `DHCPREQUEST`.
6. Waits for the `DHCPACK` to ensure the lease is committed to the server's database.
7. Instantly sends a `DHCPDECLINE`, abandoning the lease.

### Usage

**Arguments:**
* `-i`, `--interface` (Required): The network interface to send traffic from (e.g., `eth0`, `en0`).
* `-t`, `--target` (Required): The IP(s) to abandon. Accepts a single IP, a hyphenated range, or a CIDR subnet.
* `--nodecline` (Optional): No DECLINE message is send to the DHCP server. The requests IP lease will stay active.


**Examples:**

Abandon a single IP:
```bash
sudo python3 create_abandoned.py -i eth0 -t 192.168.10.244
```

Abandon a range of IPs:
```bash
sudo python3 create_abandoned.py -i eth0 -t 192.168.10.20-192.168.10.30
```

Abandon a whole subnet:
```bash
sudo python3 create_abandoned.py -i eth0 -t 192.168.10.0/24
```

Starve a DHCP range in a subnet:
```bash
sudo python3 create_abandoned.py -i eth0 -t 192.168.10.0/24 --nodecline
```

⚠️ **WARNING:** Do not run this script against IPs that are currently in use by legitimate clients. Declining a lease effectively blacklists the IP from being handed out by the DHCP server until the abandonment times out or is manually cleared.

---

## 2. `ib_manage_leases.py`

### Overview
This script is a command-line interface for the Infoblox NIOS WAPI (REST API). It allows administrators to quickly view current DHCP leases and selectively delete them based on their state, IP address, or MAC address. 

### Features
* **Secure Authentication:** Uses the `getpass` module to prompt for the Infoblox password securely, keeping it out of your command history.
* **Pagination Support:** Automatically handles WAPI pagination limits, ensuring it can safely pull tens of thousands of leases without truncating data.
* **CSV Export:** Automatically generates a timestamped CSV file containing the retrieved lease data every time a command is run. The file is formatted as `<grid_name>_leases_YYYYMMDDHHMMSS.csv`.
* **Safety Prompts:** Requires a `y/N` confirmation before performing bulk deletions (like deleting all ABANDONED leases).
* **Proxy Support:** Includes an optional flag to route API traffic through a corporate web proxy.

### Usage

**Connection Arguments (Required):**
* `-g`, `--gridmaster`: The IP address or FQDN of your Infoblox Gridmaster.
* `-u`, `--username`: Your Infoblox admin username.

**Optional Arguments:**
* `-v`, `--wapi-version`: WAPI version (Defaults to `v2.11`).
* `-p`, `--proxy`: Web proxy URL (e.g., `http://proxy.local:8080`, or `proxy.local:8080`).

**Action Arguments (You must choose exactly one):**
* `--show`: Display all leases in the grid and export to CSV.
* `--delete-state <STATE>`: Find and delete all leases matching a specific state (e.g., `ABANDONED`, `ACTIVE`, `FREE`).
* `--delete-ip <IP>`: Find and delete a lease by its IP address.
* `--delete-mac <MAC>`: Find and delete a lease by its MAC address.

**Examples:**

Show all current leases in the grid:
```bash
python3 ib_manage_leases.py -g 10.0.0.5 -u admin --show
```

Delete all abandoned leases (useful for cleaning up after `create_leases.py`):
```bash
python3 ib_manage_leases.py -g 10.0.0.5 -u admin --delete-state ABANDONED
```

Delete a specific IP lease via a proxy:
```bash
python3 ib_manage_leases.py -g 10.0.0.5 -u admin -p http://192.168.1.100:8080 --delete-ip 192.168.10.244