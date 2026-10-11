import argparse
import getpass
import requests
import urllib3
import sys
import csv
from datetime import datetime

# Suppress insecure HTTPS warnings since Infoblox often uses self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class InfobloxWAPI:
    def __init__(self, gridmaster, username, password, wapi_version="v2.11", proxy=None):
        self.base_url = f"https://{gridmaster}/wapi/{wapi_version}"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = False  # Ignore self-signed certs
        self.grid_name = "unknown_grid"

        # Apply proxy only if explicitly passed
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        else:
            # Prevent requests from implicitly picking up ambient shell env proxies
            self.session.trust_env = False

        # Test connection and retrieve grid name
        try:
            test = self.session.get(f"{self.base_url}/grid?_return_fields=name")
            test.raise_for_status()

            # Extract grid name from the response
            grid_data = test.json()
            if grid_data and isinstance(grid_data, list) and 'name' in grid_data[0]:
                self.grid_name = grid_data[0]['name']

        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to connect or authenticate to Gridmaster: {e}")
            sys.exit(1)

    def get_leases(self, query_params=None):
        """Fetch all leases, handling Infoblox WAPI pagination."""
        url = f"{self.base_url}/lease"
        params = {
            '_return_fields': 'address,hardware,uid,client_hostname,binding_state',
            '_paging': 1,
            '_return_as_object': 1,
            '_max_results': 500
        }
        if query_params:
            params.update(query_params)

        all_leases = []
        page_id = None

        while True:
            if page_id:
                params['_page_id'] = page_id

            response = self.session.get(url, params=params)

            if not response.ok:
                print(f"[-] API Error: {response.status_code}\n{response.text}")
                response.raise_for_status()

            data = response.json()
            page_results = data.get('result', [])
            all_leases.extend(page_results)

            page_id = data.get('next_page_id')
            if not page_id:
                break

        return all_leases

    def delete_lease(self, lease_ref, details):
        """Delete a lease using its object reference."""
        url = f"{self.base_url}/{lease_ref}"
        response = self.session.delete(url)
        if response.status_code == 200:
            print(f"[+] Successfully deleted lease: {details}")
        else:
            print(f"[-] Failed to delete lease {details}: {response.text}")


def display_leases(leases):
    """Format and print a list of leases."""
    if not leases:
        print("No leases found matching the criteria.")
        return

    print(f"{'IP ADDRESS':<18} | {'MAC ADDRESS':<20} | {'HOST NAME':<20} | {'CLIENT ID (UID)':<25} | {'STATE'}")
    print("-" * 85)
    for l in leases:
        ip = l.get('address', 'N/A')
        mac = l.get('hardware', 'N/A')
        hostname = l.get('client_hostname', 'N/A')
        client_id = l.get('uid', 'N/A')
        state = l.get('binding_state', 'N/A')
        print(f"{ip:<18} | {mac:<20} | {hostname:<20} | {client_id:<25} | {state}")
    print(f"\nTotal records: {len(leases)}")


def export_to_csv(leases, grid_name):
    """Export the list of leases to a CSV file."""
    if not leases:
        return

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    # Sanitize grid name to ensure it's safe for filenames
    safe_grid_name = "".join(c for c in grid_name if c.isalnum() or c in ('_', '-'))
    filename = f"{safe_grid_name}_leases_{timestamp}.csv"

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write headers exactly like the onscreen layout
            writer.writerow(['IP ADDRESS', 'MAC ADDRESS', 'HOST NAME', 'CLIENT ID (UID)', 'STATE'])
            for l in leases:
                ip = l.get('address', 'N/A')
                mac = l.get('hardware', 'N/A')
                hostname = l.get('client_hostname', 'N/A')
                client_id = l.get('uid', 'N/A')
                state = l.get('binding_state', 'N/A')
                writer.writerow([ip, mac, hostname, client_id, state])
        print(f"[*] Exported {len(leases)} leases to {filename}")
    except Exception as e:
        print(f"[-] Failed to write CSV file: {e}")


def main():
    parser = argparse.ArgumentParser(description="Infoblox DHCP Lease Manager")

    # Required connection arguments
    parser.add_argument("-g", "--gridmaster", required=True, help="Gridmaster IP or FQDN")
    parser.add_argument("-u", "--username", required=True, help="Admin username")

    # Optional connection arguments
    parser.add_argument("-v", "--wapi-version", default="v2.11", help="WAPI version (default: v2.11)")
    parser.add_argument("-p", "--proxy", default=None, required=False,
                        help="Web proxy URL (optional, e.g. http://proxy.local:8080)")

    # Mutually exclusive action group (one action must be chosen)
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--show", action="store_true", help="Show all current leases")
    action_group.add_argument("--delete-state", help="Delete leases by state (e.g., ABANDONED, ACTIVE, FREE)")
    action_group.add_argument("--delete-ip", help="Delete a lease by its IP address")
    action_group.add_argument("--delete-mac", help="Delete a lease by its MAC address")

    args = parser.parse_args()

    password = getpass.getpass(prompt=f"Enter password for '{args.username}': ")

    print("[*] Connecting to Infoblox...")
    ibx = InfobloxWAPI(
        gridmaster=args.gridmaster,
        username=args.username,
        password=password,
        wapi_version=args.wapi_version,
        proxy=args.proxy
    )

    print(f"[*] Connected to Grid: {ibx.grid_name}")

    # 1. Show all leases
    if args.show:
        print("[*] Retrieving all leases...")
        leases = ibx.get_leases()
        display_leases(leases)
        export_to_csv(leases, ibx.grid_name)

    # 2. Delete by State
    elif args.delete_state:
        state = args.delete_state.upper()
        print(f"[*] Fetching all leases to locate state: {state}...")
        all_leases = ibx.get_leases()
        leases = [l for l in all_leases if l.get('binding_state', '').upper() == state]

        if not leases:
            print(f"No leases found with state '{state}'.")
            return

        display_leases(leases)
        export_to_csv(leases, ibx.grid_name)

        confirm = input(f"\nAre you sure you want to delete these {len(leases)} leases? (y/N): ")
        if confirm.lower() == 'y':
            for l in leases:
                ibx.delete_lease(l['_ref'], f"{l.get('address')} ({state})")
        else:
            print("Operation cancelled.")

    # 3. Delete by IP Address
    elif args.delete_ip:
        print(f"[*] Locating lease for IP: {args.delete_ip}...")
        leases = ibx.get_leases({'address': args.delete_ip})

        if not leases:
            print("Lease not found.")
            return

        display_leases(leases)
        export_to_csv(leases, ibx.grid_name)

        for l in leases:
            ibx.delete_lease(l['_ref'], f"IP: {args.delete_ip}")

    # 4. Delete by MAC Address
    elif args.delete_mac:
        print(f"[*] Locating lease for MAC: {args.delete_mac}...")
        leases = ibx.get_leases({'hardware': args.delete_mac})

        if not leases:
            print("Lease not found.")
            return

        display_leases(leases)
        export_to_csv(leases, ibx.grid_name)

        for l in leases:
            ibx.delete_lease(l['_ref'], f"MAC: {args.delete_mac}")


if __name__ == "__main__":
    main()