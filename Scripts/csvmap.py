import re
import socket
import nmap
import csv
import whois
import requests
import sys
import os
import pandas as pd
from tqdm import tqdm
from pyfiglet import Figlet

def banner(title):
    figlet = Figlet(font='avatar')
    figlet_banner = figlet.renderText(title)
    print(figlet_banner)

def is_valid_ip(ip):
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return ip_pattern.match(ip) is not None

def is_valid_domain(domain):
    domain_pattern = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')
    return domain_pattern.match(domain) is not None

def resolve_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.error:
        return None

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception:
        return None

def save_whois_results(domain, whois_info):
    with open(f'Exports/{domain}/whois_results.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Domain', 'Whois Info']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if csvfile.tell() == 0:
            writer.writeheader()
        
        whois_info_str = str(whois_info)
        writer.writerow({'Domain': domain, 'Whois Info': whois_info_str})

def monitor_port_scan(host, ports):
    scanner = nmap.PortScanner()
    results = []
    os.makedirs(f'Exports/', exist_ok=True)
    os.makedirs(f'Exports/{host}/', exist_ok=True)
    try:
        csvfile = open(f'Exports/{host}/', "x")
    except Exception:
        pass
    with open(f'Exports/{host}/recon_results.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Target', 'Port', 'Protocol', 'State']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:
            writer.writeheader()

        with tqdm(total=len(ports), desc='Scanning Ports') as pbar:
            for port in ports:
                try:
                    scanner.scan(host, str(port))
                    protocol = 'tcp'
                    state = scanner[host]['tcp'][port]['state']
                    results.append({'Target': host, 'Port': port, 'Protocol': protocol, 'State': state})
                    writer.writerow({'Target': host, 'Port': port, 'Protocol': protocol, 'State': state})
                    pbar.update(1)
                except Exception:
                    results.append({'Target': host, 'Port': port, 'Protocol': protocol, 'State': 'Error'})
                    writer.writerow({'Target': host, 'Port': port, 'Protocol': protocol, 'State': 'Error'})
                    pbar.update(1)

    return results

def is_web_host(host):
    try:
        response = requests.get(f"http://{host}", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def enumerate_directories(host):
    common_directories = [
        "/admin", "/login", "admin/login", "/register", "/forum", "/uploads", "/images", "/css", "/js", "/api",
        "/wp-admin", "/wp-login.php", "/robots.txt", "/sitemap.xml"
    ]
    found_directories = []

    with tqdm(total=len(common_directories), desc='Enumerating Directories') as pbar:
        for directory in common_directories:
            try:
                response = requests.get(f"http://{host}{directory}", timeout=5)
                if response.status_code == 200:
                    found_directories.append(directory)
            except requests.RequestException:
                continue
            finally:
                pbar.update(1)

    save_directory_results(host, found_directories)  # Save results to CSV
    return found_directories

def save_directory_results(host, directories):
    folder_name = f"Exports/{host}"
    os.makedirs(folder_name, exist_ok=True)
    with open(f'{folder_name}/web_directories.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Target', 'Webdirectories']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if csvfile.tell() == 0:
            writer.writeheader()
        
        for directory in directories:
            writer.writerow({'Target': host, 'Webdirectories': directory})

def scan_subdomains(domain):
    common_subdomains = [
        "www", "mail", "ftp", "dev", "test", "blog", "api", "login", "register", "test1", "dev1", "user", "users", "forum", "auth", "logout"
    ]
    found_subdomains = []

    with tqdm(total=len(common_subdomains), desc='Scanning Subdomains') as pbar:
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                ip = resolve_dns(full_domain)
                if ip:
                    found_subdomains.append(full_domain)
            except Exception:
                continue
            finally:
                pbar.update(1)

    save_subdomain_results(domain, found_subdomains)
    return found_subdomains

def save_subdomain_results(domain, subdomains):
    folder_name = f"Exports/{domain}"
    os.makedirs(folder_name, exist_ok=True)
    try:
        csvfile = open("folder_name/subdomains.csv", "x")
    except Exception:
        pass
    with open(f'{folder_name}/subdomains.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Target', 'Subdomain']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if csvfile.tell() == 0:
            writer.writeheader()
        
        for subdomain in subdomains:
            writer.writerow({'Target': domain, 'Subdomain': subdomain})

def is_login_page(url):
    """Check if the page is a login page based on URL and content."""
    login_indicators = ["login", "signin", "auth", "account", "user", "auhtenticate", "register"]
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            content = response.text.lower()
            # Check for common login indicators in URL and content
            if any(indicator in url for indicator in login_indicators) or "login" in content or "password" in content:
                return True
    except requests.RequestException:
        return False
    return False

def find_login_pages(host):
    common_login_paths = [
        "/index/login", "/login", "/index/register", "register/", "/admin/login", "/user/login", "/signin", "/authentication", "/auth", "/wp-login.php"
    ]
    found_login_pages = []

    with tqdm(total=len(common_login_paths), desc='Finding Login Pages') as pbar:
        for path in common_login_paths:
            full_url = f"http://{host}{path}"
            if is_login_page(full_url):
                found_login_pages.append(full_url)
            pbar.update(1)

    save_login_page_results(host, found_login_pages)
    return found_login_pages

def save_login_page_results(host, login_pages):
    folder_name = f"Exports/{host}"
    os.makedirs(folder_name, exist_ok=True)
    with open(f'{folder_name}/login_pages.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Target', 'Login Page']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if csvfile.tell() == 0:
            writer.writeheader()
        
        for page in login_pages:
            writer.writerow({'Target': host, 'Login Page': page})

def summarize_results(domain):
    """Generate a summarized output of the scanning results."""
    folder_name = f"Exports/{domain}"
    summaries = []

    # Load subdomains
    try:
        subdomain_df = pd.read_csv(f'{folder_name}/subdomains.csv')
        for _, row in subdomain_df.iterrows():
            summaries.append({'Type': 'Subdomain', 'Value': row['Subdomain']})
    except FileNotFoundError:
        summaries.append({'Type': 'Subdomain', 'Value': 'No subdomains found.'})

    # Load web directories
    try:
        directory_df = pd.read_csv(f'{folder_name}/web_directories.csv')
        for _, row in directory_df.iterrows():
            summaries.append({'Type': 'Web Directory', 'Value': row['Webdirectories']})
    except FileNotFoundError:
        summaries.append({'Type': 'Web Directory', 'Value': 'No web directories found.'})

    # Load login pages
    try:
        login_page_df = pd.read_csv(f'{folder_name}/login_pages.csv')
        for _, row in login_page_df.iterrows():
            summaries.append({'Type': 'Login Page', 'Value': row['Login Page']})
    except FileNotFoundError:
        summaries.append({'Type': 'Login Page', 'Value': 'No login pages found.'})

    # Create a DataFrame and print it
    summary_df = pd.DataFrame(summaries)
    print("\nSummary of Scanning Results:")
    print(summary_df)

def main():

    banner("C$VM@P")

    # Check for command-line arguments
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
    else:
        user_input = input("Enter a domain or IP address: ")

    if is_valid_ip(user_input):
        ip_address = user_input
        print(f"Valid IP address: {ip_address}")
    elif is_valid_domain(user_input):
        ip_address = resolve_dns(user_input)
        if ip_address:
            print(f"Resolved {user_input} to {ip_address}")
    else:
        print("Invalid input. Please enter a valid domain or IP address.")
        return

    # Check if the host is a web host
    if is_web_host(user_input):
        # Enumerate directories on the web host
        enumerate_directories(user_input)
        
        if is_valid_domain:
            # Scan for subdomains
            scan_subdomains(user_input)

        # Find login pages
        find_login_pages(user_input)

    # WHOIS Lookup
    whois_info = whois_lookup(user_input)
    if whois_info:
        save_whois_results(user_input, whois_info)

    # Define specific ports to scan
    ports_to_scan = [21, 22, 23, 53, 80, 110, 111, 135, 139, 143, 190, 443, 445, 993, 995, 1024, 1723, 3306, 3389, 3390, 4000, 5900, 4444, 8000, 8080, 8888]

    # Port Scanning
    results = monitor_port_scan(ip_address, ports_to_scan)

    # Summarize results
    summarize_results(user_input)

    os.system("tree Exports/")

if __name__ == "__main__":
    main()