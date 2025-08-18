#!/usr/bin/env python3

import argparse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import TimeoutException
import requests
import re
import socket
from concurrent.futures import ThreadPoolExecutor
import threading
from requests.exceptions import HTTPError, Timeout
import traceback
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import os
import random

# For colored output
from colorama import init, Fore, Style
from tabulate import tabulate  # For table formatting

# Initialize colorama
init(autoreset=True)

session = requests.Session()

cookies_option = True
screenshots_options = False
delay_value = 100

# Create a global lock for Snyk requests
snyk_lock = threading.Lock()


def load_javascript_libraries(file_path):
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.")
        return None



def resolve_domain(domain_name):
    hasWWW = domain_name.startswith('www.')
    
    try:
        # Resolve the domain to an IP address
        ip_address = socket.gethostbyname(domain_name)
        print(f'\n{domain_name} successfully resolved to {ip_address}\n')
        return [ip_address, domain_name]
    except:
        print(f'\nThe domain {domain_name} did not resolve on the first attempt.\n')
        if hasWWW:
            domain_name = re.sub(r'^www\.', '', domain_name)
        else:
            domain_name = 'www.' + domain_name
        try:
            ip_address = socket.gethostbyname(domain_name)
            print(f'\n{domain_name} successfully resolved to {ip_address}\n')
            return [ip_address, domain_name]
        except Exception as e:
            print(f"\nError in resolving the domain: {domain_name}\n {e}\n")
            return False

def sanitise_url(url):
    """Sanitise the given URL."""
    url = re.sub(r'^https?://', '', url)
    parsed_url = urlparse(f"//{url}")
    domain = parsed_url.hostname
    port = parsed_url.port
    path = parsed_url.path

    if port:
        return [f"{domain}:{port}", path]
    return [domain, path]


def process_text_input(input_field, IP_addresses):
    address_map = {}
    for address in input_field:
        address = address.strip()
        sanitised_address, extension = sanitise_url(address)
        domain_part = sanitised_address.split(":")[0]
        port_parts = sanitised_address.split(":")[1].split(",") if ":" in sanitised_address else []

        resolved_ip_and_domain = resolve_domain(domain_part)
        if not resolved_ip_and_domain:
            continue

        urlIP, resolved_domain = resolved_ip_and_domain
        resolved_domain_with_extension = resolved_domain + extension

        if urlIP not in address_map:
            address_map[urlIP] = {
                'hosts': [resolved_domain_with_extension],
                'ports': set(port_parts) or {'443'}
            }
        else:
            address_map[urlIP]['hosts'].append(resolved_domain_with_extension)
            address_map[urlIP]['ports'].update(port_parts)

    for ip, data in address_map.items():
        IP_addresses.append({
            'host': data['hosts'],
            'ports': [{'port': p, 'service': 'https' if p in ['443', '8443'] else 'http'} for p in data['ports']]
        })

    return IP_addresses

def get_latest_version(package_name):
    """
    Get the latest version of a given npm package using a persistent session.
    """
    npm_registry_url = f'https://registry.npmjs.org/{package_name}'
    
    try:
        response = session.get(npm_registry_url, timeout=(5, 14))
        response.raise_for_status()  # This will raise an exception for HTTP errors
        data = response.json()
        return data['dist-tags']['latest']
    except (HTTPError, Timeout) as http_err:
        print(f"HTTP error occurred: {http_err}")
    except Exception as err:
        print(f"An error occurred: {err}")
    return None

def findCVE(package_name, package_version, num_cves=3):
    """
    Find CVEs for a given npm package and version.
    This function uses a global lock to ensure that only one thread
    queries Snyk at a time and includes a 1-second delay between requests.
    """
    snyk_url = f'https://security.snyk.io/package/npm/{package_name}/{package_version}'
    base_url = "https://security.snyk.io"
    cve_list = []

    with snyk_lock:
        try:
            time.sleep(random.uniform(1, 2))  # Delay before making the request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
            }
            response = requests.get(snyk_url, headers=headers, timeout=(5, 14))
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')
            vuln_links = soup.find_all('a', attrs={"data-snyk-test": "vuln table title"}, limit=num_cves)

            for link in vuln_links:
                href = link.get('href')
                if not href:
                    continue

                vuln_url = urljoin(base_url, href)
                time.sleep(random.uniform(1, 2))  # Delay before the next request
                vuln_response = requests.get(vuln_url, timeout=(5, 14))
                vuln_response.raise_for_status()

                vuln_soup = BeautifulSoup(vuln_response.text, 'html.parser')
                severity_score_element = vuln_soup.find('div', attrs={"data-snyk-test": "severity widget score"})
                score = severity_score_element['data-snyk-test-score'] if severity_score_element else "Unknown"

                cve_element = vuln_soup.find('a', id=re.compile(r'CVE-'))
                if cve_element:
                    cve = cve_element.get_text(strip=True).replace('(opens in a new tab)', '')
                    nist_link = f'https://nvd.nist.gov/vuln/detail/{cve}'
                else:
                    cve = vuln_url
                    nist_link = None

                severity_level_element = vuln_soup.find('span', class_="vue--badge__text")
                severity = severity_level_element.get_text(strip=True) if severity_level_element else "Unknown"

                cve_list.append({
                    "cve": cve,
                    "score": score,
                    "level": severity,
                    "snyk_link": snyk_url,
                    "nist_link": nist_link
                })

            return cve_list

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 404:
                return f"SNYK NOT FOUND for {package_name} version {package_version}"
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
        except Exception as err:
            print(f"An error occurred in findCVE: {err}")

    return cve_list


def is_valid_version(version_str):
    # This function checks if a string contains only numbers and dots
    return re.match(r'^\d+(\.\d+)*$', version_str) is not None


def add_cookie_to_driver(driver, cookie_str, url):
    """
    Parse the cookie string in 'name=value' format and add it to the WebDriver session.
    The domain of the cookie is set to match the domain of the URL being processed.
    """
    cookie_parts = cookie_str.split('=')
    if len(cookie_parts) != 2:
        print(f"Invalid cookie format: {cookie_str}")
        return
    
    cookie_name = cookie_parts[0].strip()
    cookie_value = cookie_parts[1].strip()

    # Extract the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.hostname

    # Add the cookie to the Selenium WebDriver session
    cookie_dict = {
        'name': cookie_name,
        'value': cookie_value,
        'domain': domain,  # Ensure this matches the domain of the website you are visiting
        'path': '/',  # Path is optional, defaults to '/'
    }

    print(f"Adding cookie: {cookie_dict}")
    driver.get(url)
    driver.add_cookie(cookie_dict)

def get_software(address, file, show_browser):
    for target_host in address['host']:
        for target_port in address['ports']:
            found_software = set()
            results = []
            try:
                service = target_port['service']
                port_number = target_port['port']
                # Build a proper URL that preserves any path included in target_host
                parsed_target = urlparse(f"//{target_host}")
                domain_only = parsed_target.hostname or target_host
                path_only = parsed_target.path if parsed_target.path else "/"
                url = f"{service}://{domain_only}:{port_number}{path_only}"

                options = Options()
                if not show_browser:
                    options.add_argument("-headless")
                options.add_argument("--window-size=1920x500")
                # Add other options as needed

                with webdriver.Firefox(options=options) as driver:
                    driver.implicitly_wait(5)
                    driver.set_page_load_timeout(timeout_value + 5)

                    if cookie_value:
                        add_cookie_to_driver(driver, cookie_value, url)

                    driver.get(url)

                    for item in file:
                        parts = item.split(":")
                        if len(parts) < 3:
                            continue

                        library, discover_methods, official_name = parts[0], parts[1].split('/'), parts[2].strip()

                        for discover in discover_methods:
                            try:
                                version = driver.execute_script(f"return {discover.strip()}")
                                if not version or not is_valid_version(version):
                                    continue

                                if library in found_software:
                                    continue

                                latest_version = get_latest_version(official_name)
                                outdated = version != latest_version if latest_version else None
                                cve = findCVE(official_name, version, num_cves_value)

                                found_software.add(library)

                                results.append({
                                    "library": library,
                                    "version": version,
                                    "latest_version": latest_version,
                                    "discover": discover.strip(),
                                    "outdated": outdated,
                                    "officialName": official_name,
                                    "cve": cve
                                })
                                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {Fore.YELLOW}{library}{Style.RESET_ALL} on {Fore.CYAN}{url}{Style.RESET_ALL}")
                                break  # Move to the next library
                            except Exception:
                                continue

                    if cookies_option and (cookies := driver.get_cookies()):
                        target_port["cookies"] = cookies

                if results:
                    target_port.setdefault("software", []).extend(results)

            except TimeoutException:
                print(f"Error: Navigation to {url} timed out.")
            except Exception as e:
                print(f"Error processing {target_host}:{port_number}: {e}")

    return address


def findSoftware(IP_addresses, timeout, threads_value, delay, javascript_libraries, num_cves_value, show_browser):
    global cookies_option, screenshots_options, timeout_value, delay_value
    timeout_value = timeout
    delay_value = delay

    file = javascript_libraries.split("\n")

    def process_address(address):
        return get_software(address, file, show_browser)

    with ThreadPoolExecutor(max_workers=threads_value) as executor:
        results = executor.map(process_address, IP_addresses)
    
    return list(results)

def print_markdown_outdated_table(results):
    snyk_links = set()
    nist_links = set()
    table_data = []

    for result in results:
        for host in result.get('host', []):
            for port_info in result.get('ports', []):
                for software in port_info.get('software', []):
                    library = software.get('library', 'N/A')
                    version_found = software.get('version', 'N/A')
                    latest_version = software.get('latest_version', 'N/A')
                    cve_list = [cve for cve in software.get('cve', []) if isinstance(cve, dict)]
                    cve_str = ", ".join([cve['cve'] for cve in cve_list]) if cve_list else 'N/A'

                    snyk_link = f"https://security.snyk.io/package/npm/{software.get('officialName', library)}/{version_found}"
                    snyk_links.add(snyk_link)

                    for cve_info in cve_list:
                        if nist_link := cve_info.get('nist_link'):
                            nist_links.add(nist_link)

                    table_data.append([host, port_info.get('port', 'N/A'), library, version_found, latest_version, cve_str])

    if not table_data:
        print("No software found.")
        return

    headers = ["Host", "Port", "Software Discovered", "Version Found", "Latest Version", "CVE"]
    print("\nMarkdown Table of Software:\n")
    print(tabulate(table_data, headers=headers, tablefmt="github"))

    if snyk_links or nist_links:
        print("Links Used:")
        for link in sorted(snyk_links):
            print(f"- Snyk: {link}")
        for link in sorted(nist_links):
            print(f"- NIST: {link}")



def get_cve_color(score):
    try:
        score = float(score)
        if score == 0:
            return Fore.BLUE
        if 0.1 <= score <= 3.9:
            return Fore.GREEN
        if 4.0 <= score <= 6.9:
            return Fore.YELLOW
        if 7.0 <= score <= 8.9:
            return Fore.MAGENTA
        if 9.0 <= score <= 10.0:
            return Fore.RED
    except (ValueError, TypeError):
        pass
    return Style.RESET_ALL

def print_colored_table(results):
    headers = ["Host", "Port", "Software Discovered", "Version Found", "Latest Version", "CVE", "Discovery Method"]
    table_rows = []

    for result in results:
        for host in result.get('host', []):
            for port_info in result.get('ports', []):
                port = port_info.get('port', 'N/A')
                software_list = port_info.get('software', [])
                if not software_list:
                    table_rows.append([host, port, 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'])
                    continue

                for software in software_list:
                    version_found = software.get('version', 'N/A')
                    latest_version = software.get('latest_version', 'N/A')
                    outdated = software.get('outdated')
                    version_color = Fore.RED if outdated else Fore.GREEN if outdated is False else Style.RESET_ALL

                    cve_list = software.get('cve', [])
                    cve_colored_list = []
                    if isinstance(cve_list, list):
                        for cve_info in cve_list:
                            if isinstance(cve_info, dict):
                                cve_code = cve_info.get('cve', 'N/A')
                                score = cve_info.get('score', 'Unknown')
                                cve_color = get_cve_color(score)
                                cve_colored_list.append(f"{cve_color}{cve_code} ({score}){Style.RESET_ALL}")
                            else:
                                cve_colored_list.append(str(cve_info))
                    elif cve_list:
                        cve_colored_list.append(str(cve_list))

                    table_rows.append([
                        host,
                        port,
                        software.get('library', 'N/A'),
                        f"{version_color}{version_found}{Style.RESET_ALL}",
                        f"{version_color}{latest_version}{Style.RESET_ALL}",
                        ", ".join(cve_colored_list) or 'N/A',
                        software.get('discover', 'N/A')
                    ])

    print("All Software Discoverd")
    print(tabulate(table_rows, headers=headers, tablefmt="github"))


titleArt = '''

███████╗ ██████╗ ███████╗████████╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔════╝██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██╔══██╗██╔══██╗██╔════╝
███████╗██║   ██║█████╗     ██║   ██║ █╗ ██║███████║██████╔╝█████╗  
╚════██║██║   ██║██╔══╝     ██║   ██║███╗██║██╔══██║██╔══██╗██╔══╝  
███████║╚██████╔╝██║        ██║   ╚███╔███╔╝██║  ██║██║  ██║███████╗
╚══════╝ ╚═════╝ ╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                    
██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗                   
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗                  
██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝                  
██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗                  
██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║                  
╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                  
                                                                    
'''

if __name__ == "__main__":
    # Command-line interface
    print (titleArt)
    parser = argparse.ArgumentParser(description='Scan URLs for outdated JavaScript libraries.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='The URL to scan.')
    group.add_argument('--file', help='File containing a list of URLs to scan.')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout value in seconds.')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads to use.')
    parser.add_argument('--delay', type=int, default=100, help='Delay value in milliseconds.')
    parser.add_argument('--cookie', help='Add a session cookie (e.g. "PHPSESSID=a8d127e..")')
    parser.add_argument('--num-cves', type=int, default=3, help='Number of CVEs to find for each vulnerability.')
    parser.add_argument('--show', action='store_true', help='Show the browser.')

    args = parser.parse_args()

    timeout_value = args.timeout
    threads_value = args.threads
    delay_value = args.delay
    cookie_value = args.cookie
    num_cves_value = args.num_cves
    show_browser = args.show

    IP_addresses = []

    if args.url:
        input_urls = [args.url]
    elif args.file:
        # Read URLs from file
        if os.path.isfile(args.file):
            with open(args.file, 'r') as f:
                input_urls = [line.strip() for line in f if line.strip()]
        else:
            print(f"File {args.file} does not exist.")
            exit(1)
    else:
        input_urls = []

    if not input_urls:
        print("No URLs provided to scan.")
        exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    js_libs_path = os.path.join(script_dir, 'javascriptLibraries.txt')
    javascript_libraries = load_javascript_libraries(js_libs_path)
    if javascript_libraries is None:
        exit(1)

    print(Fore.CYAN + "="*69)
    print(Fore.CYAN + "                       Scan Configuration")
    print(Fore.CYAN + "="*69 + "\n")
    print(f"{Fore.WHITE}Target URLs: {args.url if args.url else args.file}")
    print(f"{Fore.WHITE}Threads: {args.threads}")
    print(f"{Fore.WHITE}Timeout: {args.timeout}s")
    print(f"{Fore.WHITE}Delay: {args.delay}ms")
    print(f"{Fore.WHITE}Number of CVEs to find: {args.num_cves}")
    if args.cookie:
        print(f"{Fore.WHITE}Cookie: {args.cookie}")

    IP_addresses = process_text_input(input_urls, IP_addresses)
    results = findSoftware(IP_addresses, timeout_value, threads_value, delay_value, javascript_libraries, num_cves_value, show_browser)

    print_markdown_outdated_table(results)

    print_colored_table(results)
    print('\n')
