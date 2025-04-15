"""
OpenStack Security Assessment Tool
A comprehensive security scanning tool for OpenStack environments.
"""

# Standard library imports
import subprocess
import json
import logging
import argparse
import sys
import os
import re
from datetime import datetime
from string import Template
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Third-party imports
import openstack
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

# Constants and Configuration
# ---------------------------

# Default security keywords and patterns
DEFAULT_SENSITIVE_KEYWORDS = [
    "password",
    "secret_key",
    "auth_token",
    "private_key",
    "db_password",
    "aws_secret_access_key",
    "pass"
]

DEFAULT_CREDENTIAL_KEYWORDS = [
    "root",
    "admin",
    "administrator"
]

DEFAULT_ALLOWED_ADMIN_USERS = [
    "ops_admin",
    "administrator",
    "admin"
]

# Security patterns and ports
OUTDATED_PATTERNS = ["14.04", "trusty", "eol", "endoflife"]
KNOWN_HARMLESS_KEYS = ["root_device_name", "is_public"]
MANAGEMENT_PORTS = [22, 443, 3389]

SENSITIVE_PATTERNS_CRITICAL = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "AKIA"
]

# Global cache for network information
network_info_cache = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenStack Security Assessment Report</title>
    <style>
        :root {
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #0dcaf0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }

        .header {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }

        h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2em;
        }

        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 10px;
        }

        .search-container {
            margin: 20px 0;
            padding: 15px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        #searchBox {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1em;
        }

        .severity-legend {
            background-color: #fff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .severity-legend ul {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }

        .severity-legend li {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .issues-container {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .issues-section {
            margin-bottom: 30px;
        }

        .issues-section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }

        .issues-list {
            list-style: none;
            padding: 0;
        }

        .issues-list li {
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
            background-color: #f8f9fa;
            transition: background-color 0.2s;
        }

        .issues-list li:hover {
            background-color: #e9ecef;
        }

        .critical { color: var(--critical-color); font-weight: bold; }
        .high { color: var(--high-color); font-weight: bold; }
        .medium { color: var(--medium-color); }
        .low { color: var(--low-color); }

        #gototop {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background-color: #fff;
            color: #333;
            padding: 10px 15px;
            border-radius: 4px;
            text-decoration: none;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            display: none;
            transition: background-color 0.2s;
        }

        #gototop:hover {
            background-color: #f8f9fa;
        }

        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .severity-legend ul {
                flex-direction: column;
                gap: 10px;
            }
        }

        $additional_css
    </style>
</head>
<body>
    <div class="header">
        <h1>OpenStack Security Assessment Report</h1>
        <div class="timestamp">Generated: $timestamp</div>
    </div>

    <div class="severity-legend">
        <h2>Severity Levels</h2>
        <ul>
            <li><span class="critical">● Critical:</span> Immediate action required</li>
            <li><span class="high">● High:</span> Address as soon as possible</li>
            <li><span class="medium">● Medium:</span> Review and plan remediation</li>
            <li><span class="low">● Low:</span> Consider improvements</li>
        </ul>
    </div>

    <div class="search-container">
        <input type="text" id="searchBox" placeholder="Search issues..." onkeyup="searchIssues()">
    </div>

    <div class="issues-container">
        <h2>Potential Issues</h2>
        $issues_html
    </div>

    <div class="projects-container">
        $projects_html
    </div>

    <a id="gototop" href="#top">↑ Top</a>

    <script>
        function searchIssues() {
            const input = document.getElementById('searchBox');
            const filter = input.value.toLowerCase();
            const sections = document.querySelectorAll('.issues-section, .project-section, .instances-section, .security-groups-section, .buckets-section, .user-roles-section');
            
            sections.forEach(section => {
                const items = section.getElementsByTagName('li');
                const paragraphs = section.getElementsByTagName('p');
                let sectionHasVisibleItems = false;
                
                // Search in list items
                for (let item of items) {
                    const text = item.textContent || item.innerText;
                    const matches = text.toLowerCase().indexOf(filter) > -1;
                    item.style.display = matches ? '' : 'none';
                    if (matches) sectionHasVisibleItems = true;
                }
                
                // Search in paragraphs
                for (let p of paragraphs) {
                    const text = p.textContent || p.innerText;
                    const matches = text.toLowerCase().indexOf(filter) > -1;
                    p.style.display = matches ? '' : 'none';
                    if (matches) sectionHasVisibleItems = true;
                }

                // Show/hide section headers based on matches
                const headers = section.querySelectorAll('h2, h3, h4, h5');
                headers.forEach(header => {
                    const headerText = header.textContent || header.innerText;
                    const headerMatches = headerText.toLowerCase().indexOf(filter) > -1;
                    header.style.display = (filter === '' || sectionHasVisibleItems || headerMatches) ? '' : 'none';
                });

                // Show/hide entire section
                section.style.display = (filter === '' || sectionHasVisibleItems) ? '' : 'none';
            });
        }

        window.onscroll = function() {
            const topButton = document.getElementById("gototop");
            if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {
                topButton.style.display = "block";
            } else {
                topButton.style.display = "none";
            }
        };
    </script>
</body>
</html>
"""

def load_config():
    """
    Load security configuration from config.json file.
    Returns tuple of (sensitive_keywords, credential_keywords, allowed_admin_users).
    Falls back to default values if config file doesn't exist or is invalid.
    """
    try:
        if os.path.exists("config.json"):
            with open("config.json", "r") as f:
                cfg = json.load(f)
            return (
                cfg.get("SENSITIVE_KEYWORDS", DEFAULT_SENSITIVE_KEYWORDS),
                cfg.get("CREDENTIAL_KEYWORDS", DEFAULT_CREDENTIAL_KEYWORDS),
                cfg.get("ALLOWED_ADMIN_USERS", DEFAULT_ALLOWED_ADMIN_USERS)
            )
    except (json.JSONDecodeError, IOError) as e:
        logging.warning(f"Error loading config.json: {e}. Using default values.")
    
    return DEFAULT_SENSITIVE_KEYWORDS, DEFAULT_CREDENTIAL_KEYWORDS, DEFAULT_ALLOWED_ADMIN_USERS

# Load configuration
SENSITIVE_KEYWORDS, CREDENTIAL_KEYWORDS, ALLOWED_ADMIN_USERS = load_config()

def get_connection(project_name=None):
    return openstack.connect(project_name=project_name) if project_name else openstack.connect()

def user_select_projects(projects):
    """
    Allow user to select projects to scan.
    Args:
        projects: List of available projects
    Returns:
        List of selected projects
    """
    if not projects:
        logging.error("No projects available for selection")
        return []

    banner_text = Fore.MAGENTA + r"""

 ██████╗ ██████╗ ███████╗███╗   ██╗███████╗████████╗ █████╗  ██████╗██╗  ██╗                         
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝                         
██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗   ██║   ███████║██║     █████╔╝                          
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██╔═██╗                          
╚██████╔╝██║     ███████╗██║ ╚████║███████║   ██║   ██║  ██║╚██████╗██║  ██╗                         
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝                         
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝        ██║   ██║   ██║██║   ██║██║     
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝         ██║   ██║   ██║██║   ██║██║     
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║          ██║   ╚██████╔╝╚██████╔╝███████╗

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""" + Style.NORMAL
    print(banner_text)

    print(Fore.MAGENTA + "\nAvailable Projects:")
    for idx, project in enumerate(projects, start=1):
        print(Fore.YELLOW + f"{idx}. {project['name']}")
    print(Fore.YELLOW + "A. Select All Projects")

    while True:
        try:
            print(Fore.GREEN + "\nEnter the numbers of projects to scan, separated by commas (e.g., 1,3,5 or 'A' for all): ", end="")
            selection = input().strip().lower()
            
            if selection == 'a':
                return projects
            
            selected_indexes = []
            for idx in selection.split(","):
                idx = idx.strip()
                if not idx.isdigit():
                    raise ValueError(f"Invalid input: {idx}")
                
                num = int(idx)
                if num < 1 or num > len(projects):
                    raise ValueError(f"Project number {num} is out of range")
                
                selected_indexes.append(num - 1)
            
            return [projects[idx] for idx in selected_indexes]
            
        except ValueError as e:
            print(Fore.RED + f"Error: {e}")
            print(Fore.YELLOW + "Please try again.")
        except Exception as e:
            print(Fore.RED + f"Unexpected error: {e}")
            print(Fore.YELLOW + "Please try again.")

def get_all_projects(conn):
    return [{"id": project.id, "name": project.name} for project in conn.identity.projects()]

def run_openstack_command(command_list):
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.warning(f"Command failed: {' '.join(command_list)} - {e}")
        return None

def fetch_instances(project_id):
    return run_openstack_command(["openstack", "server", "list", "--project", project_id, "-f", "json"]) or []

def fetch_instance_details(instance_id, project_id):
    data = run_openstack_command(["openstack", "server", "show", instance_id, "--os-project-id", project_id, "-f", "json"]) or {}
    security_groups = data.get('security_groups', [])
    image = data.get('image', '')
    flavor = data.get('flavor', '')
    addresses = data.get('addresses', {})
    if not isinstance(addresses, dict):
        addresses = {}
    return {"metadata": data, "security_groups": security_groups, "image": image, "flavor": flavor, "addresses": addresses}

def is_potentially_sensitive_key(key):
    k_lower = key.lower()
    for skey in SENSITIVE_KEYWORDS:
        if skey in k_lower:
            return True
    return False

def is_high_priv_key(key):
    k_lower = key.lower()
    for ckey in CREDENTIAL_KEYWORDS:
        if ckey in k_lower:
            return True
    return False

def is_known_harmless_key(key):
    k_lower = key.lower()
    return any(hk in k_lower for hk in KNOWN_HARMLESS_KEYS)

def check_string_for_issues(s):
    issues = []
    s_lower = s.lower()

    found_sensitive = False
    for skey in SENSITIVE_KEYWORDS:
        if skey in s_lower:
            found_sensitive = True
            matched_critical_pattern = False
            for p in SENSITIVE_PATTERNS_CRITICAL:
                if p.lower() in s_lower:
                    issues.append(("critical", f"Critical sensitive pattern '{p}' found in value"))
                    matched_critical_pattern = True
                    break
            if not matched_critical_pattern:
                issues.append(("high", f"Possible sensitive keyword '{skey}' found in value, check manually"))

    if not found_sensitive:
        # high priv check
        for ckey in CREDENTIAL_KEYWORDS:
            if ckey in s_lower:
                issues.append(("high", f"High privilege keyword '{ckey}' found in value"))

    return issues

def analyze_metadata_item_for_issues(key, value):
    issues = []
    if is_known_harmless_key(key):
        return issues

    if "public" in key.lower() and str(value).lower() == "true":
        issues.append(("high", f"Public exposure found in {key}"))

    sensitive_found = False
    if is_potentially_sensitive_key(key):
        val_str = str(value)
        if not val_str or val_str.lower() in ["none", "null", "n/a", "password", "secret"]:
            issues.append(("medium", f"Potential sensitive key {key} but value seems trivial"))
        else:
            issues.append(("high", f"Possible sensitive data in {key}, check manually"))
        sensitive_found = True
    else:
        if is_high_priv_key(key):
            issues.append(("high", f"High privilege keyword found in {key} (root/admin)"))

    if isinstance(value, str):
        str_issues = check_string_for_issues(value)
        final_issues = []
        for lvl, msg in str_issues:
            if sensitive_found and "High privilege keyword" in msg:
                continue
            final_issues.append((lvl, msg))
        issues.extend(final_issues)
    elif isinstance(value, dict):
        for k,v in value.items():
            issues.extend(analyze_metadata_item_for_issues(k, v))
    elif isinstance(value, list):
        for elem in value:
            if isinstance(elem, (str, int, float)):
                str_issues = check_string_for_issues(str(elem))
                final_issues = []
                for lvl, msg in str_issues:
                    if "High privilege keyword" in msg and sensitive_found:
                        continue
                    final_issues.append((lvl, msg))
                issues.extend(final_issues)
            elif isinstance(elem, dict):
                for kk,vv in elem.items():
                    issues.extend(analyze_metadata_item_for_issues(kk, vv))
    return issues

def analyze_metadata_for_issues(metadata):
    issues = []
    for key, value in metadata.items():
        issues.extend(analyze_metadata_item_for_issues(key, value))
    return issues

def is_management_port_open(remote_ip, protocol, port_range, direction):
    if remote_ip == "0.0.0.0/0":
        try:
            pmin, pmax = port_range.split("-")
            if pmin == 'any':
                pmin = None
            else:
                pmin = int(pmin)
            if pmax == 'any':
                pmax = None
            else:
                pmax = int(pmax)

            for mport in MANAGEMENT_PORTS:
                if pmin is None and pmax is None:
                    return True
                elif pmin is None and pmax is not None:
                    if pmax >= mport:
                        return True
                elif pmax is None and pmin is not None:
                    if pmin <= mport:
                        return True
                else:
                    if pmin <= mport <= pmax:
                        return True
        except:
            pass
    return False

def fetch_security_groups(conn, project_id):
    security_groups_info = []
    try:
        for sg in conn.network.security_groups(project_id=project_id):
            risky_rules = []
            for rule in sg.security_group_rules:
                remote_ip = rule.get('remote_ip_prefix', "N/A")
                protocol = rule.get('protocol', 'any')
                direction = rule.get('direction', 'N/A')
                port_min = rule.get('port_range_min', 'any')
                port_max = rule.get('port_range_max', 'any')
                port_range = f"{port_min}-{port_max}"

                if remote_ip == "0.0.0.0/0" and (protocol == "ANY" or protocol is None):
                    level = "critical"
                    advice = "Full open access. Restrict to specific IP/Port immediately."
                elif remote_ip == "0.0.0.0/0":
                    level = "high"
                    advice = "Wide open IP range. Limit to known IP ranges."
                elif protocol == "ANY":
                    level = "high"
                    advice = "ANY protocol used. Limit to necessary protocols only."
                else:
                    level = "medium"
                    advice = "Potentially risky rule. Review and tighten if possible."

                if is_management_port_open(remote_ip, protocol, port_range, direction):
                    level = "critical"
                    advice = "Management access fully open! Close or restrict management ports now."

                risky_rules.append({
                    "remote_ip_prefix": remote_ip,
                    "port_range": port_range,
                    "protocol": protocol,
                    "direction": direction,
                    "description": sg.description or "No description",
                    "level": level,
                    "advice": advice
                })
            # Deduplicate
            unique = []
            seen = set()
            for r in risky_rules:
                key = (r['remote_ip_prefix'], r['port_range'], r['protocol'], r['level'], r['advice'], r['direction'])
                if key not in seen:
                    seen.add(key)
                    unique.append(r)

            security_groups_info.append({
                "group_name": sg.name,
                "group_id": sg.id,
                "risky_rules": unique
            })
    except Exception:
        pass
    return security_groups_info

def fetch_bucket_details(project_id, bucket_name):
    """
    Fetch details for a specific bucket.
    Args:
        project_id: Project ID
        bucket_name: Name of the bucket
    Returns:
        Dictionary containing bucket details or None if failed
    """
    try:
        bucket_details = run_openstack_command(
            ["openstack", "container", "show", "--os-project-id", project_id, bucket_name, "-f", "json"]
        )
        if not bucket_details:
            logging.warning(f"Failed to fetch details for bucket {bucket_name}")
            return None

        read_acl = bucket_details.get('read_acl', '').strip()
        write_acl = bucket_details.get('write_acl', '').strip() if 'write_acl' in bucket_details else ''
        
        if ".r:*" in read_acl or read_acl == "*":
            if "*" in write_acl or ".r:*" in write_acl:
                bucket_severity = "critical"
            else:
                bucket_severity = "high"
            is_public = "red"
        else:
            is_public = "green"
            bucket_severity = "low"
            
        return {
            "bucket_name": bucket_name,
            "is_public": is_public,
            "bucket_severity": bucket_severity
        }
    except Exception as e:
        logging.warning(f"Error fetching bucket details for {bucket_name}: {e}")
        return None

def fetch_buckets(selected_projects, threads=5):
    """
    Fetch bucket information for selected projects.
    Args:
        selected_projects: List of selected projects
        threads: Number of threads for parallel processing
    Returns:
        List of bucket information
    """
    buckets_info = []
    for project in selected_projects:
        project_id = project['id']
        project_name = project['name']
        
        try:
            bucket_list_result = run_openstack_command(
                ["openstack", "container", "list", "--os-project-id", project_id, "-f", "json"]
            )
            if not bucket_list_result:
                logging.warning(f"No buckets found for project {project_name}")
                continue

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_bucket = {
                    executor.submit(fetch_bucket_details, project_id, b['Name']): b['Name']
                    for b in bucket_list_result
                }
                for future in future_to_bucket:
                    try:
                        bucket_details = future.result()
                        if bucket_details:
                            buckets_info.append({**bucket_details, "project_name": project_name})
                    except Exception as e:
                        logging.warning(f"Error processing bucket {future_to_bucket[future]}: {e}")
                        
        except Exception as e:
            logging.warning(f"Error fetching buckets for project {project_name}: {e}")
            continue
            
    return buckets_info

def fetch_user_roles(conn, project_id):
    users_roles_info = []
    try:
        role_assignments = conn.identity.role_assignments()
        for assignment in role_assignments:
            if 'project' in assignment.scope and assignment.scope['project']['id'] == project_id:
                user_obj = assignment.get('user')
                if user_obj is None:
                    continue
                user = conn.identity.get_user(user_obj['id'])
                role = conn.identity.get_role(assignment.role['id'])
                user_name = user.name
                users_roles_info.append((user_name, role.name))
    except Exception:
        pass
    return users_roles_info

def get_name_from_image_flavor(value):
    if isinstance(value, dict):
        return value.get('name', '')
    return str(value)

def check_outdated_image_flavor(image, flavor):
    issues = []
    image_name = get_name_from_image_flavor(image)
    flavor_name = get_name_from_image_flavor(flavor)
    ilower = image_name.lower()
    flower = flavor_name.lower()
    for pat in OUTDATED_PATTERNS:
        if pat in ilower or pat in flower:
            if 'eol' in pat or 'endoflife' in pat:
                issues.append(("critical", f"Outdated image/flavor detected ({image_name}, {flavor_name}). This is end-of-life and very critical."))
            else:
                issues.append(("critical", f"Outdated image/flavor detected ({image_name}, {flavor_name}). Update to a supported version."))
            break
    return issues

def run_openstack_network_show(network_name):
    if network_name in network_info_cache:
        return network_info_cache[network_name]
    net_info = run_openstack_command(["openstack", "network", "show", network_name, "-f", "json"])
    network_info_cache[network_name] = net_info
    return net_info

def is_ip_public(ip_str):
    ip_obj = ipaddress.ip_address(ip_str)
    return not ip_obj.is_private

def check_network_setup(addresses):
    issues = []
    if isinstance(addresses, dict):
        for netname, ipinfo in addresses.items():
            net_info = run_openstack_network_show(netname)
            if net_info and net_info.get('router:external') == 'True':
                ips = []
                if isinstance(ipinfo, list):
                    for elem in ipinfo:
                        if isinstance(elem, dict):
                            ip = elem.get('addr','')
                            if ip and is_ip_public(ip):
                                ips.append(ip)
                        elif isinstance(elem, str):
                            ip = elem.strip()
                            if ip and is_ip_public(ip):
                                ips.append(ip)
                elif isinstance(ipinfo, str):
                    ip = ipinfo.strip()
                    if ip and is_ip_public(ip):
                        ips.append(ip)
                if ips:
                    if netname.lower() == "management":
                        for ip in ips:
                            issues.append(("critical", f"Instance connected to a public (external) management network ({netname}) with IP {ip}. Immediate action required!"))
                    else:
                        for ip in ips:
                            issues.append(("high", f"Instance connected to a public (external) network ({netname}) with IP {ip}. Restrict public exposure."))
    return issues

def analyze_instance_issues(instance_data):
    issues = []
    image = instance_data.get('image', '')
    flavor = instance_data.get('flavor', '')
    addresses = instance_data.get('addresses', {})

    issues.extend(check_outdated_image_flavor(image, flavor))
    net_issues = check_network_setup(addresses)
    issues.extend(net_issues)
    return issues

def analyze_suspicious_usernames(user_roles):
    issues = []
    for user, role in user_roles:
        user_is_admin = (role.lower() == 'admin')
        if user_is_admin:
            if user in ALLOWED_ADMIN_USERS:
                # allowed admin user, no issue
                pass
            else:
                # not in allowed admin users
                if "test" in user.lower():
                    issues.append(("critical", f"Admin user '{user}' not in allowed list and contains 'test'. Immediate review required!"))
                else:
                    issues.append(("high", f"Admin user '{user}' not in allowed list. Check manually."))
        # if not admin => no issue
    return issues

def extract_all_networks(data):
    net_names = set()
    for proj_name, details in data.items():
        for instance in details.get('instances', []):
            addresses = instance.get('addresses', {})
            if isinstance(addresses, dict):
                for netname in addresses.keys():
                    net_names.add(netname)
    return net_names

def prefetch_network_info(net_names, threads=5):
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(run_openstack_command, ["openstack", "network", "show", netname, "-f", "json"]): netname for netname in net_names}
        for future in futures:
            netname = futures[future]
            net_info = future.result()
            network_info_cache[netname] = net_info

def fetch_data(conn, selected_projects, threads=5):
    print(Fore.CYAN + "Scanning selected projects... Please wait.")
    spinner_chars = "|/-\\"
    idx = 0
    project_data = {}
    for project in selected_projects:
        sys.stdout.write(Fore.YELLOW + f"\rScanning project: {project['name']} {spinner_chars[idx % len(spinner_chars)]}")
        sys.stdout.flush()
        idx += 1
        project_id = project['id']
        instances = fetch_instances(project_id)
        full_instances_data = []
        for instance in instances:
            details = fetch_instance_details(instance['ID'], project_id)
            instance['metadata'] = details['metadata']
            instance['security_groups'] = details['security_groups']
            instance['image'] = details['image']
            instance['flavor'] = details['flavor']
            instance['addresses'] = details['addresses']
            full_instances_data.append(instance)

        security_groups = fetch_security_groups(conn, project_id)
        user_roles_list = fetch_user_roles(conn, project_id)
        buckets = fetch_buckets([project], threads=threads)

        project_data[project['name']] = {
            "project_id": project_id,
            "instances": full_instances_data,
            "security_groups": security_groups,
            "buckets": buckets,
            "user_roles": user_roles_list
        }
    sys.stdout.write("\n")

    all_networks = extract_all_networks(project_data)
    prefetch_network_info(all_networks, threads=threads)

    return project_data

def analyze_issues(data):
    issues = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }

    for project, details in data.items():
        project_id = details.get('project_id', project)

        # Instances
        for instance in details.get('instances', []):
            instance_name = instance.get('Name', 'Unknown')
            instance_id = instance.get('ID', 'Unknown')
            meta_issues = analyze_metadata_for_issues(instance.get('metadata', {}))
            inst_issues = analyze_instance_issues(instance)
            anchor = f"{project_id}_instance_{instance_id}"
            for level, msg in meta_issues + inst_issues:
                issues[level].append(f"[{project}] <a href='#{anchor}'>Instance {instance_name}</a> - {msg}")

        # Security Groups
        for sg in details.get('security_groups', []):
            sg_name = sg['group_name']
            sg_id = sg['group_id']
            sg_anchor = f"{project_id}_sg_{sg_id}"
            for rule in sg['risky_rules']:
                lvl = rule['level']
                advice = rule['advice']
                direction = rule['direction']
                port_range = rule['port_range']
                issues[lvl].append(
                    f"[{project}] <a href='#{sg_anchor}'>Security Group {sg_name}</a> rule: "
                    f"IP={rule['remote_ip_prefix']} Protocol={rule['protocol']} Direction={direction} Port={port_range} - {advice}"
                )

        # Buckets
        for bucket in details.get('buckets', []):
            bucket_name = bucket['bucket_name']
            bucket_anchor = f"{project_id}_bucket_{bucket_name}"
            bucket_sev = bucket['bucket_severity']
            if bucket_sev == 'critical':
                issues["critical"].append(f"[{project}] <a href='#{bucket_anchor}'>Public bucket with write access: {bucket_name}</a>")
            elif bucket_sev == 'high':
                issues["high"].append(f"[{project}] <a href='#{bucket_anchor}'>Public bucket: {bucket_name}</a>")

        # User Roles
        suspicious_user_issues = analyze_suspicious_usernames(details.get('user_roles', []))
        for level, msg in suspicious_user_issues:
            issues[level].append(f"[{project}] {msg}")

    return issues

def generate_json_report(issues_data, output_file="report.json"):
    """
    Generate a JSON report of security findings.
    Args:
        issues_data: Dictionary containing scan results
        output_file: Path to save the JSON report
    """
    if not issues_data:
        logging.warning("No issues data to generate JSON report")
        return

    try:
        with open(output_file, "w") as f:
            json.dump(issues_data, f, indent=4)
        print(f"JSON report generated: {output_file}")
    except Exception as e:
        logging.error(f"Failed to generate JSON report: {e}")

def generate_html_report(data, output_file="report.html"):
    """
    Generate an HTML report of security findings.
    Args:
        data: Dictionary containing scan results
        output_file: Path to save the HTML report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    issues_data = analyze_issues(data)

    # Generate issues HTML
    issues_html = ""
    for severity in ["critical", "high", "medium", "low"]:
        if issues_data[severity]:
            issues_html += f"""
            <div class="issues-section">
                <h2 class="{severity}">{severity.title()} Issues</h2>
                <ul class="issues-list">
                    {''.join(f'<li class="{severity}">{issue}</li>' for issue in issues_data[severity])}
                </ul>
            </div>
            """

    # Generate project details HTML
    projects_html = ""
    for project, details in data.items():
        project_id = details['project_id']
        proj_id_html = project_id.replace(" ", "_")

        projects_html += f"""
        <div class="project-section">
            <h2 id="{proj_id_html}">Project: {project}</h2>
        """

        # Instances
        projects_html += f"""
            <div class="instances-section">
                <h3 id='{proj_id_html}_instances'>Instances</h3>
        """
        if not details.get('instances'):
            projects_html += "<p>No instances found.</p>"
        else:
            for instance in details.get('instances', []):
                instance_id = instance.get('ID', 'Unknown')
                instance_name = instance.get('Name', 'Unknown')
                inst_anchor = f"{proj_id_html}_instance_{instance_id}"
                metadata = instance.get('metadata', {})
                
                projects_html += f"""
                    <div class="instance-details">
                        <h4 id="{inst_anchor}">Instance: {instance_name} ({instance_id})</h4>
                        <div class="metadata">
                            <h5>Metadata:</h5>
                            <ul>
                """
                
                # Sort metadata for better readability
                sorted_metadata = sorted(metadata.items())
                for key, value in sorted_metadata:
                    if isinstance(value, dict):
                        value = json.dumps(value, indent=2)
                    projects_html += f"<li><strong>{key}:</strong> {value}</li>"
                
                projects_html += """
                            </ul>
                        </div>
                    </div>
                """

        projects_html += "</div>"  # Close instances-section

        # Security Groups
        projects_html += f"""
            <div class="security-groups-section">
                <h3 id='{proj_id_html}_security_groups'>Security Groups</h3>
        """
        sgs = details.get('security_groups', [])
        if not sgs:
            projects_html += "<p>No security groups found.</p>"
        else:
            for sg in sgs:
                sg_id = sg['group_id']
                sg_name = sg['group_name']
                sg_anchor = f"{proj_id_html}_sg_{sg_id}"
                projects_html += f"""
                    <div class="security-group-details">
                        <h4 id="{sg_anchor}">Security Group: {sg_name} (ID: {sg_id})</h4>
                """
                
                if not sg['risky_rules']:
                    projects_html += "<p>No risky rules found.</p>"
                else:
                    projects_html += "<ul class='security-rules'>"
                    for rule in sg['risky_rules']:
                        tooltip = f"Direction: {rule['direction']}, Port: {rule['port_range']}"
                        projects_html += f"""
                            <li class='{rule["level"]}' title='{tooltip}'>
                                IP={rule['remote_ip_prefix']} Protocol={rule['protocol']} Level={rule['level']}<br>
                                <em>{rule['advice']}</em>
                            </li>
                        """
                    projects_html += "</ul>"
                projects_html += "</div>"
        
        projects_html += "</div>"  # Close security-groups-section

        # Buckets
        projects_html += f"""
            <div class="buckets-section">
                <h3 id='{proj_id_html}_buckets'>Buckets</h3>
        """
        bucket_list = details.get('buckets', [])
        if not bucket_list:
            projects_html += "<p>No buckets found.</p>"
        else:
            for bucket in bucket_list:
                bucket_name = bucket['bucket_name']
                bucket_anchor = f"{proj_id_html}_bucket_{bucket_name}"
                bucket_color = bucket['is_public']
                bucket_sev = bucket['bucket_severity']
                projects_html += f"""
                    <div class="bucket-details">
                        <h4 id="{bucket_anchor}">Bucket: {bucket_name}</h4>
                """
                if bucket_sev == "critical":
                    projects_html += f"<p class='critical'>This bucket is Public with Write Access (Critical severity)</p>"
                elif bucket_sev == "high":
                    projects_html += f"<p class='high'>This bucket is Public (High severity)</p>"
                else:
                    projects_html += f"<p class='low'>This bucket is Not Public</p>"
                projects_html += "</div>"
        
        projects_html += "</div>"  # Close buckets-section

        # User Roles
        projects_html += f"""
            <div class="user-roles-section">
                <h3 id='{proj_id_html}_user_roles'>User Roles</h3>
        """
        user_roles = details.get('user_roles', [])
        if not user_roles:
            projects_html += "<p>No user roles found.</p>"
        else:
            projects_html += "<ul class='user-roles-list'>"
            for user, role in user_roles:
                user_anchor = f"{proj_id_html}_user_{user}"
                role_class = "critical" if role.lower() == 'admin' else "low"
                projects_html += f'<li id="{user_anchor}">{user}: <span class="{role_class}">{role}</span></li>'
            projects_html += "</ul>"
        
        projects_html += "</div>"  # Close user-roles-section
        projects_html += "</div>"  # Close project-section

    # Update CSS for new sections
    additional_css = """
        .instance-details, .security-group-details, .bucket-details {
            background-color: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid #dee2e6;
        }

        .metadata ul {
            list-style: none;
            padding-left: 20px;
        }

        .metadata li {
            margin: 5px 0;
            word-break: break-word;
        }

        .security-rules li {
            margin: 10px 0;
            padding: 10px;
            background-color: #fff;
            border-radius: 4px;
        }

        .user-roles-list li {
            margin: 5px 0;
        }

        .project-section {
            margin-top: 40px;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        h3 {
            color: #2c3e50;
            margin-top: 25px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }

        h4 {
            color: #34495e;
            margin-top: 15px;
        }

        .metadata h5 {
            color: #455a64;
            margin: 10px 0;
        }
    """

    # Use the HTML_TEMPLATE
    template = Template(HTML_TEMPLATE)
    
    with open(output_file, "w") as f:
        f.write(template.substitute(
            timestamp=timestamp,
            issues_html=issues_html,
            projects_html=projects_html,
            additional_css=additional_css
        ))
    
    print(f"HTML report generated: {output_file}")
    return issues_data

def main():
    parser = argparse.ArgumentParser(description="OpenStack Pentest Reporter")
    parser.add_argument("--report-file", default="report.html", help="Output HTML report file name")
    parser.add_argument("--json-report", action="store_true", help="Also produce a JSON report")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for parallel operations")
    args = parser.parse_args()

    try:
        conn = get_connection()
        all_projects = get_all_projects(conn)
        
        if not all_projects:
            logging.error("No projects found. Please check your OpenStack connection and credentials.")
            return

        print(f"Found {len(all_projects)} projects")
        selected_projects = user_select_projects(all_projects)
        
        if not selected_projects:
            logging.error("No projects selected. Exiting.")
            return

        data = fetch_data(conn, selected_projects, threads=args.threads)
        if not data:
            logging.error("No data collected. Please check your OpenStack connection and permissions.")
            return

        issues_data = analyze_issues(data)
        generate_html_report(data, args.report_file)

        if args.json_report:
            generate_json_report(issues_data, "report.json")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
