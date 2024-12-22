import subprocess
import json
import openstack
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from string import Template
from datetime import datetime
from colorama import init, Fore, Style
import sys
import ipaddress
import os
import re

init(autoreset=True)
logging.basicConfig(level=logging.WARNING, format='%(asctime)s [%(levelname)s]: %(message)s')

DEFAULT_SENSITIVE_KEYWORDS = ["password", "secret_key", "auth_token", "private_key", "db_password", "aws_secret_access_key", "pass"]
DEFAULT_CREDENTIAL_KEYWORDS = ["root", "admin", "administrator"]
# Suspicious patterns logic removed, not needed
DEFAULT_ALLOWED_ADMIN_USERS = ["ops_admin", "administrator", "admin"]

OUTDATED_PATTERNS = ["14.04", "trusty", "eol", "endoflife"]
KNOWN_HARMLESS_KEYS = ["root_device_name", "is_public"]

network_info_cache = {}

def load_config():
    if os.path.exists("config.json"):
        with open("config.json","r") as f:
            cfg = json.load(f)
        sens = cfg.get("SENSITIVE_KEYWORDS", DEFAULT_SENSITIVE_KEYWORDS)
        cred = cfg.get("CREDENTIAL_KEYWORDS", DEFAULT_CREDENTIAL_KEYWORDS)
        allowed_admin = cfg.get("ALLOWED_ADMIN_USERS", DEFAULT_ALLOWED_ADMIN_USERS)
        return sens, cred, allowed_admin
    else:
        return DEFAULT_SENSITIVE_KEYWORDS, DEFAULT_CREDENTIAL_KEYWORDS, DEFAULT_ALLOWED_ADMIN_USERS

SENSITIVE_KEYWORDS, CREDENTIAL_KEYWORDS, ALLOWED_ADMIN_USERS = load_config()

MANAGEMENT_PORTS = [22, 443, 3389]
SENSITIVE_PATTERNS_CRITICAL = [
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "AKIA"
]

def get_connection(project_name=None):
    return openstack.connect(project_name=project_name) if project_name else openstack.connect()

def user_select_projects(projects):
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

    print(Fore.GREEN + "\nEnter the numbers of projects to scan, separated by commas (e.g., 1,3,5 or 'A' for all): ", end="")
    selection = input().strip()
    if selection.lower() == 'a':
        return projects
    selected_indexes = [int(idx.strip()) - 1 for idx in selection.split(",") if idx.strip().isdigit()]
    return [projects[idx] for idx in selected_indexes if 0 <= idx < len(projects)]

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
    bucket_details = run_openstack_command(
        ["openstack", "container", "show", "--os-project-id", project_id, bucket_name, "-f", "json"]
    )
    if not bucket_details:
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
    return {"bucket_name": bucket_name, "is_public": is_public, "bucket_severity": bucket_severity}

def fetch_buckets(selected_projects, threads=5):
    buckets_info = []
    for project in selected_projects:
        project_id = project['id']
        project_name = project['name']
        bucket_list_result = run_openstack_command(
            ["openstack", "container", "list", "--os-project-id", project_id, "-f", "json"]
        )
        if not bucket_list_result:
            continue
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_bucket = {
                executor.submit(fetch_bucket_details, project_id, b['Name']): b['Name']
                for b in bucket_list_result
            }
            for future in future_to_bucket:
                bucket_details = future.result()
                if bucket_details:
                    buckets_info.append({**bucket_details, "project_name": project_name})
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
    # Yeni mantık:
    # Admin user:
    #   - In allowed list => no issue
    #   - Not in allowed list:
    #       if 'test' in user => critical
    #       else => high
    # Non-admin user => no issue
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
    json_data = {}
    for sev in issues_data:
        json_data[sev] = issues_data[sev]
    with open(output_file, "w") as f:
        json.dump(json_data, f, indent=4)
    print(f"JSON report generated: {output_file}")

def generate_html_report(data, output_file="report.html"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    issues_data = analyze_issues(data)

    severity_legend = """
<p><strong>Severity Legend:</strong></p>
<ul>
<li><span class='critical'>Critical:</span> Immediate action required, severe exposure.</li>
<li><span class='high'>High:</span> High risk, address as soon as possible.</li>
<li><span class='medium'>Medium:</span> Moderate risk, review timely.</li>
<li><span class='low'>Low:</span> Low risk, consider improvements.</li>
</ul>
"""

    search_box = """
<div>
<input type="text" id="searchBox" placeholder="Search issues..." onkeyup="searchIssues()" />
</div>
<script>
function searchIssues() {
    var input = document.getElementById('searchBox');
    var filter = input.value.toLowerCase();
    var lists = document.getElementsByTagName('li');
    for (var i = 0; i < lists.length; i++) {
        var txtValue = lists[i].textContent || lists[i].innerText;
        if (txtValue.toLowerCase().indexOf(filter) > -1) {
            lists[i].style.display = '';
        } else {
            lists[i].style.display = 'none';
        }
    }
}
</script>
"""

    script_js = """
<script>
window.onscroll = function() {
    var topButton = document.getElementById("gototop");
    if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {
        topButton.style.display = "block";
    } else {
        topButton.style.display = "none";
    }
};
</script>
"""

    template_html = Template(f"""
<html>
<head>
<title>OpenStack Pentest Report</title>
<style>
    body {{font-family: Arial, sans-serif; font-size: 14px;}}
    h1,h2,h3,h4,h5 {{font-family: Arial, sans-serif;}}
    ul {{list-style: disc; margin-left: 20px;}}
    .red {{color: red;}}
    .green {{color: green;}}
    .orange {{color: orange;}}
    .issues {{border: 1px solid #ccc; padding: 10px; margin-top:20px; background-color: #fafafa;}}
    h2.issues-title {{color: #000;}}
    .critical {{color: #B22222;}}
    .high {{color: red;}}
    .medium {{color: orange;}}
    .low {{color: blue;}}
    #top {{margin-bottom:20px;}}
    #gototop {{
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #eee;
        border: 1px solid #ccc;
        padding: 10px;
        text-decoration: none;
        color: #333;
        font-weight: bold;
        border-radius: 5px;
        display: none;
    }}
    #gototop:hover {{
        background: #ddd;
    }}
</style>
{script_js}
</head>
<body>
<div id="top"></div>
<h1>OpenStack Pentest Report</h1>
<p>Report generated at: $timestamp</p>
{severity_legend}
{search_box}
<div class="issues">
<h2 class="issues-title">Potential Issues</h2>
$issues_html
</div>

$projects_html

<a id="gototop" href="#top">↑ Top</a>

</body>
</html>
""")

    issues_html = ""
    has_issues = False
    severity_order = [("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low")]
    issues_data = analyze_issues(data)
    for sev_level, sev_class in severity_order:
        if issues_data[sev_level]:
            has_issues = True
            issues_html += f"<h3 class='{sev_class}'>{sev_level.capitalize()} Issues:</h3><ul>"
            for issue in issues_data[sev_level]:
                issues_html += f"<li>{issue}</li>"
            issues_html += "</ul>"

    if not has_issues:
        issues_html = "<p>No potential issues found.</p>"

    projects_html = ""
    for project, details in data.items():
        project_id = details['project_id']
        proj_id_html = project_id.replace(" ", "_")

        projects_html += f'<h2 id="{proj_id_html}">Project: {project}</h2>'

        # Instances
        projects_html += f"<h3 id='{proj_id_html}_instances'>Instances</h3>"
        if not details.get('instances'):
            projects_html += "<p>No instances found.</p>"
        for instance in details.get('instances', []):
            instance_id = instance.get('ID', 'Unknown')
            instance_name = instance.get('Name', 'Unknown')
            inst_anchor = f"{proj_id_html}_instance_{instance_id}"
            projects_html += f'<h4 id="{inst_anchor}">Instance: {instance_name} ({instance_id})</h4>'
            metadata = instance.get('metadata', {})
            projects_html += "<h5>Metadata:</h5><ul>"
            for key, value in metadata.items():
                projects_html += f"<li>{key}: {value}</li>"
            projects_html += "</ul>"

        # Security Groups
        projects_html += f"<h3 id='{proj_id_html}_security_groups'>Security Groups</h3>"
        sgs = details.get('security_groups', [])
        if not sgs:
            projects_html += "<p>No security groups found.</p>"
        else:
            for sg in sgs:
                sg_id = sg['group_id']
                sg_name = sg['group_name']
                sg_anchor = f"{proj_id_html}_sg_{sg_id}"
                projects_html += f'<h4 id="{sg_anchor}">Security Group: {sg_name} (ID: {sg_id})</h4>'
                if not sg['risky_rules']:
                    projects_html += "<p>No risky rules found.</p>"
                else:
                    projects_html += "<ul>"
                    for rule in sg['risky_rules']:
                        tooltip = f"Direction: {rule['direction']}, Port: {rule['port_range']}"
                        projects_html += (
                            f"<li class='{rule['level']}' title='{tooltip}'>"
                            f"IP={rule['remote_ip_prefix']} Protocol={rule['protocol']} Level={rule['level']}<br>"
                            f"<i>{rule['advice']}</i></li>"
                        )
                    projects_html += "</ul>"

        # Buckets
        projects_html += f"<h3 id='{proj_id_html}_buckets'>Buckets</h3>"
        bucket_list = details.get('buckets', [])
        if not bucket_list:
            projects_html += "<p>No buckets found.</p>"
        else:
            for bucket in bucket_list:
                bucket_name = bucket['bucket_name']
                bucket_anchor = f"{proj_id_html}_bucket_{bucket_name}"
                bucket_color = bucket['is_public']
                bucket_sev = bucket['bucket_severity']
                projects_html += f'<h4 id="{bucket_anchor}">Bucket: {bucket_name}</h4>'
                if bucket_sev == "critical":
                    projects_html += f"<p class='red'>This bucket is Public with Write Access (Critical severity)</p>"
                elif bucket_sev == "high":
                    projects_html += f"<p class='red'>This bucket is Public (High severity)</p>"
                else:
                    projects_html += f"<p class='{bucket_color}'>This bucket is Not Public</p>"

        # User Roles
        projects_html += f"<h3 id='{proj_id_html}_user_roles'>User Roles</h3>"
        user_roles = details.get('user_roles', [])
        if not user_roles:
            projects_html += "<p>No user roles found.</p>"
        else:
            projects_html += "<ul>"
            for user, role in user_roles:
                user_anchor = f"{proj_id_html}_user_{user}"
                color = "red" if role.lower() == 'admin' else "green"
                projects_html += f'<li id="{user_anchor}">{user}: <span class="{color}">{role}</span></li>'
            projects_html += "</ul>"

    html_content = template_html.substitute(timestamp=timestamp, projects_html=projects_html, issues_html=issues_html)

    with open(output_file, "w") as file:
        file.write(html_content)
    print(f"HTML report generated: {output_file}")

    return issues_data

def main():
    parser = argparse.ArgumentParser(description="OpenStack Pentest Reporter")
    parser.add_argument("--report-file", default="report.html", help="Output HTML report file name")
    parser.add_argument("--json-report", action="store_true", help="Also produce a JSON report")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for parallel operations")
    args = parser.parse_args()

    # RC dosyasını source etmeli:
    # source admin-openrc.sh

    conn = get_connection()
    all_projects = get_all_projects(conn)
    selected_projects = user_select_projects(all_projects)

    data = fetch_data(conn, selected_projects, threads=args.threads)
    issues_data = generate_html_report(data, args.report_file)

    if args.json_report:
        generate_json_report(issues_data, "report.json")

if __name__ == "__main__":
    main()
