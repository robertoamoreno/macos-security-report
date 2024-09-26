#!/usr/bin/env python3
import os
import subprocess
import plistlib
import time
import argparse
import inquirer
import gzip
import shutil
import requests
from collections import defaultdict
from pathlib import Path
import geoip2.database
import psutil
import subprocess
from datetime import datetime, timedelta
import hashlib
import re
import jinja2
import pdfkit
import platform
import platform

def get_running_processes():
    """Retrieve a list of running process names."""
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    processes = result.stdout.strip().split('\n')[1:]  # Skip header
    return [p.split()[10] for p in processes]  # Get just the process names

def get_launchd_services():
    """Retrieve a dictionary of launchd services."""
    services = defaultdict(list)
    launchd_dirs = [
        '/Library/LaunchDaemons',
        '/Library/LaunchAgents',
        os.path.expanduser('~/Library/LaunchAgents'),
        '/System/Library/LaunchDaemons',
        '/System/Library/LaunchAgents'
    ]
    
    for directory in launchd_dirs:
        if os.path.exists(directory):
            for filename in os.listdir(directory):
                if filename.endswith('.plist'):
                    filepath = os.path.join(directory, filename)
                    with open(filepath, 'rb') as f:
                        try:
                            plist = plistlib.load(f)
                            if 'ProgramArguments' in plist:
                                services[directory].append(plist['ProgramArguments'][0])
                            elif 'Program' in plist:
                                services[directory].append(plist['Program'])
                        except Exception as e:
                            print(f"Error parsing {filepath}: {e}")
    return services

def get_applications():
    """Retrieve a list of installed applications and check for unsigned apps."""
    app_dirs = ['/Applications', os.path.expanduser('~/Applications')]
    apps = []
    unsigned_apps = []
    for directory in app_dirs:
        if os.path.exists(directory):
            for app in os.listdir(directory):
                if app.endswith('.app'):
                    apps.append(app)
                    app_path = os.path.join(directory, app)
                    result = subprocess.run(['codesign', '-v', app_path], capture_output=True, text=True)
                    if result.returncode != 0:
                        unsigned_apps.append(app)
    return apps, unsigned_apps

def get_homebrew_services():
    """Retrieve a list of Homebrew services."""
    result = subprocess.run(['brew', 'services', 'list'], capture_output=True, text=True)
    services = result.stdout.strip().split('\n')[1:]  # Skip header
    return [s.split()[0] for s in services]

def get_macports_services():
    """Retrieve a list of MacPorts services."""
    result = subprocess.run(['port', 'echo', 'installed', 'and', 'active'], capture_output=True, text=True)
    services = result.stdout.strip().split('\n')
    return [s.split('@')[0].strip() for s in services]

def get_network_connections():
    """Retrieve a list of current network connections."""
    result = subprocess.run(['lsof', '-i', '-n', '-P'], capture_output=True, text=True)
    connections = result.stdout.strip().split('\n')[1:]  # Skip header
    parsed_connections = []
    for conn in connections:
        parts = conn.split()
        if len(parts) >= 9:
            parsed_connections.append({
                'name': parts[0],
                'pid': parts[1],
                'user': parts[2],
                'fd': parts[3],
                'type': parts[4],
                'device': parts[5],
                'size/off': parts[6],
                'node': parts[7],
                'name': parts[8]
            })
    return parsed_connections

def check_recently_modified_system_files(days=7):
    """Check for recently modified system files."""
    cmd = f"find /System /Library /usr -type f -mtime -{days} -print0 | xargs -0 ls -l"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def get_cron_jobs():
    """Retrieve all user cron jobs and scheduled tasks."""
    cron_dirs = ['/etc/crontab', '/etc/cron.d', '/var/at/tabs']
    cron_jobs = []
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            if os.path.isfile(cron_dir):
                try:
                    with open(cron_dir, 'r') as f:
                        cron_jobs.extend(f.readlines())
                except PermissionError:
                    cron_jobs.append(f"Permission denied: Unable to read {cron_dir}")
            elif os.path.isdir(cron_dir):
                for root, _, files in os.walk(cron_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r') as f:
                                cron_jobs.extend(f.readlines())
                        except PermissionError:
                            cron_jobs.append(f"Permission denied: Unable to read {file_path}")
    
    try:
        at_jobs = subprocess.check_output(['atq'], universal_newlines=True).strip().split('\n')
        cron_jobs.extend(at_jobs)
    except (subprocess.CalledProcessError, FileNotFoundError):
        cron_jobs.append("Unable to check scheduled 'at' jobs")
    
    return cron_jobs

def find_hidden_files(directory):
    """Find hidden files and directories."""
    hidden = []
    for root, dirs, files in os.walk(directory):
        hidden.extend([os.path.join(root, f) for f in files if f.startswith('.')])
        hidden.extend([os.path.join(root, d) for d in dirs if d.startswith('.')])
    return hidden

def check_ssh_keys(authorized_keys):
    """Check for unauthorized SSH keys."""
    ssh_dir = os.path.expanduser('~/.ssh')
    authorized_keys_file = os.path.join(ssh_dir, 'authorized_keys')
    unauthorized_keys = []

    if os.path.exists(authorized_keys_file):
        try:
            with open(authorized_keys_file, 'r') as f:
                for key in f.readlines():
                    key_fingerprint = hashlib.md5(key.strip().encode()).hexdigest()
                    if not authorized_keys or key_fingerprint not in authorized_keys:
                        unauthorized_keys.append(key.strip())
        except PermissionError:
            unauthorized_keys.append("Permission denied: Unable to read authorized_keys file")
    else:
        unauthorized_keys.append("No authorized_keys file found")

    return unauthorized_keys

def scan_for_malware():
    """Perform an enhanced check for potentially malicious files on macOS/Linux."""
    suspicious_patterns = [
        r'backdoor', r'trojan', r'keylog', r'rootkit',  # Common malware terms
        r'\.dylib$', r'\.so$',  # Dynamic libraries
    ]
    
    # Whitelist of known safe directories and files
    whitelist = [
        '/System', '/Library', '/Applications',
        os.path.expanduser('~/Library'),
        os.path.expanduser('~/.vscode'),
        os.path.expanduser('~/.npm'),
    ]
    
    home_dir = os.path.expanduser('~')
    suspicious_files = []

    def is_whitelisted(path):
        return any(path.startswith(safe_path) for safe_path in whitelist)

    def calculate_file_hash(file_path):
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
            return file_hash.hexdigest()
        except Exception:
            return None

    for root, dirs, files in os.walk(home_dir):
        if is_whitelisted(root):
            continue
        for file in files:
            file_path = os.path.join(root, file)
            score = 0
            
            # Check file name against suspicious patterns
            if any(re.search(pattern, file.lower()) for pattern in suspicious_patterns):
                score += 1
            
            try:
                # Check if the file is executable or has unusual permissions
                file_stat = os.stat(file_path)
                if os.access(file_path, os.X_OK):
                    score += 1
                if file_stat.st_mode & 0o777 == 0o777:
                    score += 2
                
                # Check file signature (for macOS)
                if platform.system() == 'Darwin':
                    codesign_result = subprocess.run(['codesign', '-v', file_path], capture_output=True, text=True)
                    if codesign_result.returncode != 0:
                        score += 1
                
                # Calculate and check file hash (you would need to implement a check against a database of known malware hashes)
                file_hash = calculate_file_hash(file_path)
                if file_hash:
                    # Here you would check the hash against a database of known malware hashes
                    # For demonstration, we'll just add to the score if the hash ends with "bad" (not a real check)
                    if file_hash.endswith("bad"):
                        score += 3
                
                if score >= 2:
                    suspicious_files.append((file_path, score))
            except OSError:
                # If we can't check permissions or other attributes, consider it somewhat suspicious
                suspicious_files.append((file_path, 1))

    return sorted(suspicious_files, key=lambda x: x[1], reverse=True)

def check_outdated_software():
    """Check for outdated software using softwareupdate."""
    result = subprocess.run(['softwareupdate', '--list'], capture_output=True, text=True)
    return result.stdout.strip()

def verify_system_integrity():
    """Verify system integrity using csrutil."""
    result = subprocess.run(['csrutil', 'status'], capture_output=True, text=True)
    sip_status = result.stdout.strip()
    
    # Check if any kernel extensions are loaded
    kext_result = subprocess.run(['kextstat'], capture_output=True, text=True)
    loaded_kexts = kext_result.stdout.strip().split('\n')[1:]  # Skip header
    
    return f"System Integrity Protection (SIP) status:\n{sip_status}\n\nLoaded Kernel Extensions:\n" + \
           "\n".join(kext.split()[-1] for kext in loaded_kexts)

def check_firewall_status():
    """Check the status of the macOS firewall."""
    result = subprocess.run(['sudo', 'defaults', 'read', '/Library/Preferences/com.apple.alf', 'globalstate'], capture_output=True, text=True)
    status = result.stdout.strip()
    return "Enabled" if status == "1" else "Disabled"

def check_unauthorized_users():
    """Check for unauthorized users or groups."""
    # macOS default users and groups
    default_users = [
        'root', 'daemon', 'nobody', '_uucp', '_taskgated', '_networkd', '_installassistant',
        '_lp', '_postfix', '_scsd', '_ces', '_appstore', '_mcxalr', '_appleevents', '_geod',
        '_devdocs', '_sandbox', '_mdnsresponder', '_ard', '_www', '_eppc', '_cvs', '_svn',
        '_mysql', '_sshd', '_qtss', '_cyrus', '_mailman', '_appserver', '_clamav', '_amavisd',
        '_jabber', '_appowner', '_windowserver', '_spotlight', '_tokend', '_securityagent',
        '_calendar', '_teamsserver', '_update_sharing', '_installer', '_atsserver', '_ftp',
        '_unknown', '_softwareupdate', '_coreaudiod', '_screensaver', '_locationd', '_trustevaluationagent',
        '_timezone', '_lda', '_cvmsroot', '_usbmuxd', '_dovecot', '_dpaudio', '_postgres',
        '_krbtgt', '_kadmin_admin', '_kadmin_changepw', '_devicemgr', '_webauthserver',
        '_netbios', '_warmd', '_dovenull', '_netstatistics', '_avbdeviced', '_krb_krbtgt',
        '_krb_kadmin', '_krb_changepw', '_krb_kerberos', '_krb_anonymous', '_assetcache',
        '_coremediaiod', '_launchservicesd', '_iconservices', '_distnote', '_nsurlsessiond',
        '_displaypolicyd', '_astris', '_krbfast', '_gamecontrollerd', '_mbsetupuser',
        '_ondemand', '_xserverdocs', '_wwwproxy', '_mobileasset', '_findmydevice', '_datadetectors',
        '_captiveagent', '_ctkd', '_oahd', '_xserverdocs', '_wwwproxy', '_mobileasset',
        '_findmydevice', '_datadetectors', '_captiveagent', '_ctkd', '_oahd', '_gamed',
        '_syncservices', '_actionanalytics', '_analyticsd', '_fpsd', '_timed'
    ]
    default_groups = [
        'wheel', 'daemon', 'kmem', 'sys', 'tty', 'operator', 'mail', 'bin', 'staff',
        'certusers', 'admin', 'com.apple.access_screensharing', 'com.apple.access_ssh',
        'com.apple.access_ftp', 'com.apple.access_web', 'com.apple.access_remote_ae'
    ]

    users = subprocess.run(['dscl', '.', '-list', '/Users'], capture_output=True, text=True).stdout.strip().split('\n')
    groups = subprocess.run(['dscl', '.', '-list', '/Groups'], capture_output=True, text=True).stdout.strip().split('\n')

    unauthorized_users = [user for user in users if user not in default_users]
    unauthorized_groups = [group for group in groups if group not in default_groups]

    return unauthorized_users, unauthorized_groups

def check_disk_encryption():
    """Check the status of FileVault disk encryption."""
    result = subprocess.run(['fdesetup', 'status'], capture_output=True, text=True)
    return result.stdout.strip()

def check_geolite2_database():
    """Check if the GeoLite2 City database exists."""
    mmdb_file = "GeoLite2-City.mmdb"
    if not os.path.exists(mmdb_file):
        print(f"Error: {mmdb_file} not found. Please download it manually.")
        print("Visit https://dev.maxmind.com/geoip/geoip2/geolite2/ for instructions.")
        return False
    return True

def monitor_network_activity(duration=60):
    """Monitor network activity for the specified duration and report on destinations."""
    if not check_geolite2_database():
        return []

    connections = set()
    start_time = time.time()

    while time.time() - start_time < duration:
        try:
            for conn in psutil.net_connections():
                if conn.raddr and conn.raddr.ip:
                    connections.add(conn.raddr.ip)
        except psutil.AccessDenied:
            print("Access denied when trying to get network connections. Try running the script with sudo.")
            return []
        time.sleep(1)

    results = []
    with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
        for ip in connections:
            try:
                response = reader.city(ip)
                country = response.country.name or "Unknown Country"
                city = response.city.name or "Unknown City"
                results.append(f"{ip}: {city}, {country}")
            except geoip2.errors.AddressNotFoundError:
                results.append(f"{ip}: Location not found")

    return results

def generate_report(results, output_format='console'):
    if output_format == 'console':
        for section, content in sorted(results.items()):
            print(f"\n{section}:")
            print(content)
    else:
        template = jinja2.Template('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>macOS Security and Process Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #2980b9; margin-top: 30px; }
                pre { background-color: #f8f8f8; border: 1px solid #ddd; border-radius: 4px; padding: 10px; white-space: pre-wrap; word-wrap: break-word; }
            </style>
        </head>
        <body>
            <h1>macOS Security and Process Report</h1>
            {% for section, content in results|dictsort %}
                <h2>{{ section }}</h2>
                <pre>{{ content }}</pre>
            {% endfor %}
        </body>
        </html>
        ''')
        
        html_output = template.render(results=results)
        
        if output_format == 'html':
            with open('security_report.html', 'w') as f:
                f.write(html_output)
            print("HTML report saved as security_report.html")
        
        elif output_format == 'pdf':
            pdfkit.from_string(html_output, 'security_report.pdf')
            print("PDF report saved as security_report.pdf")

def main():
    parser = argparse.ArgumentParser(description="macOS Security and Process Report")
    parser.add_argument("--cli", action="store_true", help="Use CLI menu to select checks")
    parser.add_argument("--authorized-keys", type=str, default='', help="Comma-separated list of authorized SSH key fingerprints")
    parser.add_argument("--output", choices=['console', 'html', 'pdf'], default='console', help="Output format")
    args = parser.parse_args()

    all_checks = [
        ('Check running processes', 'check_processes'),
        ('Check launchd services', 'check_launchd'),
        ('Check applications', 'check_applications'),
        ('Check Homebrew services', 'check_homebrew'),
        ('Check MacPorts services', 'check_macports'),
        ('Check modified files', 'check_modified_files'),
        ('Monitor network activity', 'monitor_network'),
        ('Check hidden files', 'check_hidden_files'),
        ('Check cron jobs', 'check_cron_jobs'),
        ('Check SSH keys', 'check_ssh_keys'),
        ('Scan for malware', 'scan_malware'),
        ('Check for outdated software', 'check_outdated_software'),
        ('Verify system integrity', 'verify_system_integrity'),
        ('Check firewall status', 'check_firewall_status'),
        ('Check for unauthorized users', 'check_unauthorized_users'),
        ('Check disk encryption status', 'check_disk_encryption'),
    ]

    if args.cli:
        questions = [
            inquirer.Checkbox('checks',
                              message="Select the checks you want to perform",
                              choices=[('All checks', 'all')] + all_checks,
                              ),
        ]
        answers = inquirer.prompt(questions)
        selected_checks = answers['checks']
        if 'all' in selected_checks:
            selected_checks = [check[1] for check in all_checks]
    else:
        selected_checks = [check[1] for check in all_checks]

    # Convert selected_checks to a namespace-like object for compatibility with the rest of the code
    class Namespace:
        pass
    args_namespace = Namespace()
    for check in selected_checks:
        setattr(args_namespace, check, True)
    args_namespace.authorized_keys = args.authorized_keys

    print("macOS Security and Process Report")
    print("==================================")

    results = {}
    running_processes = []

    def run_check(check_name, check_function, *args):
        print(f"Running {check_name}...")
        return check_function(*args)

    if hasattr(args_namespace, 'check_processes'):
        running_processes = run_check('Process Check', get_running_processes)
        results['Running Processes'] = f"Total running processes: {len(running_processes)}"

    if hasattr(args_namespace, 'check_launchd'):
        launchd_services = run_check('Launchd Services Check', get_launchd_services)
        results['Launchd Services'] = "\n".join([f"{directory}:\n" + "\n".join([f"  - {service} ({'RUNNING' if any(service in p for p in running_processes) else 'NOT RUNNING'})" for service in services]) for directory, services in launchd_services.items()])

    if hasattr(args_namespace, 'check_applications'):
        applications, unsigned_apps = run_check('Applications Check', get_applications)
        results['Installed Applications'] = f"Total installed applications: {len(applications)}\n\nRunning Applications:\n" + "\n".join([f"  - {app.replace('.app', '')}" for app in applications if any(app.replace('.app', '').lower() in p.lower() for p in running_processes)])
        if unsigned_apps:
            results['Unsigned Applications'] = "\n".join([f"  - {app}" for app in unsigned_apps])

    if hasattr(args_namespace, 'check_homebrew'):
        try:
            homebrew_services = run_check('Homebrew Services Check', get_homebrew_services)
            results['Homebrew Services'] = "\n".join([f"  - {service} ({'RUNNING' if any(service in p for p in running_processes) else 'NOT RUNNING'})" for service in homebrew_services])
        except FileNotFoundError:
            results['Homebrew Services'] = "Homebrew not installed or not in PATH"

    if hasattr(args_namespace, 'check_macports'):
        try:
            macports_services = run_check('MacPorts Services Check', get_macports_services)
            results['MacPorts Services'] = "\n".join([f"  - {service} ({'RUNNING' if any(service in p for p in running_processes) else 'NOT RUNNING'})" for service in macports_services])
        except FileNotFoundError:
            results['MacPorts Services'] = "MacPorts not installed or not in PATH"

    if hasattr(args_namespace, 'check_network'):
        connections = run_check('Network Connections Check', get_network_connections)
        results['Unusual Network Connections'] = "\n".join([f"  - Process: {conn['name']} (PID: {conn['pid']})\n    User: {conn['user']}, Type: {conn['type']}\n    Device: {conn['device']}, Node: {conn['node']}\n    Name: {conn['name']}\n" for conn in connections])

    if hasattr(args_namespace, 'check_modified_files'):
        modified_files = run_check('Modified Files Check', check_recently_modified_system_files)
        results['Recently Modified System Files'] = "\n".join([f"  - {file}" for file in modified_files[:10]])
        if len(modified_files) > 10:
            results['Recently Modified System Files'] += f"\n  ... and {len(modified_files) - 10} more"

    if hasattr(args_namespace, 'check_cron_jobs'):
        cron_jobs = run_check('Cron Jobs Check', get_cron_jobs)
        results['Cron Jobs and Scheduled Tasks'] = "\n".join([f"  {job}" if job.startswith("Permission denied:") or job.startswith("Unable to check") else f"  - {job.strip()}" for job in cron_jobs if not job.startswith('#') and job.strip()])

    if hasattr(args_namespace, 'check_hidden_files'):
        hidden = run_check('Hidden Files Check', find_hidden_files, os.path.expanduser('~'))
        results['Hidden Files and Directories'] = "\n".join([f"  - {item['path']} (Error: {item['error']})" if isinstance(item, dict) and 'error' in item else f"  - {item['path']} ({item['type']}, Size: {item['size']} bytes, Modified: {item['modified']})" if isinstance(item, dict) else f"  - {item}" for item in hidden[:10]])
        if len(hidden) > 10:
            results['Hidden Files and Directories'] += f"\n  ... and {len(hidden) - 10} more"

    if hasattr(args_namespace, 'check_ssh_keys'):
        authorized_keys = args_namespace.authorized_keys.split(',') if args_namespace.authorized_keys else []
        unauthorized_keys = run_check('SSH Keys Check', check_ssh_keys, authorized_keys)
        results['Unauthorized SSH Keys'] = "\n".join([f"  - {key}" for key in unauthorized_keys])

    if hasattr(args_namespace, 'scan_malware'):
        suspicious_files = run_check('Malware Scan', scan_for_malware)
        if suspicious_files:
            results['Potentially Malicious Files'] = "\n".join([f"  - {file} (Score: {score})" for file, score in suspicious_files[:10]])
            if len(suspicious_files) > 10:
                results['Potentially Malicious Files'] += f"\n  ... and {len(suspicious_files) - 10} more"
            results['Potentially Malicious Files'] += "\n\nWARNING: These files may be malicious. Please investigate further."
        else:
            results['Potentially Malicious Files'] = "No suspicious files found."
        results['Potentially Malicious Files'] += "\n\nNote: This is an enhanced check but does not guarantee the absence of malware.\nFor comprehensive malware detection, use dedicated antivirus software."

    if hasattr(args_namespace, 'monitor_network'):
        network_activity = run_check('Network Activity Monitor', monitor_network_activity)
        results['Network Activity'] = "\n".join([f"  - {result}" for result in network_activity])

    if hasattr(args_namespace, 'check_outdated_software'):
        results['Outdated Software'] = run_check('Outdated Software Check', check_outdated_software)

    if hasattr(args_namespace, 'verify_system_integrity'):
        results['System Integrity'] = run_check('System Integrity Check', verify_system_integrity)

    if hasattr(args_namespace, 'check_firewall_status'):
        results['Firewall Status'] = f"Firewall is {run_check('Firewall Status Check', check_firewall_status)}"

    if hasattr(args_namespace, 'check_unauthorized_users'):
        unauthorized_users, unauthorized_groups = run_check('Unauthorized Users Check', check_unauthorized_users)
        results['Unauthorized Users and Groups'] = "Unauthorized Users:\n" + "\n".join([f"  - {user}" for user in unauthorized_users]) if unauthorized_users else "No unauthorized users found."
        results['Unauthorized Users and Groups'] += "\n\nUnauthorized Groups:\n" + "\n".join([f"  - {group}" for group in unauthorized_groups]) if unauthorized_groups else "\nNo unauthorized groups found."

    if hasattr(args_namespace, 'check_disk_encryption'):
        results['Disk Encryption Status'] = run_check('Disk Encryption Check', check_disk_encryption)

    generate_report(results, args.output)

    # Print results to console
    if args.output == 'console':
        for section, content in results.items():
            print(f"\n{section}:")
            print(content)

if __name__ == "__main__":
    main()
