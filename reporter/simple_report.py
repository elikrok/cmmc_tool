
import csv
import hashlib
import os
import json

def generate_file_hash(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def write_result(result, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    txt_path = os.path.join(output_dir, 'compliance_result.txt')
    csv_path = os.path.join(output_dir, 'compliance_result.csv')
    file_hash = generate_file_hash(result['file_path'])

    with open(txt_path, 'a', encoding='utf-8') as f:
        if 'error' in result:
            f.write(f"ERROR: {result['error']}\n")
        else:
            f.write(f"Hostname: {result['hostname']}\n")
            status = 'COMPLIANT' if result['compliant'] else 'NOT COMPLIANT'
            f.write(f"Compliance Status: {status}\n\n")
            if 'checks' in result:
                f.write('Control Checks:\n')
                for control, data in result['checks'].items():
                    f.write(f"  - {control}: {'PASSED' if data.get('passed') else 'FAILED'}\n")
                    if control == 'CM.L1-3.4.1':
                        if data.get('missing_lines'):
                            f.write('    Missing vs Baseline:\n')
                            for line in data['missing_lines']:
                                f.write(f'      • {line}\n')
                        if data.get('extra_lines'):
                            f.write('    Unexpected vs Baseline:\n')
                            for line in data['extra_lines']:
                                f.write(f'      • {line}\n')
                    if control == 'AC.L1-3.1.1':
                        f.write(f"    AAA configured: {'Yes' if data.get('aaa_configured') else 'No'}\n")
                        f.write(f"    TACACS servers: {', '.join(data.get('tacacs_servers', [])) or 'None'}\n")
                        if data.get('connectivity_skipped'):
                            f.write('    Connectivity: SKIPPED (user selected)\n')
                        elif data.get('tacacs_reachability'):
                            f.write('    TACACS reachability:\n')
                            for srv, ok in data['tacacs_reachability'].items():
                                f.write(f"      • {srv}: {'reachable' if ok else 'no response'}\n")
                    if control == 'AC.L1-3.1.2':
                        f.write(f"    enable secret present: {'Yes' if data.get('enable_secret_present') else 'No'}\n")
                        f.write(f"    user privileges/roles parsed: {bool(data.get('user_privileges'))}\n")
                        f.write(f"    telnet disabled on VTY: {'Yes' if data.get('no_telnet') else 'No'}\n")
                    if control == 'SC.L1-3.13.1':
                        f.write(f"    SSH-only mgmt: {'Yes' if data.get('ssh_mgmt') else 'No'}\n")
                        f.write(f"    ACLs present & applied: {'Yes' if data.get('acls_present_and_applied') else 'No'}\n")
                        f.write(f"    mgmt ACL bound (vty/access-class or Mgmt1 ACL): {'Yes' if data.get('mgmt_acl_signal') else 'No'}\n")
                        f.write(f"    mgmt VRF or Mgmt1 present: {'Yes' if data.get('mgmt_vrf_or_mgmt1') else 'No'}\n")
                    if control == 'SC.L1-3.13.5':
                        missing = data.get('dmz_interfaces_without_acl', [])
                        if missing:
                            f.write('    DMZ interfaces missing ACL binding:\n')
                            for iface in missing:
                                f.write(f'      • {iface}\n')
            f.write('\nEvidence:\n')
            f.write(f'  • File Hash (SHA-256): {file_hash}\n')
            f.write(f"  • Evidence File: {result['file_path']}\n")
            f.write('\n' + '='*40 + '\n\n')

    header_needed = not os.path.exists(csv_path)
    with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if header_needed:
            writer.writerow(['Hostname', 'CMMC_Control', 'Compliant', 'Evidence_Hash', 'Evidence_File', 'Notes'])
        for control, data in result.get('checks', {}).items():
            writer.writerow([
                result['hostname'],
                control,
                'Yes' if data.get('passed') else 'No',
                file_hash,
                result['file_path'],
                json.dumps(data)
            ])

    print(f"✅ Checked {result['hostname']}")
    print("🔍 See output/compliance_result.txt and output/compliance_result.csv for details.")
    return file_hash
