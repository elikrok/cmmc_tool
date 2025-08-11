
import re
import socket

def extract_hostname(config_path: str) -> str:
    try:
        with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip().lower().startswith("hostname"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return "unknown"

def _normalize_lines(lines):
    norm = []
    for line in lines:
        if not line.strip():
            continue
        if line.lstrip().startswith('!'):
            continue
        norm.append(line.rstrip('\r\n'))
    return norm

def _collect_aaa_login_lines(lowlines):
    return [l for l in lowlines if l.startswith('aaa authentication login')]

def _aaa_is_configured(lines):
    low = [l.lower() for l in lines]
    aaa_lines = _collect_aaa_login_lines(low)
    if not aaa_lines:
        return False
    tacacs_direct = any((' tacacs+' in l or ' tacacs ' in l or ' tacplus ' in l or ' group tacacs' in l) for l in aaa_lines)
    aaa_groups = set()
    for l in aaa_lines:
        parts = l.split()
        for i, tok in enumerate(parts):
            if tok == 'group' and i + 1 < len(parts):
                aaa_groups.add(parts[i + 1])
    tacacs_groups = set()
    for l in low:
        m = re.match(r'aaa\s+group\s+server\s+tacacs\+?\s+(\S+)', l)
        if m:
            tacacs_groups.add(m.group(1))
    tacacs_via_group = any(g in tacacs_groups for g in aaa_groups)
    mentions_tacacs = tacacs_direct or tacacs_via_group
    has_local_fallback = any((' local' in l) for l in aaa_lines) or any('login local' in l for l in low)
    return mentions_tacacs and has_local_fallback

def _find_tacacs_servers(lines):
    servers = set()
    ipv4 = r'(?:\d{1,3}\.){3}\d{1,3}'
    in_tacacs_block = False
    for raw in lines:
        low = raw.strip().lower()
        if low.startswith('tacacs server ') or low.startswith('aaa group server tacacs+'):
            in_tacacs_block = True
        m = re.search(r'\btacacs-server\s+host\s+([^\s]+)', low)
        if m:
            servers.add(m.group(1))
        m2 = re.search(r'\baddress\s+ipv4\s+(' + ipv4 + r')', low)
        if m2 and in_tacacs_block:
            servers.add(m2.group(1))
        if in_tacacs_block and low.startswith('server '):
            parts = low.split()
            if len(parts) >= 2:
                servers.add(parts[1])
        if low and not low.startswith(('server ', 'address ', 'key ', 'timeout ', 'retransmit ', 'port ')):
            if not (low.startswith('tacacs server ') or low.startswith('aaa group server tacacs+')):
                in_tacacs_block = False
    return list(servers)

def _test_tacacs_connectivity(servers, timeout=1.5):
    results = {}
    for s in servers:
        ok = False
        try:
            with socket.create_connection((s, 49), timeout=timeout):
                ok = True
        except Exception:
            ok = False
        results[s] = ok
    return results

def _parse_user_privileges(lines):
    users = {}
    for raw in lines:
        low = raw.strip().lower()
        if not low.startswith('username '):
            continue
        parts = low.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        priv = None
        roles = []
        if ' privilege ' in low:
            try:
                idx = parts.index('privilege')
                if idx + 1 < len(parts):
                    priv = int(parts[idx + 1])
            except Exception:
                pass
        if ' role ' in low:
            for i, tok in enumerate(parts):
                if tok == 'role' and i + 1 < len(parts):
                    roles.append(parts[i + 1])
        users[name] = {'privilege': priv, 'roles': roles}
    return users

def _ac_limit_transactions(lines):
    low = [l.lower() for l in lines]
    config_text = '\n'.join(low)
    has_enable_secret = any(l.strip().startswith('enable secret') for l in low)
    users = _parse_user_privileges(lines)
    any_restricted = any((u['privilege'] is not None and u['privilege'] < 15) or (u['roles']) for u in users.values())
    no_telnet = 'transport input telnet' not in config_text
    return has_enable_secret and (any_restricted or bool(users)) and no_telnet

def _has_ssh_only_transport(lines):
    ssh_ok = False
    in_vty = False
    for raw in lines:
        low = raw.strip().lower()
        if low.startswith('line vty'):
            in_vty = True
            continue
        if in_vty and low.startswith(('line ', 'interface ', 'router ', 'hostname', 'aaa ', 'ip ')):
            in_vty = False
        if in_vty and 'transport input ssh' in low:
            ssh_ok = True
        if in_vty and 'transport input telnet' in low:
            return False
    return ssh_ok

def _access_lists_applied(lines):
    has_acl_def = any(l.lower().startswith(('access-list', 'ip access-list')) for l in lines)
    has_acl_apply = any(' ip access-group ' in l.lower() for l in lines)
    return has_acl_def and has_acl_apply

def _vty_management_controls(lines):
    in_vty = False
    ssh_only = False
    access_class = False
    for raw in lines:
        low = raw.strip().lower()
        if low.startswith('line vty'):
            in_vty = True
            continue
        if in_vty and low.startswith(('line ', 'interface ', 'router ', 'hostname', 'aaa ', 'ip ')):
            in_vty = False
        if in_vty:
            if 'transport input ssh' in low and 'telnet' not in low:
                ssh_only = True
            if 'transport input telnet' in low:
                ssh_only = False
            if low.startswith('access-class ') and (' in' in low or ' out' in low):
                access_class = True
    return {'ssh_only': ssh_only, 'vty_access_class': access_class}

def _eos_management_controls(lines):
    ssh_enabled = any(l.strip().lower() == 'management ssh' for l in lines)
    mgmt_iface_present = any(l.strip().lower().startswith(('interface management1', 'interface management 1')) for l in lines)
    in_mgmt1 = False
    mgmt_acl_bound = False
    for raw in lines:
        line = raw.rstrip()
        low = line.strip().lower()
        if low.startswith(('interface management1', 'interface management 1')):
            in_mgmt1 = True
            continue
        if in_mgmt1 and low.startswith(('interface ', 'line ', 'router ', 'hostname', 'aaa ', 'ip ')):
            in_mgmt1 = False
        if in_mgmt1 and ' ip access-group ' in low:
            mgmt_acl_bound = True
    return {'ssh_enabled': ssh_enabled, 'mgmt_acl_bound': mgmt_acl_bound, 'mgmt_iface_present': mgmt_iface_present}

def _has_management_vrf(lines):
    low = [l.lower() for l in lines]
    vrf_defined = any(l.startswith('vrf definition ') or l.startswith('ip vrf ') for l in low)
    vrf_forwarding = any(' vrf forwarding ' in l for l in low)
    has_mgmt1 = any(l.startswith(('interface management1', 'interface management 1')) for l in low)
    return vrf_defined or vrf_forwarding or has_mgmt1

def _find_dmz_interfaces(lines):
    dmz_ifaces = set()
    current_if = None
    for raw in lines:
        low = raw.rstrip().lower()
        if low.startswith(('interface ', 'ethernet', 'vlan')):
            current_if = raw.strip()
        if current_if and (' dmz' in low or low.endswith(' dmz') or 'description dmz' in low or ' name dmz' in low):
            dmz_ifaces.add(current_if)
        if current_if and ('dmz' in current_if.lower()):
            dmz_ifaces.add(current_if)
    return dmz_ifaces

def _interface_has_acl(lines, iface_header):
    in_block = False
    for raw in lines:
        line = raw.rstrip()
        low = line.lower().strip()
        if line.strip() == iface_header.strip():
            in_block = True
            continue
        if in_block and low.startswith(('interface ', 'line ', 'router ', 'vlan ', 'hostname', 'aaa ', 'ip ')):
            in_block = False
        if in_block and ' ip access-group ' in low:
            return True
    return False

def _sc_public_separation(lines):
    dmz_ifaces = _find_dmz_interfaces(lines)
    if not dmz_ifaces:
        return True, []
    missing = []
    for iface in dmz_ifaces:
        if not _interface_has_acl(lines, iface):
            missing.append(iface)
    return len(missing) == 0, missing

def _sc_boundary_protection_deep(lines):
    vty = _vty_management_controls(lines)
    eos = _eos_management_controls(lines)
    ssh_mgmt = vty['ssh_only'] or eos['ssh_enabled']
    acls_present_applied = _access_lists_applied(lines)
    mgmt_acl_signal = vty['vty_access_class'] or eos['mgmt_acl_bound']
    mgmt_vrf = _has_management_vrf(lines)
    return (ssh_mgmt and acls_present_applied and (mgmt_acl_signal or mgmt_vrf)), {
        'ssh_mgmt': ssh_mgmt,
        'acls_present_applied': acls_present_applied,
        'mgmt_acl_signal': mgmt_acl_signal,
        'mgmt_vrf_or_mgmt1': mgmt_vrf
    }

def check_config_compliance(current_path, baseline_path, skip_connectivity=False):
    with open(current_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines_raw = f.readlines()
    with open(baseline_path, 'r', encoding='utf-8', errors='ignore') as f:
        base_raw = f.readlines()

    current_lines = _normalize_lines(lines_raw)
    baseline_lines = _normalize_lines(base_raw)

    missing_lines = [line for line in baseline_lines if line not in current_lines]
    extra_lines = [line for line in current_lines if line not in baseline_lines]
    config_matches_baseline = not missing_lines and not extra_lines

    aaa_ok = _aaa_is_configured(current_lines)
    tacacs_servers = _find_tacacs_servers(current_lines)
    if skip_connectivity:
        reachability = {}
        any_reachable = bool(tacacs_servers)
    else:
        reachability = _test_tacacs_connectivity(tacacs_servers) if tacacs_servers else {}
        any_reachable = any(reachability.values()) if reachability else False
    ac_3111_pass = aaa_ok and any_reachable

    ac_3112_pass = _ac_limit_transactions(current_lines)
    config_text = '\n'.join([l.lower() for l in current_lines])

    sc_13131_pass, sc_13131_notes = _sc_boundary_protection_deep(current_lines)
    sc_13135_pass, dmz_missing_acl = _sc_public_separation(current_lines)

    overall = config_matches_baseline and ac_3111_pass and ac_3112_pass and sc_13131_pass and sc_13135_pass

    return {
        'hostname': extract_hostname(current_path),
        'compliant': overall,
        'missing': missing_lines,
        'extra': extra_lines,
        'checks': {
            'CM.L1-3.4.1': {
                'passed': config_matches_baseline,
                'missing_lines': missing_lines,
                'extra_lines': extra_lines
            },
            'AC.L1-3.1.1': {
                'aaa_configured': aaa_ok,
                'tacacs_servers': tacacs_servers,
                'tacacs_reachability': reachability,
                'connectivity_skipped': bool(skip_connectivity),
                'passed': ac_3111_pass
            },
            'AC.L1-3.1.2': {
                'enable_secret_present': any(l.lower().strip().startswith('enable secret') for l in current_lines),
                'user_privileges': _parse_user_privileges(current_lines),
                'no_telnet': 'transport input telnet' not in config_text,
                'passed': ac_3112_pass
            },
            'SC.L1-3.13.1': {
                'ssh_mgmt': sc_13131_notes['ssh_mgmt'],
                'acls_present_and_applied': sc_13131_notes['acls_present_applied'],
                'mgmt_acl_signal': sc_13131_notes['mgmt_acl_signal'],
                'mgmt_vrf_or_mgmt1': sc_13131_notes['mgmt_vrf_or_mgmt1'],
                'passed': sc_13131_pass
            },
            'SC.L1-3.13.5': {
                'dmz_interfaces_without_acl': dmz_missing_acl,
                'passed': sc_13135_pass
            }
        }
    }
