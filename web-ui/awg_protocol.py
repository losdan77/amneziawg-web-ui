"""AWG 1/2/3.0 configuration shared by servers, clients and upstream links.

Wire format follows amnezia-vpn/amneziawg-go v3.0.20260805 and
amnezia-vpn/amneziawg-tools v3.0.20260730. Never upgrade imported peers
implicitly: header protection and S/H values must agree at both ends.
"""
import base64
import re
import secrets

BASE_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4')
TIMING_KEYS = ('RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
               'KeepaliveTimeout', 'MaxHandshakeAttempts')
OBFUSCATION_KEYS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
                    'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5',
                    'HeaderProtectionKey', 'ContentPaddingAddition') + TIMING_KEYS
V3_KEYS = ('HeaderProtectionKey', 'ContentPaddingAddition') + TIMING_KEYS


def normalize_range(value, name, maximum=65535):
    text = str(value).strip()
    if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', text):
        raise ValueError(f'{name} must be an unsigned integer or min-max range')
    parts = [int(x) for x in text.split('-')]
    lo, hi = parts[0], parts[-1]
    if not 0 <= lo <= hi <= maximum:
        raise ValueError(f'{name} must be ordered and within 0..{maximum}')
    return lo if lo == hi else f'{lo}-{hi}'


def range_bounds(value):
    parts = str(value).split('-')
    return int(parts[0]), int(parts[-1])


def normalize_keepalive(value):
    if str(value).strip().lower() in ('off', '(off)'):
        return 0
    return normalize_range(value, 'PersistentKeepalive')


def _validate_cps(value, key, mtu):
    if not isinstance(value, str) or any(c in value for c in '\r\n\x00#;'):
        raise ValueError(f'{key} must be a single-line CPS chain')
    size = 0
    remaining = value.strip()
    while remaining:
        match = re.match(r'<(b|r|rc|rd|t|d|ds|dz)(?:\s+([^<>]+))?>', remaining)
        if not match:
            raise ValueError(f'Invalid CPS tag in {key}')
        tag, arg = match.groups()
        if tag == 'b':
            if not arg or not re.fullmatch(r'0x(?:[a-fA-F0-9]{2})+', arg):
                raise ValueError(f'{key}: b requires even-length hex bytes with 0x prefix')
            size += (len(arg) - 2) // 2
        elif tag in ('r', 'rc', 'rd', 'dz'):
            length = normalize_range(arg, key, mtu)
            if not isinstance(length, int):
                raise ValueError(f'{key}: CPS lengths must be integers')
            size += length
        else:
            if arg:
                raise ValueError(f'{key}: {tag} takes no argument')
            size += 4 if tag == 't' else 0
        remaining = remaining[match.end():].strip()
    if size > mtu:
        raise ValueError(f'{key} exceeds MTU ({mtu})')
    return value.strip()


def normalize_params(params, mtu):
    if not isinstance(params, dict):
        raise ValueError('Obfuscation params must be an object')
    unknown = set(params) - set(OBFUSCATION_KEYS) - {'MTU'}
    if unknown:
        raise ValueError('Unsupported AWG parameters: ' + ', '.join(sorted(unknown)))
    result = {}
    for key in OBFUSCATION_KEYS:
        if key not in params:
            continue
        value = params[key]
        if key.startswith('I'):
            result[key] = _validate_cps(value, key, mtu)
        elif key == 'HeaderProtectionKey':
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError('HeaderProtectionKey must be a base64 32-byte key') from exc
            if len(decoded) != 32 or not any(decoded):
                raise ValueError('HeaderProtectionKey must be a nonzero 32-byte key')
            result[key] = base64.b64encode(decoded).decode('ascii')
        else:
            maximum = 4294967295 if key.startswith('H') else 65535
            result[key] = normalize_range(value, key, maximum)
            if key.startswith(('J', 'S')) and not isinstance(result[key], int):
                raise ValueError(f'{key} must be an integer')
    # Upstream allows omitted fields. Do not emit/add them when importing.
    # Bounds below prevent oversized allocations while accepting legal zeros.
    if not 0 <= result.get('Jmin', 0) <= result.get('Jmax', 0) <= mtu:
        raise ValueError(f'Jmin must be <= Jmax <= MTU ({mtu})')
    for key, overhead in (('S1', 148), ('S2', 92), ('S3', 64), ('S4', 32)):
        if result.get(key, 0) > mtu - overhead:
            raise ValueError(f'{key} must be <= MTU-{overhead}')
    headers = [(f'H{i}', range_bounds(result.get(f'H{i}', i))) for i in range(1, 5)]
    for i, (left_name, (lo, hi)) in enumerate(headers):
        for right_name, (other_lo, other_hi) in headers[i + 1:]:
            if max(lo, other_lo) <= min(hi, other_hi):
                raise ValueError(f'{left_name} and {right_name} must not overlap')
    if result.get('HeaderProtectionKey'):
        for key in ('S1', 'S2', 'S3', 'S4'):
            if result.get(key, 0) < 12:
                raise ValueError(f'{key} must be at least 12 for AWG 3 header protection')
    return result


def import_params(interface, mtu):
    # Fail explicitly on 3.1-only fields instead of silently breaking its wire format.
    unsupported = {'RandomTrailers', 'DisableCookies'} & set(interface)
    if unsupported:
        raise ValueError('AWG 3.1 config is not supported by this AWG 3.0 runtime: '
                         + ', '.join(sorted(unsupported)))
    params = {k: v for k, v in interface.items() if k in OBFUSCATION_KEYS}
    if not params:
        raise ValueError('Imported config must contain AmneziaWG parameters')
    return normalize_params(params, mtu)


def protocol_version(params, enabled=True):
    if not enabled:
        return 'wireguard'
    params = params or {}
    if params.get('HeaderProtectionKey'):
        return '3'
    if any(k in params for k in ('S3', 'S4')) or any('-' in str(params.get(f'H{i}', '')) for i in range(1, 5)):
        return '2'
    return '1'


def upgrade_params(params, mtu):
    result = dict(params)
    for key in ('S1', 'S2', 'S3', 'S4'):
        value = normalize_range(result.get(key, 0), key)
        if not isinstance(value, int):
            raise ValueError(f'{key} must be an integer')
        result[key] = max(12, value)
    result.setdefault('HeaderProtectionKey', base64.b64encode(secrets.token_bytes(32)).decode('ascii'))
    result.setdefault('ContentPaddingAddition', '0-32')
    result.setdefault('RekeyAfterTime', '100-120')
    result.setdefault('RekeyTimeout', '4-6')
    result.setdefault('RejectAfterTime', '160-180')
    result.setdefault('KeepaliveTimeout', '10-15')
    result.setdefault('MaxHandshakeAttempts', '18-20')
    return normalize_params(result, mtu)


def generate_params(mtu=1280, version='3'):
    rng = secrets.SystemRandom()
    params = dict(Jc=rng.randint(4, 12), Jmin=8, Jmax=rng.randint(80, 200),
                  S1=rng.randint(15, 80), S2=rng.randint(15, 60), S3=12, S4=12)
    for i in range(1, 5):
        start = rng.randint(i * 1000000, i * 1000000 + 900000)
        params[f'H{i}'] = f'{start}-{start + 1000}'
    if str(version) == '3':
        return upgrade_params(params, mtu)
    if str(version) != '2':
        raise ValueError('awg_version must be 2 or 3')
    return normalize_params(params, mtu)


def render_params(params):
    return ''.join(f'{key} = {params[key]}\n' for key in OBFUSCATION_KEYS
                   if key in params and params[key] != '')


def replace_interface_params(config, params):
    """Preserve all peers, comments and non-AWG settings during explicit upgrade."""
    result, in_interface, inserted = [], False, False
    known = {k.lower() for k in OBFUSCATION_KEYS}
    for line in config.splitlines(keepends=True):
        stripped = line.split('#', 1)[0].strip()
        if stripped.startswith('['):
            in_interface = stripped.lower() == '[interface]'
            result.append(line)
            if in_interface:
                if inserted:
                    raise ValueError('Multiple Interface sections in server config')
                if not line.endswith('\n'):
                    result.append('\n')
                result.append(render_params(params))
                inserted = True
            continue
        key = stripped.split('=', 1)[0].strip().lower()
        if in_interface and key in known:
            continue
        result.append(line)
    if not inserted:
        raise ValueError('Missing Interface section in server config')
    return ''.join(result)
