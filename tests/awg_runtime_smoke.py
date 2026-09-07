"""Run ONLY in an isolated Linux container with NET_ADMIN and netns support.

Creates two network namespaces connected by a private veth, then checks real
handshakes and tunneled traffic for AWG3, AWG2 and legacy configs. No host data.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from awg_protocol import generate_params, render_params


def run(*args, input=None, check=True):
    result = subprocess.run(args, input=input, text=True, capture_output=True)
    if check and result.returncode:
        # Avoid printing commands/config input: they may contain ephemeral keys.
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr}')
    return result


def ns(name, *args, **kwargs):
    return run('ip', 'netns', 'exec', name, *args, **kwargs)


def main():
    names = ['awg-test-a', 'awg-test-b']
    try:
        for name in names:
            run('ip', 'netns', 'add', name)
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'link-a', 'type', 'veth', 'peer', 'name', 'link-b')
        for i, name in enumerate(names):
            link = ['link-a', 'link-b'][i]
            run('ip', 'link', 'set', link, 'netns', name)
            ns(name, 'ip', 'addr', 'add', f'198.18.0.{i + 1}/30', 'dev', link)
            ns(name, 'ip', 'link', 'set', link, 'up')
        private = [run('awg', 'genkey').stdout.strip() for _ in names]
        public = [run('awg', 'pubkey', input=k).stdout.strip() for k in private]
        legacy = dict(Jc=4, Jmin=8, Jmax=80, S1=50, S2=60,
                      H1=1000, H2=2000, H3=3000, H4=4000)
        for version, params in [('3.0', generate_params()), ('2.0', generate_params(version='2')), ('1.x', legacy)]:
            with tempfile.TemporaryDirectory() as directory:
                paths = []
                for i, name in enumerate(names):
                    other = 1 - i
                    config = (f'[Interface]\nPrivateKey = {private[i]}\nAddress = 10.230.0.{i + 1}/32\n'
                              f'ListenPort = {53221 + i}\nMTU = 1280\n' + render_params(params)
                              + f'[Peer]\nPublicKey = {public[other]}\nAllowedIPs = 10.230.0.{other + 1}/32\n'
                              f'Endpoint = 198.18.0.{other + 1}:{53221 + other}\n'
                              f'PersistentKeepalive = {"15-30" if version == "3.0" else "25"}\n')
                    path = Path(directory, name + '.conf')
                    path.write_text(config)
                    os.chmod(path, 0o600)
                    paths.append(str(path))
                    ns(name, 'awg-quick', 'up', str(path))
                try:
                    ns(names[0], 'ping', '-c', '3', '-W', '3', '10.230.0.2')
                    # MTU-size inner traffic, including padding and header protection.
                    ns(names[1], 'ping', '-c', '2', '-W', '3', '-s', '1252', '10.230.0.1')
                    for name in names:
                        handshake = ns(name, 'awg', 'show', name, 'latest-handshakes').stdout.strip().split()
                        assert int(handshake[-1]) > 0, f'{version}: no handshake'
                        actual = ns(name, 'awg', 'showconf', name).stdout
                        if version == '3.0':
                            assert f"HeaderProtectionKey = {params['HeaderProtectionKey']}" in actual
                            assert 'ContentPaddingAddition = 0-32' in actual
                        else:
                            assert 'HeaderProtectionKey' not in actual
                        # A live peer refresh must retain header key and ranges.
                        stripped = ns(name, 'awg-quick', 'strip', paths[names.index(name)]).stdout
                        tmp = Path(directory, 'sync.conf')
                        tmp.write_text(stripped)
                        ns(name, 'awg', 'syncconf', name, str(tmp))
                    ns(names[0], 'ping', '-c', '1', '-W', '3', '10.230.0.2')
                    print(f'PASS AWG {version}: handshake, bidirectional traffic, MTU 1280, live syncconf', flush=True)
                finally:
                    for name, path in zip(names, paths):
                        ns(name, 'awg-quick', 'down', path, check=False)
    finally:
        for name in names:
            run('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    main()
