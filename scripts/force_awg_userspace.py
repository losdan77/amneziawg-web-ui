"""Use the pinned AWG3 userspace even if an older host kernel module exists.

WG_QUICK_USERSPACE_IMPLEMENTATION alone only selects the fallback binary in
upstream awg-quick; it does not bypass kernel interface creation.
"""
import re
import sys
from pathlib import Path


def force_userspace(text):
    replacement = '''add_if() {
    cmd /usr/bin/amneziawg-go "$INTERFACE"
}
'''
    updated, count = re.subn(r'^add_if\(\) \{\n.*?^\}\n', replacement, text,
                             flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise ValueError('Unexpected awg-quick source: expected exactly one add_if function')
    return updated


if __name__ == '__main__':
    path = Path(sys.argv[1])
    path.write_text(force_userspace(path.read_text()), encoding='utf-8', newline='\n')
