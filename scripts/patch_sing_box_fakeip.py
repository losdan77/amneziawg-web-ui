#!/usr/bin/env python3
"""Apply the narrowly scoped FakeIP durability fix to pinned sing-box v1.14.3.

Upstream consumes allocator metadata on startup and debounces its replacement
for ten seconds. A crash can then reset valid mappings or reuse assigned IPs.
Keep the metadata, and commit the advanced allocator before the address mapping
and before answering DNS. An interrupted allocation may skip one address, but
cannot reuse an address which a client has already received.

The exact-source checks deliberately fail when upstream changes. Re-evaluate
this patch when upgrading sing-box; do not blindly relax its anchors.
"""
from pathlib import Path
import sys

PINNED_COMMIT = '7054cac5124465ffdb145870d7c01885566711b1'

METADATA_OLD = '''func (c *CacheFile) FakeIPMetadata() *adapter.FakeIPMetadata {
	var metadata adapter.FakeIPMetadata
	err := c.batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return os.ErrNotExist
		}
		metadataBinary := bucket.Get(keyMetadata)
		if len(metadataBinary) == 0 {
			return os.ErrInvalid
		}
		err := bucket.Delete(keyMetadata)
		if err != nil {
			return err
		}
		return metadata.UnmarshalBinary(metadataBinary)
	})
	if err != nil {
		return nil
	}
	return &metadata
}'''
METADATA_NEW = METADATA_OLD.replace('c.batch(', 'c.view(').replace('''		err := bucket.Delete(keyMetadata)
		if err != nil {
			return err
		}
''', '')

ALLOCATE_OLD = '''	err := s.storage.FakeIPStore(address, domain)
	if err != nil {
		s.logger.Warn("save FakeIP cache: ", err)
	}
	s.storage.FakeIPSaveMetadataAsync(&adapter.FakeIPMetadata{
		Inet4Range:   s.inet4Range,
		Inet6Range:   s.inet6Range,
		Inet4Current: s.inet4Current,
		Inet6Current: s.inet6Current,
	})
	return address, nil'''
ALLOCATE_NEW = '''	// Persist the advanced allocator before the mapping. A crash between these
	// commits skips an unused address instead of reassigning a client's FakeIP.
	if err := s.storage.FakeIPSaveMetadata(&adapter.FakeIPMetadata{
		Inet4Range:   s.inet4Range,
		Inet6Range:   s.inet6Range,
		Inet4Current: s.inet4Current,
		Inet6Current: s.inet6Current,
	}); err != nil {
		return netip.Addr{}, E.Cause(err, "save FakeIP metadata")
	}
	if err := s.storage.FakeIPStore(address, domain); err != nil {
		return netip.Addr{}, E.Cause(err, "save FakeIP cache")
	}
	return address, nil'''


def patch_source(directory):
    directory = Path(directory)
    changes = []
    for relative, old, new in (
        ('experimental/cachefile/fakeip.go', METADATA_OLD, METADATA_NEW),
        ('dns/transport/fakeip/store.go', ALLOCATE_OLD, ALLOCATE_NEW),
    ):
        path = directory / relative
        original = path.read_text(encoding='utf-8')
        if original.count(old) != 1:
            raise RuntimeError(f'Unexpected sing-box source in {relative}; durability patch refused')
        changes.append((path, original.replace(old, new)))
    # Validate both files before changing either one.
    for path, content in changes:
        path.write_text(content, encoding='utf-8')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: patch_sing_box_fakeip.py <sing-box source directory>')
    patch_source(sys.argv[1])
