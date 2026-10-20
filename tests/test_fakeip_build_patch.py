"""The source patch fails closed on an upgrade instead of half-patching a build."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

script = Path(__file__).resolve().parents[1] / 'scripts' / 'patch_sing_box_fakeip.py'
spec = importlib.util.spec_from_file_location('durability_patch', script)
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class FakeIPBuildPatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.metadata = self.root / 'experimental/cachefile/fakeip.go'
        self.allocator = self.root / 'dns/transport/fakeip/store.go'
        self.metadata.parent.mkdir(parents=True)
        self.allocator.parent.mkdir(parents=True)
        self.metadata.write_text('package cachefile\n' + patcher.METADATA_OLD, encoding='utf-8')
        self.allocator.write_text('package fakeip\n' + patcher.ALLOCATE_OLD, encoding='utf-8')

    def test_refuses_changed_upstream_without_touching_either_file(self):
        self.allocator.write_text('changed upstream source', encoding='utf-8')
        before = self.metadata.read_bytes(), self.allocator.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'patch refused'):
            patcher.patch_source(self.root)
        self.assertEqual((self.metadata.read_bytes(), self.allocator.read_bytes()), before)

    def test_repeated_application_is_rejected_instead_of_changing_more_code(self):
        patcher.patch_source(self.root)
        before = self.metadata.read_bytes(), self.allocator.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'patch refused'):
            patcher.patch_source(self.root)
        self.assertEqual((self.metadata.read_bytes(), self.allocator.read_bytes()), before)

    def test_ambiguous_anchor_is_rejected(self):
        self.metadata.write_text(patcher.METADATA_OLD * 2, encoding='utf-8')
        before = self.metadata.read_bytes(), self.allocator.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'patch refused'):
            patcher.patch_source(self.root)
        self.assertEqual((self.metadata.read_bytes(), self.allocator.read_bytes()), before)


if __name__ == '__main__':
    unittest.main()
