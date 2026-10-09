import importlib.metadata
import unittest

import webposture


class VersionTest(unittest.TestCase):
    def test_metadata_version_matches_dunder_version(self):
        # pyproject reads the version from webposture.__version__, so the
        # installed package metadata and the attribute must never disagree.
        self.assertEqual(
            importlib.metadata.version("web-posture-check"),
            webposture.__version__,
        )


if __name__ == "__main__":
    unittest.main()
