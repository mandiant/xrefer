"""Tests for importing the IDA backend outside an IDA runtime"""
from __future__ import annotations
import unittest
from xrefer_new.backend.ida import IDABackEnd

class IDABackEndImportTests(unittest.TestCase):
    def test_constructor_raises_without_ida_runtime(self) -> None:
        with self.assertRaises(RuntimeError):
            IDABackEnd()


if __name__ == "__main__":
    unittest.main()
