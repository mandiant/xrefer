"""
Example script demonstrating the string extraction backend usage.

This script shows how to:
1. Use the default IDA backend
2. Switch to the custom xref-based extractor
3. Compare results between backends
4. Extend the system for other platforms

Run this in IDA Pro's Python console.
"""

from xrefer.core.disasm_backend import (
    IDABackend,
    XRefBasedStringExtractor,
    get_backend,
    set_backend
)


def example_default_usage():
    """Example 1: Default usage (IDA backend)"""
    print("\n=== Example 1: Default IDA Backend ===")
    
    # The default backend is IDABackend
    backend = get_backend()
    print(f"Current backend: {type(backend).__name__}")
    
    # Extract strings using the default backend
    strings = backend.get_strings()
    print(f"Extracted {len(strings)} strings")
    
    # Show first 5 strings
    print("\nFirst 5 strings:")
    for addr, content in list(strings.items())[:5]:
        print(f"  0x{addr:08x}: {content[0][:60]}")


def example_custom_extractor():
    """Example 2: Using the custom xref-based extractor"""
    print("\n=== Example 2: Custom XRef-Based Extractor ===")
    
    # Switch to custom extractor
    set_backend(XRefBasedStringExtractor())
    backend = get_backend()
    print(f"Current backend: {type(backend).__name__}")
    
    # Extract strings with the custom extractor
    strings = backend.get_strings()
    print(f"Extracted {len(strings)} strings")
    
    # Show first 5 strings
    print("\nFirst 5 strings:")
    for addr, content in list(strings.items())[:5]:
        print(f"  0x{addr:08x}: {content[0][:60]}")


def example_with_filters():
    """Example 3: Using filters to exclude specific strings"""
    print("\n=== Example 3: String Extraction with Filters ===")
    
    # Reset to IDA backend
    set_backend(IDABackend())
    backend = get_backend()
    
    # Extract strings, filtering out debug strings
    filters = [b'debug', b'DEBUG', b'test', b'TEST']
    strings = backend.get_strings(filters=filters)
    
    print(f"Extracted {len(strings)} strings (excluding debug/test strings)")
    
    # Show sample
    print("\nSample strings:")
    for addr, content in list(strings.items())[:5]:
        print(f"  0x{addr:08x}: {content[0][:60]}")


def example_compare_backends():
    """Example 4: Compare results between backends"""
    print("\n=== Example 4: Comparing Backends ===")
    
    # Get strings using IDA backend
    set_backend(IDABackend())
    ida_strings = get_backend().get_strings()
    
    # Get strings using custom extractor
    set_backend(XRefBasedStringExtractor())
    custom_strings = get_backend().get_strings()
    
    # Compare
    print(f"IDA Backend: {len(ida_strings)} strings")
    print(f"Custom Backend: {len(custom_strings)} strings")
    print(f"Difference: {abs(len(ida_strings) - len(custom_strings))} strings")
    
    # Find strings unique to each backend
    ida_addrs = set(ida_strings.keys())
    custom_addrs = set(custom_strings.keys())
    
    only_ida = ida_addrs - custom_addrs
    only_custom = custom_addrs - ida_addrs
    
    print(f"\nStrings only in IDA backend: {len(only_ida)}")
    print(f"Strings only in Custom backend: {len(only_custom)}")
    
    if only_ida:
        print("\nSample strings only in IDA backend:")
        for addr in list(only_ida)[:3]:
            print(f"  0x{addr:08x}: {ida_strings[addr][0][:60]}")
    
    if only_custom:
        print("\nSample strings only in Custom backend:")
        for addr in list(only_custom)[:3]:
            print(f"  0x{addr:08x}: {custom_strings[addr][0][:60]}")


def example_direct_usage():
    """Example 5: Using backends directly without global state"""
    print("\n=== Example 5: Direct Backend Usage ===")
    
    # Create backend instances directly
    ida_backend = IDABackend()
    custom_backend = XRefBasedStringExtractor()
    
    # Use them directly without changing global state
    ida_result = ida_backend.get_strings()
    custom_result = custom_backend.get_strings()
    
    print(f"IDA backend (direct): {len(ida_result)} strings")
    print(f"Custom backend (direct): {len(custom_result)} strings")


def example_xref_queries():
    """Example 6: Using backend for xref queries"""
    print("\n=== Example 6: Cross-Reference Queries ===")
    
    backend = get_backend()
    strings = backend.get_strings()
    
    if not strings:
        print("No strings found")
        return
    
    # Pick a string address
    string_addr = list(strings.keys())[0]
    string_content = strings[string_addr][0]
    
    print(f"\nString at 0x{string_addr:08x}: {string_content[:60]}")
    
    # Get xrefs to this string
    xrefs = backend.get_xrefs_to(string_addr)
    print(f"Cross-references: {len(xrefs)}")
    
    # Show xref locations
    print("\nXref locations:")
    for xref_addr in xrefs[:5]:
        is_code = backend.is_code(xref_addr)
        xref_type = "CODE" if is_code else "DATA"
        print(f"  0x{xref_addr:08x} ({xref_type})")


# Template for Binary Ninja backend (for future implementation)
def example_binary_ninja_template():
    """
    Example 7: Template for Binary Ninja backend implementation
    
    This is a template showing how to implement a Binary Ninja backend.
    Uncomment and modify when Binary Ninja support is needed.
    """
    
    template_code = '''
from xrefer.core.disasm_backend import DisassemblerBackend
import binaryninja as bn
from typing import Dict, List, Optional

class BinaryNinjaBackend(DisassemblerBackend):
    """Binary Ninja backend with xref-based filtering."""
    
    def __init__(self, bv):
        """
        Initialize Binary Ninja backend.
        
        Args:
            bv: Binary Ninja BinaryView instance
        """
        self.bv = bv
    
    def get_strings(self, filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        if filters is None:
            filters = []
        
        str_dict = {}
        
        # Use Binary Ninja's API to get strings
        for string in self.bv.strings:
            # Get xrefs to this string
            xrefs = self.bv.get_code_refs(string.start)
            
            # Skip strings with no xrefs (likely garbage)
            if not list(xrefs):
                continue
            
            # Apply filters
            if any(f in string.value.encode() for f in filters):
                continue
            
            # Apply quality heuristics
            if len(string.value) < 2:
                continue
            
            printable_ratio = sum(1 for c in string.value if c.isprintable()) / len(string.value)
            if printable_ratio < 0.7:
                continue
            
            str_dict[string.start] = [string.value]
        
        return str_dict
    
    def get_xrefs_to(self, address: int) -> List[int]:
        return [ref.address for ref in self.bv.get_code_refs(address)]
    
    def is_code(self, address: int) -> bool:
        return self.bv.get_function_at(address) is not None

# Usage in Binary Ninja:
# from xrefer.core.disasm_backend import set_backend
# bn_backend = BinaryNinjaBackend(bv)
# set_backend(bn_backend)
'''
    
    print("\n=== Example 7: Binary Ninja Backend Template ===")
    print("Template code for Binary Ninja backend:")
    print(template_code)


def run_all_examples():
    """Run all examples"""
    print("=" * 70)
    print("XRefer String Extraction Backend Examples")
    print("=" * 70)
    
    try:
        example_default_usage()
        example_custom_extractor()
        example_with_filters()
        example_compare_backends()
        example_direct_usage()
        example_xref_queries()
        example_binary_ninja_template()
    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Reset to default backend
        set_backend(IDABackend())
        print("\n" + "=" * 70)
        print("Examples complete. Backend reset to IDABackend.")
        print("=" * 70)


if __name__ == "__main__":
    # Run all examples
    run_all_examples()
    
    # Or run individual examples:
    # example_default_usage()
    # example_custom_extractor()
    # example_with_filters()
    # example_compare_backends()
