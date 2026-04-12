"""Configure test path to find project root modules."""
import sys
import os

# Add project root to Python path so tests can import root-level modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
