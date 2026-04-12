#!/usr/bin/env python3
"""
Test script for environment variable manager
"""

from env_manager import EnvManager

def test_env_manager():
    print("Testing EnvManager...")
    env_manager = EnvManager()
    
    # Test 1: Check current token
    print("\n1. Checking current token...")
    token = env_manager.get_token()
    if token:
        print(f"   ✓ Token found: {token[:8]}...{token[-4:]}")
    else:
        print("   ℹ No token currently set")
    
    # Test 2: Validate token format
    print("\n2. Testing token validation...")
    test_tokens = [
        ("sk-proj-abcd1234efgh5678", True),
        ("sk-abcdefghijklmnop", True),
        ("invalid-token", False),
        ("", False),
        ("pk-test123", False)
    ]
    
    for test_token, expected in test_tokens:
        result = env_manager.validate_token(test_token)
        status = "✓" if result == expected else "✗"
        print(f"   {status} '{test_token[:20]}...' -> {result} (expected {expected})")
    
    # Test 3: Check .bashrc path
    print(f"\n3. .bashrc location: {env_manager.bashrc_path}")
    print(f"   Exists: {env_manager.bashrc_path.exists()}")
    
    print("\n✓ All tests completed!")

if __name__ == "__main__":
    test_env_manager()
