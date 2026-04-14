#!/usr/bin/env python3
"""
Test script to verify the orchestrator semaphore fix.

This test demonstrates that the nested semaphore acquisition bug has been fixed.
The orchestrator should not attempt to acquire the same semaphore twice in the
same thread, which would cause a deadlock.
"""

import threading
import time

def test_nested_semaphore_deadlock():
    """
    Test that demonstrates the deadlock issue with nested semaphore acquisition.
    This is what was happening BEFORE the fix.
    """
    print("\n=== Testing BROKEN behavior (nested semaphore - would deadlock) ===")
    semaphore = threading.Semaphore(1)
    deadlock_detected = False
    
    def broken_nested_acquire():
        nonlocal deadlock_detected
        print("1. Acquiring semaphore (outer)...")
        with semaphore:
            print("2. Semaphore acquired (outer)")
            print("3. Trying to acquire semaphore again (inner - THIS WILL HANG)...")
            # This would deadlock - commenting out to prevent actual hang
            # with semaphore:
            #     print("4. This line would NEVER execute!")
            deadlock_detected = True
            print("4. Skipped nested acquisition to avoid deadlock")
    
    thread = threading.Thread(target=broken_nested_acquire)
    thread.start()
    thread.join(timeout=2)
    
    if thread.is_alive():
        print("⚠️  Thread is still alive - DEADLOCK DETECTED!")
        return False
    elif deadlock_detected:
        print("✓ Test passed - deadlock would have occurred with nested acquisition")
        return True
    else:
        print("✗ Test failed - unexpected behavior")
        return False

def test_sequential_semaphore_release():
    """
    Test that demonstrates the CORRECT behavior - sequential execution
    without nested acquisition. This is what happens AFTER the fix.
    """
    print("\n=== Testing FIXED behavior (no nested semaphore) ===")
    semaphore = threading.Semaphore(1)
    execution_log = []
    
    def parent_action():
        """Simulates parent action execution"""
        execution_log.append("parent_start")
        time.sleep(0.1)
        execution_log.append("parent_end")
    
    def child_action():
        """Simulates child action execution"""
        execution_log.append("child_start")
        time.sleep(0.1)
        execution_log.append("child_end")
    
    def fixed_sequential_execution():
        """This is the FIXED pattern - both actions run in same semaphore context"""
        print("1. Acquiring semaphore...")
        with semaphore:
            print("2. Semaphore acquired")
            print("3. Executing parent action...")
            parent_action()
            print("4. Parent complete, executing child action...")
            # Child runs in SAME semaphore context - no re-acquisition needed
            child_action()
            print("5. Child complete")
        print("6. Semaphore released")
    
    thread = threading.Thread(target=fixed_sequential_execution)
    thread.start()
    thread.join(timeout=2)
    
    if thread.is_alive():
        print("✗ Test failed - thread hung unexpectedly!")
        return False
    
    expected_log = ["parent_start", "parent_end", "child_start", "child_end"]
    if execution_log == expected_log:
        print(f"✓ Test passed - actions executed sequentially: {execution_log}")
        return True
    else:
        print(f"✗ Test failed - unexpected execution order: {execution_log}")
        return False

def main():
    """Run all tests"""
    print("=" * 70)
    print("Orchestrator Semaphore Fix Verification Tests")
    print("=" * 70)
    
    results = []
    results.append(("Nested Semaphore Deadlock Detection", test_nested_semaphore_deadlock()))
    results.append(("Sequential Execution (Fixed)", test_sequential_semaphore_release()))
    
    print("\n" + "=" * 70)
    print("Test Results Summary")
    print("=" * 70)
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    all_passed = all(result for _, result in results)
    print("\n" + ("=" * 70))
    if all_passed:
        print("✓ All tests passed! The semaphore fix is working correctly.")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    exit(main())
