#!/usr/bin/env python3
"""Test if the server can start"""
import sys
print("=" * 60)
print("Testing server startup...")
print("=" * 60)

try:
    print("1. Importing modules...")
    from server import app
    print("✅ Server imported successfully!")
    
    print("\n2. Checking app routes...")
    routes = [route.path for route in app.routes]
    print(f"✅ Found {len(routes)} routes")
    
    print("\n3. Server is ready to start!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
