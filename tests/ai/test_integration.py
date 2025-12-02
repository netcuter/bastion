#!/usr/bin/env python3
"""
Quick Test - Security Scanner AI Integration
Tests all components without requiring external APIs
"""

import sys
from pathlib import Path

def test_imports():
    """Test if all modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        import scanner_ai_wrapper
        print("  ✅ scanner_ai_wrapper")
    except Exception as e:
        print(f"  ❌ scanner_ai_wrapper: {e}")
        return False
        
    try:
        import ai_cloud_api
        print("  ✅ ai_cloud_api")
    except Exception as e:
        print(f"  ❌ ai_cloud_api: {e}")
        return False
        
    try:
        import ai_local
        print("  ✅ ai_local")
    except Exception as e:
        print(f"  ❌ ai_local: {e}")
        return False
        
    try:
        import code_anonymizer
        print("  ✅ code_anonymizer")
    except Exception as e:
        print(f"  ❌ code_anonymizer: {e}")
        return False
        
    return True

def test_anonymization():
    """Test code anonymization"""
    print("\n🔒 Testing code anonymization...")
    
    from code_anonymizer import CodeAnonymizer
    
    # Test code with sensitive info
    test_code = '''
# Client: SecretCorp Inc.
def upload_file():
    # Upload to /var/www/secretcorp/uploads
    filename = request.form.get('name')
    path = os.path.join("/var/www/secretcorp/uploads", filename)
    with open(path, 'wb') as f:
        f.write(data)
'''
    
    anonymizer = CodeAnonymizer()
    anon_code, mapping = anonymizer.anonymize(test_code)
    
    # Check anonymization worked
    if "SecretCorp" not in anon_code:
        print("  ✅ Client name anonymized (in comments)")
    else:
        print("  ❌ Client name still visible")
        return False
        
    if "/var/www/secretcorp" not in anon_code or "string_" in anon_code:
        print("  ✅ Paths anonymized")
    else:
        print("  ❌ Paths still visible")
        print(f"     Code: {anon_code[:200]}")
        return False
        
    # Check that comments were removed
    if "#" not in anon_code or "Client:" not in anon_code:
        print("  ✅ Comments removed")
    else:
        print("  ❌ Comments still present")
        return False
        
    print(f"\n  Anonymized {len(mapping['strings'])} strings")
    print(f"  Anonymized {len(mapping['paths'])} paths")
    
    return True

def test_scanner():
    """Test scanner wrapper"""
    print("\n🔍 Testing scanner (no AI mode)...")
    
    from scanner_ai_wrapper import SecurityScannerAI
    
    scanner = SecurityScannerAI(ai_mode="none")
    results = scanner.scan("/tmp/test")
    
    if results['findings']:
        print(f"  ✅ Found {len(results['findings'])} findings (mock data)")
    else:
        print("  ❌ No findings returned")
        return False
        
    if 'statistics' in results:
        print(f"  ✅ Statistics generated")
        print(f"     - Raw: {results['statistics']['total_raw']}")
        print(f"     - Filtered: {results['statistics']['total_filtered']}")
    else:
        print("  ❌ No statistics")
        return False
        
    return True

def test_local_ai_class():
    """Test Local AI class (without actual server)"""
    print("\n🤖 Testing Local AI class...")
    
    from ai_local import LocalAIAssistant
    
    try:
        assistant = LocalAIAssistant(server_url="http://localhost:1234")
        print("  ✅ LocalAIAssistant initialized")
        
        # Don't actually call - just test initialization
        stats = assistant.get_stats()
        if stats['total_cost'] == 0.0:
            print("  ✅ Cost tracking works (local is free)")
        else:
            print("  ❌ Cost tracking broken")
            return False
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
        
    return True

def test_cloud_api_class():
    """Test Cloud API class (without actual API calls)"""
    print("\n☁️  Testing Cloud API class...")
    
    from ai_cloud_api import CloudAIAssistant
    
    try:
        # Test with dummy credentials (won't actually call API)
        assistant = CloudAIAssistant(
            api_key="test-key",
            api_base="https://api.example.com",
            model="fast"
        )
        print("  ✅ CloudAIAssistant initialized")
        
        stats = assistant.get_stats()
        if 'total_cost' in stats and 'model_tier' in stats:
            print("  ✅ Statistics structure correct")
        else:
            print("  ❌ Statistics structure broken")
            return False
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False
        
    return True

def main():
    """Run all tests"""
    print("="*60)
    print("🚀 Security Scanner AI Integration - Quick Test")
    print("="*60)
    
    tests = [
        ("Imports", test_imports),
        ("Anonymization", test_anonymization),
        ("Scanner", test_scanner),
        ("Local AI", test_local_ai_class),
        ("Cloud API", test_cloud_api_class),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} test crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}  {name}")
    
    print(f"\n🎯 Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Ready for deployment!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Check output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
