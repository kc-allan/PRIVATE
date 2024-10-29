import requests
import time
import sys

def test_sql_injection(base_url="http://localhost"):
    # List of test cases with different SQL injection patterns
    test_cases = [
        {
            "name": "Basic Single Quote Test",
            "payload": "'",
            "description": "Testing basic SQL syntax error"
        },
        {
            "name": "UNION SELECT Test",
            "payload": "' UNION SELECT 1,2,3--",
            "description": "Testing UNION-based injection"
        },
        {
            "name": "Boolean Test",
            "payload": "' OR '1'='1",
            "description": "Testing boolean-based injection"
        },
        {
            "name": "Time-Based Test",
            "payload": "' WAITFOR DELAY '0:0:5'--",
            "description": "Testing time-based injection"
        },
        {
            "name": "Stacked Queries Test",
            "payload": "'; DROP TABLE users--",
            "description": "Testing stacked queries"
        },
        {
            "name": "Comment Test",
            "payload": "'--",
            "description": "Testing comment injection"
        }
    ]

    print("\nStarting SQL Injection Tests...")
    print("=" * 50)

    for test in test_cases:
        print(f"\nExecuting: {test['name']}")
        print(f"Description: {test['description']}")
        print(f"Payload: {test['payload']}")
        
        try:
            # Encode the payload for URL
            encoded_payload = requests.utils.quote(test['payload'])
            url = f"{base_url}/search?q={encoded_payload}"
            
            # Send the request
            start_time = time.time()
            response = requests.get(url)
            end_time = time.time()
            
            print(f"Status Code: {response.status_code}")
            print(f"Response Time: {end_time - start_time:.2f} seconds")
            print(f"Response Length: {len(response.text)} bytes")
            
            # Check if ModSecurity blocked the request
            if response.status_code in [403, 406]:
                print("✅ ModSecurity successfully blocked the request")
            else:
                print("⚠️ Request was not blocked by ModSecurity")
                
        except requests.exceptions.RequestException as e:
            print(f"Error during test: {e}")
        
        print("-" * 50)
        # Add delay between tests
        time.sleep(1)

if __name__ == "__main__":
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost"
    test_sql_injection(base_url)
