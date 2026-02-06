import requests
import json

# Test configuration
API_URL = "http://localhost:5000/api/message"
API_KEY = "your-api-key-here"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

def test_scam_detection():
    """Test scam detection and agent engagement"""
    
    # Test messages simulating a scam conversation
    test_messages = [
        "Congratulations! You've won a lottery prize of $10,000!",
        "To claim your prize, you need to verify your bank account details immediately.",
        "Please provide your account number and we'll transfer the money.",
        "Also, send your UPI ID for faster processing: scammer@paytm",
        "Click this link to complete verification: http://fake-bank.com/verify"
    ]
    
    conversation_id = "test_conv_001"
    
    print("Testing Agentic Honey-Pot System")
    print("=" * 50)
    
    for i, message in enumerate(test_messages, 1):
        print(f"\nTurn {i}: Scammer Message")
        print(f"Input: {message}")
        
        payload = {
            "message": message,
            "conversation_id": conversation_id
        }
        
        try:
            response = requests.post(API_URL, headers=HEADERS, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                print(f"Scam Detected: {data['scam_detected']}")
                print(f"Agent Response: {data['agent_response']}")
                print(f"Turn Count: {data['engagement_metrics']['turn_count']}")
                
                # Show extracted intelligence if any
                intel = data['extracted_intelligence']
                if intel['bank_accounts'] or intel['upi_ids'] or intel['phishing_urls']:
                    print("Extracted Intelligence:")
                    if intel['bank_accounts']:
                        print(f"  Bank Accounts: {intel['bank_accounts']}")
                    if intel['upi_ids']:
                        print(f"  UPI IDs: {intel['upi_ids']}")
                    if intel['phishing_urls']:
                        print(f"  Phishing URLs: {intel['phishing_urls']}")
            else:
                print(f"Error: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to the API. Make sure the server is running.")
            break
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_scam_detection()