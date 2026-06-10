import requests
import pandas as pd

def fetch_tron_wallet_data(wallet_address):
    """
    Pulls real-time TRC-20 USDT transaction history via TronGrid API.
    Strips the hex jargon and returns a clean DataFrame.
    """
    if not wallet_address:
        return None
        
    url = f"https://api.trongrid.io/v1/accounts/{wallet_address}/transactions/trc20"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', [])
            if not data:
                return None
            
            parsed_data = []
            for tx in data:
                parsed_data.append({
                    "Timestamp": pd.to_datetime(tx.get('block_timestamp'), unit='ms'),
                    "From": tx.get('from'),
                    "To": tx.get('to'),
                    "Token": tx.get('token_info', {}).get('symbol', 'USDT'),
                    "Amount": float(tx.get('value', 0)) / (10 ** int(tx.get('token_info', {}).get('decimals', 6)))
                })
            return pd.DataFrame(parsed_data)
        return None
    except Exception as e:
        return None