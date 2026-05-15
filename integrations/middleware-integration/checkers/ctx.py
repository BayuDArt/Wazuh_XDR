import requests
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("CTX_API_KEY")

IOC_TYPE_PATHS = {
    "hash": "file",
    "ip": "ip"
}

def check_ctx(ioc_value, ioc_type):
    
    path_segment = IOC_TYPE_PATHS.get(ioc_type)
    
    if not path_segment:
        print(f"Error CTX: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"
    
    url = f"https://api.ctx.io/v1/{path_segment}/report/{ioc_value}"
    headers = {"x-api-key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return "Not Found"
            
        response.raise_for_status() 
        data = response.json()
        
        analysis_data = data.get("ctx_data") or \
                        data.get("ip_data") or \
                        {} 

        
        detect_name = analysis_data.get("detect")
        
        
        return detect_name 

    except requests.exceptions.RequestException as e:
        print(f"Error saat menghubungi CTX API: {e}")
        return "Error"
    except Exception as e:
        print(f"Error pemrosesan data CTX: {e}")
        return "Error"