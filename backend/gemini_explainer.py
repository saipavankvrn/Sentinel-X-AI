import os
import time
try:
    import google.generativeai as genai
    from google.generativeai.types import HarmCategory, HarmBlockThreshold
    from dotenv import load_dotenv
    load_dotenv() # Load variables from .env
except ImportError:
    genai = None

# Load API Key from environment variable for security
api_key = os.getenv("GEMINI_API_KEY")

# Global states for Quota management
api_throttled_until = 0  # Timestamp when we can try the API again
explanation_cache = {}    # Cache results by Task-Type (Port) to save money/quota

if genai and api_key:
    genai.configure(api_key=api_key)

def get_best_model_name():
    try:
        models = [m.name for m in genai.list_models()]
        candidates = ["models/gemini-2.0-flash", "models/gemini-1.5-flash", "models/gemini-pro"]
        for c in candidates:
            if c in models: return c
        return "models/gemini-pro"
    except:
        return "gemini-pro"

def get_local_fallback_explanation(features):
    port = features.get('dst_port') or features.get('Destination Port')
    length = features.get('packet_length') or features.get('Packet Length Mean') or 0
    
    if port == 53: return "Anomaly in DNS traffic. Potential DNS tunneling or amplification attempt."
    if port in [80, 443]: return "Suspicious web traffic. Pattern suggests SQLi or abnormal payload size."
    if port == 22: return "Brute force attempt on SSH service detected. High-frequency login attempts."
    if length > 1400: return "Abnormally large packet size detected. Possible data exfiltration."
    
    return "Traffic deviates from baseline. Behavioral signature suggests scanning or reconnaissance."

def get_threat_explanation(features):
    global api_throttled_until
    
    # 1. Check if we are currently "Cooling Down" from a 429 Quota error
    if time.time() < api_throttled_until:
        return get_local_fallback_explanation(features)

    # 2. Check Cache (Same port often has same threat type)
    port = features.get('dst_port', features.get('Destination Port', 'generic'))
    if port in explanation_cache:
        return explanation_cache[port]

    if not genai or not api_key:
        return get_local_fallback_explanation(features)
        
    try:
        model_name = get_best_model_name()
        model = genai.GenerativeModel(model_name, 
                                    generation_config={"temperature": 0.4, "max_output_tokens": 100},
                                    safety_settings={ HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE })
        
        prompt = f"Explain briefly why this is suspicious: Port {port}, Proto {features.get('protocol')}, Length {features.get('packet_length', 0)}B."
        
        response = model.generate_content(prompt)
        if response and response.text:
            cleaned_text = response.text.strip()
            explanation_cache[port] = cleaned_text # Store for quota saving
            return cleaned_text
        return get_local_fallback_explanation(features)

    except Exception as e:
        # If Quota Exceeded (429), silence the error and throttle for 2 minutes
        if "429" in str(e) or "quota" in str(e).lower():
            print("⚠️ [SYSTEM] Gemini API Quota reached. Switching to Local Intelligence Engine for 2 minutes.")
            api_throttled_until = time.time() + 120 # 2 minute cooldown
        else:
            print(f"DEBUG [API Error]: {str(e)[:50]}...")
            
        return get_local_fallback_explanation(features)
