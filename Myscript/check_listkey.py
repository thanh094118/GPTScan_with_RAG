import time
import google.generativeai as genai

# API Key của bạn
API_KEY = "AIzaSyDl4GOtAb41jV3NgndjYcPYH7x7ZP4CvdQ"
genai.configure(api_key=API_KEY)

# Danh sách model free tier
MODELS_TO_TEST = [
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash-lite",
    "gemini-2.0-flash",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemini-pro-latest",
    "gemini-1.5-flash",
    "gemini-1.5-flash-lite",
]

print("🔍 Đang test các model Gemini...\n")

for model_name in MODELS_TO_TEST:
    print(f"Testing: {model_name}", end="... ")
    
    success = False
    response_text = ""
    
    for attempt in range(2):  # Thử tối đa 2 lần mỗi model
        try:
            model = genai.GenerativeModel(model_name)
            resp = model.generate_content("Xin chào!")
            
            if resp and resp.text:
                success = True
                response_text = resp.text[:50] + "..." if len(resp.text) > 50 else resp.text
                break
            else:
                time.sleep(1)  # Chờ 1s nếu không có response
                
        except Exception as e:
            error_str = str(e)
            if "quota" in error_str.lower() or "429" in error_str:
                print(f"[QUOTA] ", end="")
                break
            time.sleep(1)  # Chờ 1s trước khi retry
    
    if success:
        print(f"✅ OK - Response: {response_text}")
    else:
        print("❌ FAILED")
    
    time.sleep(0.5)  # Chờ giữa các model

print("\n✅ Hoàn thành test tất cả model!")