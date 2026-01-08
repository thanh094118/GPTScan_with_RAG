import requests
import json

# ================= CẤU HÌNH =================
# Model ID bạn muốn kiểm tra (Copy chính xác từ log trước)
TARGET_MODEL_ID = "gemini-2.5-flash-lite-preview-09-2025"

# Key của bạn (Tôi đã điền sẵn key cũ, nếu đổi key mới hãy sửa lại)
GOOGLE_API_KEY = "AIzaSyDl4GOtAb41jV3NgndjYcPYH7x7ZP4CvdQ" 

def test_specific_model():
    print(f"📡 Đang kết nối tới model: {TARGET_MODEL_ID} ...")
    
    # URL chuẩn của Google API
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{TARGET_MODEL_ID}:generateContent?key={GOOGLE_API_KEY}"
    
    payload = {
        "contents": [{
            "parts": [{"text": "Xin chào, hãy giới thiệu ngắn gọn về bạn."}]
        }]
    }
    
    try:
        response = requests.post(
            url, 
            headers={"Content-Type": "application/json"}, 
            json=payload,
            timeout=10
        )
        
        # --- PHÂN TÍCH KẾT QUẢ ---
        if response.status_code == 200:
            data = response.json()
            try:
                # Lấy nội dung trả lời
                reply = data['candidates'][0]['content']['parts'][0]['text']
                print("\n✅ [THÀNH CÔNG] ID Model CHÍNH XÁC!")
                print("-" * 50)
                print(f"🤖 Phản hồi từ model:\n{reply}")
                print("-" * 50)
                return True
            except KeyError:
                print("\n⚠️ [CẢNH BÁO] Kết nối OK nhưng model không trả lời nội dung (Có thể do filter).")
                print(json.dumps(data, indent=2))
                return False
                
        elif response.status_code == 404:
            print(f"\n❌ [LỖI 404] Sai tên ID Model!")
            print(f"Google báo: Không tìm thấy resource 'models/{TARGET_MODEL_ID}'")
            print("👉 Gợi ý: Kiểm tra lại xem có thừa khoảng trắng hoặc sai ký tự không.")
            
        else:
            print(f"\n❌ [LỖI {response.status_code}]")
            print(response.text)

    except Exception as e:
        print(f"\n❌ Lỗi kết nối: {e}")

if __name__ == "__main__":
    test_specific_model()

#python3.10 main.py -s ../contracts -o ../sourcecode/output.json -k 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
#AIzaSyDl4GOtAb41jV3NgndjYcPYH7x7ZP4CvdQ