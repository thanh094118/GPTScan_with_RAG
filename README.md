# 🔍 GPTScan – AI-powered Smart Security Scanner

GPTScan là một công cụ quét và phân tích bảo mật thông minh, kết hợp giữa **rule-based scanning** và **trí tuệ nhân tạo (LLM)** nhằm phát hiện, phân tích và diễn giải các lỗ hổng bảo mật trong mã nguồn, tài liệu và hệ thống phần mềm.

GPTScan hướng tới việc tự động hóa quy trình **kiểm toán bảo mật**, **phân tích mã nguồn**, và **đánh giá rủi ro**, phù hợp cho cả học tập, nghiên cứu và ứng dụng thực tế.

---

## 🚀 Mục tiêu chính

- Tự động hóa quá trình quét và phân tích bảo mật
- Ứng dụng mô hình ngôn ngữ lớn (LLM) trong lĩnh vực Security
- Khai thác **RAG (Retrieval-Augmented Generation)** để truy vấn tài liệu và tri thức chuyên ngành
- Giảm phụ thuộc vào phân tích bảo mật thủ công
- Hỗ trợ sinh viên, pentester, auditor và DevSecOps

---

## 🧠 Kiến trúc tổng quan

GPTScan gồm các thành phần chính sau:

- **Scanning Engine**  
  Phân tích mã nguồn, log và tài liệu dựa trên các luật bảo mật (OWASP, custom rules)

- **LLM Analyzer**  
  Sử dụng LLM để:
  - Diễn giải kết quả quét
  - Phân loại mức độ nghiêm trọng (Low / Medium / High)
  - Gợi ý biện pháp khắc phục

- **RAG Module**  
  Truy vấn thông minh trên tập tài liệu đã được index (PDF, source code, audit report)

- **Rule Repository**  
  Kho chứa các luật phát hiện lỗ hổng, có thể được mở rộng tự động bằng AI

- **Web UI / API**  
  Giao diện web để upload tài liệu, gửi truy vấn và theo dõi kết quả

- **Docker-based Deployment**  
  Dễ dàng triển khai bằng Docker / Docker Compose

---

## ⚙️ Tính năng chính

- 🔹 Quét bảo mật tĩnh (Static Analysis)
- 🔹 Truy vấn tài liệu bằng ngôn ngữ tự nhiên
- 🔹 Hỗ trợ nhiều LLM (OpenAI, Gemini, local models…)
- 🔹 Phân tích báo cáo kiểm toán (PDF)
- 🔹 Sinh và mở rộng rule quét bảo mật bằng AI
- 🔹 Dễ tích hợp CI/CD và mở rộng

---

## 📚 Retrieval-Augmented Generation (RAG)

**Retrieval-Augmented Generation (RAG)** là kỹ thuật kết hợp giữa:
- **Retrieval**: truy xuất thông tin từ knowledge base bên ngoài
- **Generation**: sinh nội dung bằng mô hình ngôn ngữ lớn (LLM)

Thay vì chỉ phụ thuộc vào dữ liệu huấn luyện sẵn, RAG cho phép LLM **lấy thông tin trực tiếp từ các tài liệu chuyên biệt**, giúp kết quả:
- Chính xác hơn
- Có ngữ cảnh rõ ràng
- Phù hợp với bài toán chuyên ngành như bảo mật

RAG đặc biệt hiệu quả trong các bài toán:
- Truy vấn báo cáo audit
- Phân tích lỗ hổng bảo mật
- Khai thác tri thức OWASP, CVE, Secure Coding

---

## 🧠 Ứng dụng RAG trong GPTScan

Trong GPTScan, RAG không chỉ được dùng để **trả lời câu hỏi**, mà còn để **mở rộng kho luật quét bảo mật (Rule Repository)**.

### 🔎 Query Knowledge Base

GPTScan sử dụng RAG để:
- Truy vấn knowledge base nội bộ (audit reports, secure coding guidelines, CVE, source code mẫu)
- Trích xuất các đoạn nội dung liên quan đến:
  - Lỗ hổng bảo mật
  - Pattern/anti-pattern nguy hiểm
  - Điều kiện khai thác

### 🧩 Sinh Rule bổ sung cho GPTScan

Quy trình sử dụng RAG để sinh rule trong GPTScan:

1. **Retrieve**  
   Truy xuất các đoạn nội dung liên quan từ knowledge base

2. **Analyze & Generate**  
   LLM phân tích nội dung và:
   - Trừu tượng hóa thành các detection pattern
   - Sinh ra rule quét bảo mật mới (YAML / JSON / DSL)

3. **Rule Enrichment**  
   Các rule mới được:
   - Bổ sung vào kho Rule của GPTScan
   - Áp dụng cho các lần quét tiếp theo
   - Giúp hệ thống cải thiện theo thời gian

### 🔁 Lợi ích

- Giảm công sức viết rule thủ công
- Luật quét bám sát tài liệu và dữ liệu thực tế
- Dễ thích nghi với lỗ hổng mới hoặc hệ thống đặc thù
- Biến GPTScan thành **AI Security Scanner bán tự học**

---

## 📦 Ứng dụng thực tế

- Kiểm toán bảo mật hệ thống backend, API
- Phân tích báo cáo audit (PDF)
- Nghiên cứu và học tập về **AI for Security**
- Hỗ trợ DevSecOps trong SDLC

---

## 📄 Giấy phép

Dự án được phát triển với mục đích học tập và nghiên cứu.  
Chi tiết xem tại file `LICENSE`.

---

## 📬 Đóng góp

Mọi đóng góp, issue và pull request đều được hoan nghênh 🚀  
