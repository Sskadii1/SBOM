# SBOM
Enhancing SBOM Vulnerability Comprehension for Non-Expert Stakeholders: An LLM-based Explanation Framework

Lấy SBOM (danh sách “những thứ phần mềm này đang dùng” – giống như danh sách nguyên liệu),

kiểm tra xem trong danh sách đó có phân mảnh nào đang dính lỗ hổng bảo mật không,

xuất báo cáo,

rồi (tuỳ chọn) đưa báo cáo/dữ liệu vào bộ nhớ tra cứu để bạn hỏi kiểu ChatGPT: “Có rủi ro gì? package nào nguy hiểm nhất? nên xử lý gì trước?” và nó trả lời dựa trên dữ liệu đó.

Quy trình đó chạy như thế nào

Có SBOM

Trong tài liệu này, SBOM đang được tải về mẫu để thử nghiệm (chứ không phải tự tạo SBOM từ code).

Bóc danh sách thư viện ra

Đọc file SBOM để lấy ra từng tên thư viện + phiên bản + mã định danh chuẩn.

Nó gọi tới database lỗ hổng (OSV) để hỏi: “thư viện X phiên bản Y có lỗ hổng nào đang biết không?”

Tạo file report kiểu Markdown: package nào có bao nhiêu lỗ hổng, ID lỗ hổng là gì…

Nó gom kết quả thành các “mẩu thông tin” (chunks) sau đưa vào Vector DB và khi hỏi, nó sẽ lôi đúng mẩu liên quan ra làm bằng chứng rồi AI trả lời.

Kết quả cuối cùng bạn nhận được là một báo cáo: phần mềm đang dùng những thư viện nào và thư viện nào có lỗ hổng bảo mật.
