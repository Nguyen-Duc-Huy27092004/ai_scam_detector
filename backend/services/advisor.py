def generate_advice(
    url: str,
    prediction: int,
    confidence: float,
    risk_level: str
) -> str:
    """
    Sinh lời khuyên cho người dùng dựa trên kết quả AI
    """

    if prediction == 1: 
        if risk_level == "high":
            return (
                "CẢNH BÁO NGUY HIỂM!\n"
                "Đây là đường link có dấu hiệu lừa đảo rất cao.\n"
                "Không truy cập\n"
                "Không nhập thông tin cá nhân\n"
                "Không đăng nhập tài khoản\n\n"
                "Bạn nên đóng trang web này ngay và báo cáo nếu có thể."
            )

        if risk_level == "medium":
            return (
                "Đường link này có nhiều dấu hiệu đáng ngờ.\n"
                "Hãy kiểm tra kỹ tên miền, nội dung website và nguồn gửi link.\n"
                "Tuyệt đối không nhập mật khẩu hoặc thông tin nhạy cảm."
            )

        return (
            "Đường link có một số dấu hiệu bất thường.\n"
            "Bạn nên cẩn trọng và chỉ truy cập nếu chắc chắn nguồn gửi là đáng tin cậy."
        )

    # safe
    return (
        "Đường link có vẻ an toàn theo phân tích của hệ thống.\n"
        "Tuy nhiên, bạn vẫn nên kiểm tra kỹ nội dung và không chia sẻ thông tin cá nhân "
        "nếu có bất kỳ nghi ngờ nào."
    )
