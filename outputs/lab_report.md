# Báo cáo Lab 11

*Sinh tự động bằng `scripts/grade.py`.*

## CP2–CP3 · Blue Team

Trong lượt kiểm thử của em, Blue cho qua **5/5** câu hợp lệ, chặn **7/7** ca đối kháng và **2/3** ca biên. Rate limit cho qua **10** và chặn **5** trong **15** yêu cầu.

[results.json](<results.json>) · [audit_log.json](<audit_log.json>) · [metrics.json](<metrics.json>)

## CP4 · Red Team

Kết quả em lưu khi chạy `openai` / `gpt-4o-mini` ghi nhận **2/5** ca lộ dữ liệu demo ở Red và **0/5** ca ở Red Advance. Điểm cộng cần được xác minh qua lượt chạy lại của grader.

[attack_results.json](<attack_results.json>) · [unsafe_attack_result.json](<unsafe_attack_result.json>) · [guards_attack_result.json](<guards_attack_result.json>)

## CP5 · Tự kiểm

- Em đã kiểm tra đủ hai artifact bắt buộc.
- `results.json` hợp lệ theo schema.
- **Smoke tests** có mã thoát `0` · `39 passed in 2.08s`
- **Public tests** có mã thoát `0` · `15 passed in 0.40s`
