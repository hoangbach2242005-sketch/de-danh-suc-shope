# Phân Tích Chuyên Sâu Shopee (`com.shopee.vn` v3.86.31) — Anti-Fraud, Network API & Session Hủy Đơn

Repository này lưu trữ toàn bộ tài liệu reverse engineering tĩnh/nhị phân từ gói `shopeezin.xapk` (`com.shopee.vn`, `versionName: 3.86.31`, `versionCode: 38631`) và đối chiếu trực tiếp với phiên đặt/hủy đơn thực tế trong `NetworkCapture/REPORT ORDER.md`.

---

## 1. Cấu Trúc Thư Mục Project

```text
DIZMESHOPEFOOD/
├── README.md                          # Tài liệu hướng dẫn đọc cấu trúc project (file này)
├── .gitignore                         # Loại trừ file nhị phân >100MB (.xapk/.apk) và thư mục decompile/extracted
├── APK/
│   ├── shopeezin_re_report.md         # [Báo cáo tổng] Cấu trúc XAPK, nhóm API & header bảo mật
│   ├── FRAUD_Analyze.md               # [Báo cáo tổng] Kiến trúc Anti-Fraud 6 tầng & chấm điểm thiết bị
│   ├── ROUND1_OPTION_C_NATIVE.md      # [Vòng 1 - Option C] Phân tích tầng Native (.so) bằng LIEF/Capstone/REA
│   ├── ROUND2_OPTION_B_FLOW.md        # [Vòng 2 - Option B] Luồng JS/RN/Web -> SHPSSDK & đối chiếu phiên hủy đơn
│   ├── ROUND3_OPTION_A_LOGCAT.md      # [Vòng 3 - Option A] Phân tích toàn bộ 5,045 dòng logcat + ma trận khắc phục
│   ├── shopeezin.xapk                 # (Ignored trên Git) Gói XAPK gốc (111 MB)
│   ├── shopeezin-extracted/           # (Ignored trên Git) Nội dung giải nén XAPK, bundle_v9 (Hermes v90), .so
│   └── shopeezin-decompiled/          # (Ignored trên Git) Mã nguồn Java/Kotlin decompile bởi JADX 1.5.7
└── NetworkCapture/
    └── REPORT ORDER.md                # Log phiên đặt đơn thực tế (SHOPEE_LOGCAT.LOG + TIMELINE.LOG, 5,045 dòng)
```

---

## 2. Thứ Tự Đọc Tài Liệu Đề Xuất

1. **Bắt đầu từ tổng quan API & cấu trúc gói:**
   - Đọc [`APK/shopeezin_re_report.md`](APK/shopeezin_re_report.md) để nắm cấu trúc `shopeezin.xapk`, các module React Native/Hermes (`bundle_v9`), các nhóm endpoint (`df.infra.sz.shopee.vn`, `mall.shopee.vn`, `api.shopee.vn:20346`, UBT tracking), và các header bảo mật (`af-ac-enc-sz-token`, `x-sap-ri`, `x-sap-sec`, `X-SPC-DF`).
2. **Hiểu kiến trúc chấm điểm thiết bị 6 tầng:**
   - Đọc [`APK/FRAUD_Analyze.md`](APK/FRAUD_Analyze.md) để nắm toàn bộ 12 cờ bitmask `SPSAssessRisk`, cơ chế `SHPSSDK`, `Aloeswood` (sensor/touch), `LuBan`, `DataCollection`, và cơ chế chặn `HTTP 418` (`CaptchaInterceptor`).
3. **Đi sâu từng vòng phân tích chi tiết (Round 1 -> Round 3):**
   - **Vòng 1 (Tầng Native `.so`):** [`APK/ROUND1_OPTION_C_NATIVE.md`](APK/ROUND1_OPTION_C_NATIVE.md) — phân tích `libshpssdk.so` (116 `.init_array` ctors, ẩn 6 hàm JNI qua `JNI_OnLoad`, Lua VM + 5 payload `\x1bCS\x80`/`\x1bLVM`), `libshopeeaegis.so` (179 exports mật mã `Aegis`/`TeslaModel`), và `libtoolChecker.so` (`RootBeerNative`).
   - **Vòng 2 (Luồng `assessRisk()` & Checkout):** [`APK/ROUND2_OPTION_B_FLOW.md`](APK/ROUND2_OPTION_B_FLOW.md) — truy vết từ `shopeepay.bundle` (`GADigitalSignature.assessRisk`, `GASECProtect.assessRisk`, `place_order`) qua bridge Java xuống `vvvvwvvvu.java` (DisplayListener bit `128`, isolated process `:wvvvuvww` bit `1`, quét Accessibility/IME `vwwwvvuwv.java`) và đối chiếu trực tiếp với đơn `249036761217534`.
   - **Vòng 3 (Toàn bộ Logcat & Khắc phục):** [`APK/ROUND3_OPTION_A_LOGCAT.md`](APK/ROUND3_OPTION_A_LOGCAT.md) — phân loại đầy đủ toàn bộ 5,045 dòng trong [`NetworkCapture/REPORT ORDER.md`](NetworkCapture/REPORT%20ORDER.md) (kể cả log nền hệ thống), chứng minh chuỗi nguyên nhân hủy đơn `odp_banner_cancelled_cancel_by_system` (`error: 31300102`), và bảng đánh giá phương pháp khắc phục + rủi ro.

---

## 3. Tóm Tắt Nhanh Nguyên Nhân Hủy Đơn `249036761217534`

| Tín hiệu ghi nhận trong `REPORT ORDER.md` | Cơ chế tương ứng trong APK | Tác động |
|---|---|---|
| **239x `[SCAM_DETECTION]`** (`pkg=com.android.display.colorimeter`) | `Action` Anti-Fraud Accessibility + `vwwwvvuwv.java` (`RISK_ACC_ENABLE`) | Đánh dấu dịch vụ Accessibility chạy suốt phiên checkout |
| **5x `ContentRecordingSession`** (`displayId=2..6`) | `DisplayManager.DisplayListener` trong `vvvvwvvvu.java` (`RISK_SCREEN_SHARING=128`) | Phát hiện màn hình ảo mirror `displayId=0` |
| **`com.android.shell (uid=0)` -> `xwkeyboard/.ClipboardService`** | Giám sát tiến trình & IME (`vwwwvvuwv.java`) | Dấu hiệu tự động hóa / điều khiển qua shell |
| **`ClassLoaderContext` checksum mismatch & `keystore2` error** | Kiểm tra toàn vẹn môi trường (`libshpssdk.so`, `:wvvvuvww`) | Nghi ngờ môi trường/ROM/APK bị can thiệp |
| **`tss_captcha`** (`scenario="crawler_item"`) ngay trước checkout | Backend bot scoring trước `place_order` | Đẩy risk score lên ngưỡng hủy tức thì (`error: 31300102`) |

---

## 4. Ghi Chú Tái Lập Môi Trường Phân Tích

- Nếu cần tái kiểm tra mã nguồn Java hoặc binary `.so` cục bộ, đặt file `shopeezin.xapk` vào `APK/`, giải nén bằng `unzip`/7z ra `APK/shopeezin-extracted/`, và decompile `com.shopee.vn.apk` bằng **JADX 1.5.7** ra `APK/shopeezin-decompiled/base`.
- Toàn bộ tài liệu trong repo tuân thủ nguyên tắc **chỉ ghi nhận bằng chứng quan sát trực tiếp** từ file decompile, ELF binary, chuỗi HBC v90 và log phiên thực tế.
