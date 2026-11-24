# Vòng 1 (Option C): Phân Tích Tầng Native Binary (`.so`) — `shopeezin.xapk`

> **Đối tượng:** `d:\DIZMESHOPEFOOD\APK\shopeezin.xapk` (`com.shopee.vn`, v`3.86.31`, `versionCode: 38631`)  
> **Kiến trúc trích xuất:** `config.arm64_v8a.apk` (`arm64-v8a`)  
> **Công cụ xác thực:** `rea` MCP (`inspect_native_exports`), Python `lief`, `capstone` (ARM64), `zlib` / `base64`  
> **Nguyên tắc:** Toàn bộ địa chỉ, kích thước, symbol, chuỗi và cấu trúc dưới đây được trích xuất trực tiếp từ ELF binary trong gói APK; không suy diễn phần chưa quan sát.

---

## 1. Tổng Quan Các Thư Viện Native Trọng Yếu

| Thư viện | Kích thước (`arm64-v8a`) | Lớp Java nạp | Vai trò chính |
|---|---|---|---|
| `libshpssdk.so` | `5,720,080` bytes | `com.shopee.shpssdk.wvvvuuww` (ZygotePreload) & `wvvvuwwu` | Lõi phát hiện rủi ro thiết bị, DFP (`df.infra.sz.shopee.vn`), ký request (`x-sap-*`, `af-ac-enc-sz-token`), nhúng Lua VM |
| `libshopeeaegis.so` | `280,808` bytes | `com.shopee.sz.reinforce.Aegis` | Engine mật mã/ký nội tuyến (`AES-CBC/CCM/CTR`, `SHA`, `HMAC`) cho module `com.shopee.sz` |
| `libtoolChecker.so` | `5,512` bytes | `com.scottyab.rootbeer.RootBeerNative` | Kiểm tra sự tồn tại của các file dấu hiệu root (`su`, `magisk`, `busybox`) qua `fopen` |

---

## 2. `libshpssdk.so` (`5,720,080` bytes, ARM64 ELF)

### 2.1. Khởi tạo sớm & Ẩn JNI Symbol
- **`.init_array`:** Chứa **116 hàm constructor** (bắt đầu từ `0x5aea0`, `0x5aeec`, `0x63154`, ...) chạy giải mã bảng chuỗi và thiết lập môi trường trước khi `JNI_OnLoad` thực thi.
- **Dynamic Exports:** Bảng export chỉ lộ duy nhất **`JNI_OnLoad`** tại `0x32e7a4` (size `148` bytes).
- **Đăng ký JNI động (`RegisterNatives`):** Disassembly ARM64 tại `JNI_OnLoad` (`0x32e7a4`) cho thấy hàm gọi tiếp vào bộ đăng ký nội bộ tại `0x32c444`, truyền con trỏ bảng phương thức tại `0x571e78`, `0x571f40` và descriptor tại `0x474538` để đăng ký ẩn 6 hàm `native` của `com/shopee/shpssdk/wvvvuwwu` (`vuwuuwvu`, `vuwuuwvv`, `vuwuuwvvw`, `vuwuuwvw`, `vuwuvuwwvw`, `vuwuvwwu`).

### 2.2. Lua VM & 5 Khối Bytecode Nén Nhúng Sẵn
- **Lua VM:** Chứa đầy đủ chuỗi runtime của Lua (`LUA_PATH`, `LUA_CPATH`, `cannot resume dead coroutine`, `PANIC: unprotected error in call to Lua API`).
- **5 khối dữ liệu `zlib + Base64` (`eJ...`):**
  - **4 khối header `1b 43 53 80` (`\x1bCS\x80`)** — biến thể header bytecode Lua (`\x1bLua`), kích thước sau giải nén lần lượt là **`4,738`**, **`4,164`**, **`2,426`**, và **`5,728` bytes**.
  - **1 khối header `1b 4c 56 4d` (`\x1bLVM`)** — kích thước sau giải nén **`5,520` bytes**.
- **Ý nghĩa kiến trúc:** Cho phép `SHPSSDK` cập nhật và thực thi các rule phát hiện/ký request động (`SAP_APPID`, `updateRequestCfg` qua response header `X-Sp-A`) mà không cần phát hành bản APK mới.

### 2.3. Imports & Chuỗi Kiểm Tra Môi Trường
- **System Imports:** `dl_iterate_phdr`, `dlopen`, `dlsym`, `fork`, `kill`, `stat`, `lstat`, `fstatat`, `statfs`, `access`, `readdir`, `__system_property_get`.
- **Chuỗi kiểm tra phát hiện:**
  - Bộ nhớ & tiến trình: `/proc/self/maps` (dò thư viện hook/Frida/Zygisk nạp vào tiến trình), `/sys/fs/selinux/context`, `/system/bin/app_process`, `/system/bin/app_process32`, `/system/bin/app_process64`.
  - Đối chiếu OEM framework: `miui-framework.jar`, `oplus-framework.jar`, `hwframework.jar`, `com.samsung.device.jar`, `libmiui_security.so`, `lib_oplus_security.so`, `libvivo_runtime.so`.

---

## 3. `libshopeeaegis.so` (`280,808` bytes, ARM64 ELF)

- **Lớp gọi Java:** `com/shopee/sz/reinforce/Aegis.java` (`System.loadLibrary("shopeeaegis")`), gọi `fire(int, byte[], byte[])` ứng với 9 chế độ trong `com/shopee/sz/reinforce/b.java`: `AEGIS_B64`, `AEGIS_AES_CBC`, `AEGIS_AES_CBC_B64`, `AEGIS_IV_AES_CBC_B64`, `AEGIS_MD5`, `AEGIS_SHA256`, `AEGIS_SHA512`, `AEGIS_HMAC_SHA256_BASE64`, `AEGIS_HMAC_SHA1_BASE64`.
- **Cấu trúc ELF:** `init_funcs=0`, entrypoint `0xf180`, **179 exported symbols**.
- **Các nhóm symbol chính:**
  - Lớp C++ `Aegis`: `Aegis::parse`, `Aegis::missileFire`, `Aegis::missileCount`, `Aegis::prism`, `Aegis::tugWar`, `Aegis::snowDon`.
  - Lớp C++ `TeslaModel`: `model_3`, `model_a`, `model_b`, `model_c`, `model_e`, `model_s`, `model_x`, `model_y`, `getNuremberg`.
  - Bộ mật mã nội tuyến: `modelx_autopilot_cbc`, `modelx_autopilot_ccm`, `modelx_autopilot_ctr`, `phantom1`, `phantom224`, `phantom256`, và các hàm vòng AES (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`).
- **Vai trò:** Là engine mật mã/ký cho module `com.shopee.sz`; không trực tiếp thực hiện kiểm tra root/hook như `libshpssdk.so` hay `libtoolChecker.so`.

---

## 4. `libtoolChecker.so` (`5,512` bytes, ARM64 ELF)

- **Xác nhận là `RootBeerNative`**, export đúng **3 symbol**:
  1. `Java_com_scottyab_rootbeer_RootBeerNative_setLogDebugMessages` (`0x8a8`)
  2. `_Z6existsPKc` (`0x8f0`): gọi `fopen(path, "r")`; nếu mở được thì `fclose` và trả `1`, ngược lại trả `0`.
  3. `Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot` (`0x9ac`): duyệt mảng `String[]` truyền từ Java (`com.scottyab.rootbeer.c`) và gọi `_Z6existsPKc` kiểm tra từng đường dẫn `su`/`magisk`/`busybox`.
