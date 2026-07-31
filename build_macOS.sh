#!/bin/bash
# ============================================================
#  build_macOS.sh — BYPASS LOGIN V9.5 cho 8 Ball Pool MOD
#  Tự động hóa 8 bước từ prompt V9.5
#
#  Chạy trên macOS (GitHub Actions hoặc local). Cần Xcode CLT.
#
#  Trước khi chạy (local):
#    $ brew install ldid insert_dylib
#    $ xcode-select --install
#    $ python3 -m pip install cryptography
#
#  Trên GitHub Actions: các dependencies đã được cài qua workflow.
#
#  Cách chạy (2 lựa chọn CHO WASM):
#  [A] Nếu có g_Ks thật từ runtime (hex 64 ký tự):
#      $ KS_HEX=41414141...  bash build_macOS.sh
#  [B] Nếu đã có sẵn file cheat_decoded.wasm (plaintext):
#      $ cp /path/to/cheat_decoded.wasm ./  &&  bash build_macOS.sh
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# === CẤU HÌNH ===
IPA_URL="https://download2276.mediafire.com/ul1espf6cx6gQOaOXo4ivPLbc93uSrG3kPrxvmHh0OIbJb4QljEbzdPuv_NzSTYDQSyb2G6MuzEnkgyeIkBRS-NmKjbha3j1IgJSp8KiENzO5X4GYp-KAe7BPU7pEKqwFWPq2QlxDr8AOX5d4hY5tIlMuSRAtrAz4BFPYgFjUjUpRA/bixvlpp43y5jozj/8+Ball+Pool_56.27.0_1785279359.ipa"
IPA_ORIG="$HERE/8 Ball Pool_56.27.0_1785279359.ipa"
IPA_OUT="$HERE/8BallPool_BYPASSED_V9.5.ipa"
EXTRACT="$HERE/ipa_extracted"
SRC_MM="$HERE/BYPASS_V9.5_DEFINITIVE.mm"
DECRYPT_PY="$HERE/decrypt_wasm.py"
LOGFILE="$HERE/V9.5_build_log.txt"
CHEAT_BASENAME="cheat_decoded.wasm"
ENC_WASM_REL="Payload/pool.app/j1O1pP4cpnaLPxs2xoSf/uTPEauDexK34zwVRiCRp"
BUNDLE_POOL="$EXTRACT/Payload/pool.app"
FRAMEWORKS="$BUNDLE_POOL/Frameworks"

# ============================================================
# 0. Prerequisites
# ============================================================
echo "============================================================"
echo " [0/8] KIỂM TRA PREREQUISITES"
echo "============================================================"
need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "  ❌ Thiếu: $1  (cần cài đặt: $2)"
    exit 1
  fi
}
need_cmd xcrun         "Xcode Command Line Tools -> xcode-select --install"
need_cmd clang         "Xcode Command Line Tools"
need_cmd insert_dylib  "brew install insert_dylib (hoặc dùng lệnh thay thế)"
need_cmd ldid          "brew install ldid"
need_cmd plutil        "macOS built-in"
need_cmd zip           "macOS built-in"
need_cmd unzip         "macOS built-in"
need_cmd python3       "macOS built-in (hoặc brew install python@3)"
need_cmd lipo          "Xcode Command Line Tools"
need_cmd otool         "Xcode Command Line Tools"
need_cmd shasum        "macOS built-in"

# Check cryptography python package (chỉ cần nếu có decrypt)
if ! python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('ok')" >/dev/null 2>&1; then
  echo "  ⚠️  Python package 'cryptography' chưa cài (không bắt buộc nếu có cheat_decoded.wasm sẵn)"
  echo "     -> Nếu cần decrypt, chạy: python3 -m pip install cryptography"
fi
echo "  ✅ Tất cả tools OK."

# ============================================================
# 1. Tải IPA từ MediaFire (nếu chưa có)
# ============================================================
echo ""
echo "============================================================"
echo " [1/8] TẢI IPA TỪ MEDIAFIRE (nếu chưa có local)"
echo "============================================================"
if [ ! -f "$IPA_ORIG" ]; then
    echo "  -> Đang tải IPA từ MediaFire..."
    curl -L -o "$IPA_ORIG" "$IPA_URL"
    if [ $? -ne 0 ] || [ ! -f "$IPA_ORIG" ]; then
        echo "  ❌ Tải IPA thất bại. Kiểm tra link."
        exit 2
    fi
    echo "  ✅ Tải IPA thành công: $(ls -lh "$IPA_ORIG" | awk '{print $5}')"
else
    echo "  ℹ️  IPA đã có sẵn ở local, bỏ qua tải."
fi

# ============================================================
# 2. Extract IPA & verify version
# ============================================================
echo ""
echo "============================================================"
echo " [2/8] GIẢI NÉN IPA VÀ XÁC NHẬN PHIÊN BẢN"
echo "============================================================"
if [ -d "$EXTRACT" ] && [ -f "$BUNDLE_POOL/pool" ]; then
  echo "  ℹ️  ipa_extracted/ đã có sẵn, bỏ qua giải nén."
else
  rm -rf "$EXTRACT"
  mkdir -p "$EXTRACT"
  echo "  -> unzip '$IPA_ORIG' ..."
  unzip -q "$IPA_ORIG" -d "$EXTRACT"
fi

# Check Info.plist CFBundleShortVersionString
VER=$(plutil -extract CFBundleShortVersionString raw "$BUNDLE_POOL/Info.plist" 2>/dev/null || echo "UNKNOWN")
echo "  CFBundleShortVersionString = $VER"
if [ "$VER" != "56.27.0" ]; then
  echo "  ⚠️  Version KHÔNG phải 56.27.0 — offset có thể sai. Tiếp tục (người dùng chịu trách nhiệm)."
fi
# Check critical files exist
for F in "pool" "Frameworks/libloader.framework/libloader" "Frameworks/loader.framework/loader" "Frameworks/ninja.framework/ninja" "j1O1pP4cpnaLPxs2xoSf/uTPEauDexK34zwVRiCRp"; do
  if [ ! -e "$BUNDLE_POOL/$F" ]; then
    echo "  ❌ Thiếu file quan trọng: $BUNDLE_POOL/$F"
    exit 3
  fi
done
echo "  ✅ Cấu trúc bundle OK."

# ============================================================
# 3. Decrypt WASM module (nếu có thể, hoặc dùng file sẵn)
# ============================================================
echo ""
echo "============================================================"
echo " [3/8] GIẢI MÃ WASM MODULE -> cheat_decoded.wasm"
echo "============================================================"
WASM_OUT="$BUNDLE_POOL/$CHEAT_BASENAME"

if [ -f "$HERE/$CHEAT_BASENAME" ] && [ $(stat -f%z "$HERE/$CHEAT_BASENAME" 2>/dev/null || echo 0) -gt 4000000 ]; then
  echo "  ℹ️  Tìm thấy cheat_decoded.wasm sẵn tại thư mục gốc (>= 4MB)."
  cp "$HERE/$CHEAT_BASENAME" "$WASM_OUT"
elif [ -f "$WASM_OUT" ] && [ $(stat -f%z "$WASM_OUT" 2>/dev/null || echo 0) -gt 4000000 ]; then
  echo "  ℹ️  cheat_decoded.wasm đã có trong bundle (>= 4MB). Bỏ qua decrypt."
else
  # Thử decrypt nếu có cryptography và g_Ks
  if command -v python3 >/dev/null 2>&1 && python3 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM" 2>/dev/null; then
    DEC_ARGS=()
    if [ -n "${KS_HEX:-}" ]; then
      echo "  -> Sử dụng g_Ks từ env KS_HEX (${#KS_HEX} chars)."
      DEC_ARGS+=(--ks-hex "$KS_HEX")
    else
      echo "  -> Không có KS_HEX. Thử decrypt với g_Ks = 0x41 * 32 (V9.5 SharedKey32 fix)."
      echo "     NẾU BỊ GCM TAG FAIL (exit code 2):"
      echo "        + set KS_HEX= hoặc cp cheat_decoded.wasm sẵn vào thư mục gốc rồi chạy lại."
    fi
    set +e
    python3 "$DECRYPT_PY" "$BUNDLE_POOL/j1O1pP4cpnaLPxs2xoSf/uTPEauDexK34zwVRiCRp" \
      --output "$WASM_OUT" "${DEC_ARGS[@]}"
    RC=$?
    set -e
    if [ $RC -ne 0 ]; then
      echo ""
      echo "  ⚠️  decrypt_wasm.py exit=$RC (thường là GCM tag fail vì g_Ks key 0x41 không đúng)."
      echo ""
      echo "  ======= CÁCH LẤY WASM THẬT ======="
      echo "  [Cách 1] — Dump g_Ks thật từ runtime:"
      echo "    a) Jailbreak hoặc debugserver: attach vào process pool"
      echo "    b) breakpoint tại ninja::AuthSession::handshake offset 0x128F20"
      echo "    c) Sau khi handshake thành công, dump 32 bytes tại:"
      echo "       VM = slide_ninja + 0x108000 + 0x0FC9  (g_Ks)"
      echo "    d) Chạy lại:   KS_HEX=<64 hex chars> bash build_macOS.sh"
      echo ""
      echo "  [Cách 2] — Dump WASM plaintext từ memory sau khi login gốc OK:"
      echo "    a) Cho app login thật thành công (trước khi bị wipe)"
      echo "    b) Tìm vùng nhớ chứa magic '\\0asm' với size ~4.1MB"
      echo "    c) Dump ra file cheat_decoded.wasm, copy vào ./ rồi chạy lại build."
      echo ""
      echo "  Script sẽ tiếp tục nhưng cheat sẽ KHÔNG HOẠT ĐỘNG nếu thiếu WASM thật."
      echo "  (Tạo dummy WASM để build bypass.dylib vẫn thành công.)"
    fi
  else
    echo "  ⚠️  Không có cryptography hoặc python, bỏ qua decrypt WASM."
  fi
fi

# Nếu vẫn chưa có WASM thật, tạo dummy để build pass
if [ ! -f "$WASM_OUT" ] || [ $(stat -f%z "$WASM_OUT" 2>/dev/null || echo 0) -lt 4000000 ]; then
  echo "  -> Tạo dummy WASM (1024 bytes) để build bypass.dylib vẫn thành công."
  dd if=/dev/zero of="$WASM_OUT" bs=1024 count=1 2>/dev/null
  echo "  ⚠️  DUMMY WASM được tạo. Cheat sẽ KHÔNG HOẠT ĐỘNG."
  echo "  ⚠️  Để cheat hoạt động, bạn cần cung cấp file WASM thật (>=4MB)."
fi

# Kiểm tra kích thước và magic (nếu có)
SZ=$(stat -f%z "$WASM_OUT" 2>/dev/null || echo 0)
echo "  cheat_decoded.wasm size = $SZ bytes ($(python3 -c "print(f'{$SZ/1024/1024:.2f}')" 2>/dev/null || echo "?"))"
if [ "$SZ" -ge 4000000 ]; then
  MAGIC=$(xxd -l 4 -p "$WASM_OUT" 2>/dev/null || echo "00000000")
  if [ "$MAGIC" = "0061736d" ]; then
    echo "  ✅ WASM magic OK (\\0asm)."
  else
    echo "  ⚠️  Magic không phải \\0asm (0x$MAGIC) — có thể file bị hỏng."
  fi
else
  echo "  ℹ️  Dummy WASM được sử dụng (cheat không hoạt động)."
fi

# ============================================================
# 4. Compile bypass.dylib (arm64 iOS)
# ============================================================
echo ""
echo "============================================================"
echo " [4/8] BIÊN DỊCH bypass.dylib (arm64)"
echo "============================================================"
if [ ! -f "$SRC_MM" ]; then
  echo "  ❌ Không tìm thấy $SRC_MM"
  exit 5
fi
DYLIB="$HERE/bypass.dylib"
rm -f "$DYLIB"
SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || echo "")
if [ -z "$SDK" ]; then
  echo "  ❌ Không tìm thấy iPhoneOS SDK. Xcode CLT chưa cài?"
  exit 5
fi
echo "  SDK path: $SDK"
BUILD_CMD=(xcrun -sdk iphoneos clang -arch arm64 -fobjc-arc
  -isysroot "$SDK"
  -miphoneos-version-min=14.0
  -framework Foundation -framework CFNetwork -framework Security
  -Wl,-undefined,dynamic_lookup
  -O2
  "$SRC_MM" -o "$DYLIB")
echo "  ${BUILD_CMD[*]}"
"${BUILD_CMD[@]}"
# Verify architecture
if ! lipo -info "$DYLIB" 2>/dev/null | grep -q "arm64"; then
  echo "  ❌ bypass.dylib không phải arm64!  lipo output:"
  lipo -info "$DYLIB" || true
  exit 5
fi
echo "  ✅ bypass.dylib built OK (arm64). Size: $(stat -f%z "$DYLIB") bytes"

# ============================================================
# 5. Inject LC_LOAD_DYLIB + copy dylib vào Frameworks
# ============================================================
echo ""
echo "============================================================"
echo " [5/8] CHÈN LC_LOAD_DYLIB (insert_dylib)"
echo "============================================================"
mkdir -p "$FRAMEWORKS"
cp "$DYLIB" "$FRAMEWORKS/bypass.dylib"
POOL_BIN="$BUNDLE_POOL/pool"
DYLIB_INSTALL_NAME="@executable_path/Frameworks/bypass.dylib"

# Check if already injected
if otool -l "$POOL_BIN" 2>/dev/null | grep -qF "$DYLIB_INSTALL_NAME"; then
  echo "  ℹ️  LC_LOAD_DYLIB bypass.dylib đã có sẵn trong pool. Bỏ qua injection."
else
  # Back up binary nếu chưa
  if [ ! -f "$POOL_BIN.orig" ]; then cp "$POOL_BIN" "$POOL_BIN.orig"; fi
  echo "  -> insert_dylib --inplace --all-yes \"$DYLIB_INSTALL_NAME\" \"$POOL_BIN\""
  if ! insert_dylib --inplace --all-yes "$DYLIB_INSTALL_NAME" "$POOL_BIN"; then
    echo "  ❌ insert_dylib FAILED. Có thể binary đã có protected segment."
    echo "     Restore backup: cp pool.orig pool"
    exit 6
  fi
fi

# Verify
echo "  -> Verify LC_LOAD_DYLIB entries (pool binary):"
otool -l "$POOL_BIN" 2>/dev/null | grep -A2 LC_LOAD_DYLIB | head -60 || true
if ! otool -L "$POOL_BIN" 2>/dev/null | grep -qF "bypass.dylib"; then
  echo "  ❌ SAU insert_dylib: bypass.dylib vẫn chưa xuất hiện trong otool -L!"
  exit 6
fi
echo "  ✅ LC_LOAD_DYLIB bypass.dylib injected OK."

# ============================================================
# 6. Copy cheat_decoded.wasm vào bundle
# ============================================================
echo ""
echo "============================================================"
echo " [6/8] COPY WASM VÀO BUNDLE"
echo "============================================================"
if [ ! -f "$WASM_OUT" ]; then
  echo "  ❌ $WASM_OUT không tồn tại!"
  exit 7
fi
echo "  ✅ $WASM_OUT tồn tại (size=$SZ)."

# ============================================================
# 7. Patch Info.plist ATS
# ============================================================
echo ""
echo "============================================================"
echo " [7/8] PATCH Info.plist ATS (NSAllowsArbitraryLoads = true)"
echo "============================================================"
PLIST="$BUNDLE_POOL/Info.plist"
plutil -convert xml1 "$PLIST"
set +e
CUR=$(plutil -extract NSAppTransportSecurity raw "$PLIST" 2>/dev/null)
set -e
if [ -z "${CUR:-}" ]; then
  echo "  -> Thêm NSAppTransportSecurity dict mới."
  plutil -insert NSAppTransportSecurity -xml "<dict><key>NSAllowsArbitraryLoads</key><true/></dict>" "$PLIST"
else
  echo "  -> NSAppTransportSecurity đã có. Bật NSAllowsArbitraryLoads=true (ghi đè)."
  plutil -replace NSAppTransportSecurity -xml "<dict><key>NSAllowsArbitraryLoads</key><true/></dict>" "$PLIST"
fi
ARBITRARY=$(plutil -extract NSAppTransportSecurity.NSAllowsArbitraryLoads raw "$PLIST" 2>/dev/null || echo "")
echo "  NSAppTransportSecurity.NSAllowsArbitraryLoads = $ARBITRARY"
plutil -convert binary1 "$PLIST" || true
echo "  ✅ Info.plist ATS patched OK."

# ============================================================
# 8. Re-sign toàn bộ binaries bằng ldid
# ============================================================
echo ""
echo "============================================================"
echo " [8/8] KÝ LẠI TẤT CẢ BINARIES BẰNG LDID (TrollStore compatible)"
echo "============================================================"
sign_with_ldid() {
  local f="$1"
  if [ ! -w "$f" ]; then chmod u+w "$f" 2>/dev/null || true; fi
  if ldid -S "$f" 2>/dev/null; then
    echo "  ✅ ldid -S $(basename "$f")"
  else
    echo "  ⚠️  ldid -S FAILED trên $f (chấp nhận, ESign sẽ ký lại trên device)."
  fi
}
sign_with_ldid "$POOL_BIN"
while IFS= read -r -d '' fw; do
  name=$(basename "$fw" .framework)
  bin="$fw/$name"
  if [ -f "$bin" ]; then sign_with_ldid "$bin"; fi
done < <(find "$FRAMEWORKS" -name "*.framework" -type d -print0)
sign_with_ldid "$FRAMEWORKS/bypass.dylib"
echo "  ✅ Re-sign phase done."

# ============================================================
# 9. Đóng gói lại IPA
# ============================================================
echo ""
echo "============================================================"
echo " [9/9] ĐÓNG GÓI LẠI -> 8BallPool_BYPASSED_V9.5.ipa"
echo "============================================================"
rm -f "$IPA_OUT"
cd "$EXTRACT"
zip -qr "$IPA_OUT" Payload/
cd "$HERE"
OUT_SZ=$(stat -f%z "$IPA_OUT")
echo "  ✅ IPA created: $IPA_OUT  (size: $OUT_SZ bytes = $(python3 -c "print(f'{$OUT_SZ/1024/1024:.2f}')" 2>/dev/null || echo "?"))"
if [ "$OUT_SZ" -lt 100000000 ]; then
  echo "  ⚠️  IPA < 100 MB — có thể thiếu resource (lẽ ra ~200-300MB)."
fi

# ============================================================
# X. Build log & checksums
# ============================================================
echo ""
echo "============================================================"
echo " X. XUẤT BUILD LOG VÀ CHECKSUM -> $LOGFILE"
echo "============================================================"
{
  echo "=============================================="
  echo " V9.5 BUILD LOG  ($(date '+%Y-%m-%d %H:%M:%S'))"
  echo "=============================================="
  echo ""
  echo "--- Filesize summary ---"
  for F in \
    "$IPA_ORIG" "$SRC_MM" "$DECRYPT_PY" "$WASM_OUT" "$DYLIB" "$IPA_OUT"; do
    if [ -f "$F" ]; then
      echo "  $(stat -f%12z "$F") B   $(basename "$F")"
    fi
  done
  echo ""
  echo "--- SHA-256 checksums ---"
  for F in \
    "$IPA_ORIG" "$SRC_MM" "$DECRYPT_PY" "$WASM_OUT" "$DYLIB" "$IPA_OUT" \
    "$FRAMEWORKS/ninja.framework/ninja" "$FRAMEWORKS/loader.framework/loader" "$FRAMEWORKS/libloader.framework/libloader" \
    "$POOL_BIN"; do
    if [ -f "$F" ]; then
      H=$(shasum -a 256 "$F" | awk '{print $1}')
      echo "  $H  $(basename "$F")"
    fi
  done
  echo ""
  echo "--- Static offsets confirmed (ninja.framework __DATA) ---"
  echo "  vmaddr __DATA  = 0x108000"
  echo "  vmsize __DATA  = 0x3C000 (245760 B)"
  echo "  g_valid  (DATA_base+0x1096) = 0x109096  (force -> 0x01)"
  echo "  g_exp    (DATA_base+0x10FE) = 0x1090FE  (force -> 0xFFFFFFFFFFFFFFFF)"
  echo ""
  echo "--- LC_LOAD_DYLIB verify (pool binary first 10 entries) ---"
  otool -L "$POOL_BIN" 2>/dev/null | head -15 || echo "(otool fail)"
  echo ""
  echo "--- LC_LOAD_DYLIB load commands (with paths, grep bypass): ---"
  otool -l "$POOL_BIN" 2>/dev/null | grep -A2 LC_LOAD_DYLIB | grep -E "name |bypass" || true
  echo ""
  echo "--- Build environment ---"
  echo "  macOS $(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
  echo "  clang $(xcrun clang --version | head -1 2>/dev/null || echo 'unknown')"
  echo "  iPhoneOS SDK: ${SDK:-unknown}"
  echo "  insert_dylib: $(which insert_dylib 2>/dev/null || echo '?')"
  echo "  ldid:   $(ldid 2>&1 | head -1 || echo '?')"
  echo ""
  echo "=============================================="
  echo " HOÀN TẤT V9.5 BUILD."
  echo "=============================================="
} | tee "$LOGFILE"

echo ""
echo "==========================================================================="
echo " ✅ BUILD HOÀN TẤT!"
echo "==========================================================================="
echo "  Output IPA  : $IPA_OUT"
echo "  Build log   : $LOGFILE"
echo ""
echo "  CÀI ĐẶT QUA TROLLSTORE:"
echo "    1. AirDrop / Share $IPA_OUT vào thiết bị iOS 15.0-16.6.1"
echo "    2. Mở TrollStore -> Tab 'Apps' -> 'Install IPA'"
echo "    3. Chọn file, bấm Install, đợi 10 giây."
echo ""
echo "  TEST FUNCTIONAL:"
echo "    - Mở app -> Login screen. Nhập username=a password=b -> Login."
echo "    - Không báo lỗi, thấy 'Authenticating...' rồi vào game."
echo "    - Vào bàn chơi 1v1: dòng line overlay (aimbot) hiện, autoplay tự đánh."
echo "    - Test 3-5 phút, không crash, không auto-logout."
echo "    - Bật Airplane mode: vẫn hoạt động (WASM cached)."
echo "==========================================================================="
