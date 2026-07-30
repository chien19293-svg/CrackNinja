# -*- coding: utf-8 -*-
"""
Giải mã WASM module từ NinjaDeliveryEnvelope (E1 1C FF 10)
Phương pháp:
  env_aes_key[32] = BLAKE2b(g_Ks || kdf_salt || module_id || b"ENV_DATA_V1\x00")
  AES-256-GCM decrypt:
    key   = env_aes_key
    nonce = nonce[12]  (từ header offset 0x08)
    AD    = module_id[16]  (additional authenticated data)
    ciphertext_with_tag = bytes[120 .. file_end]  (cipher || tag theo chuẩn libsodium)
    HOẶC: tag tách rời ở header offset 0x18

  Header offsets CONFIRMED từ hex dump thực của uTPEauDexK34zwVRiCRp:
    magic        @ 0x00 (4B)   = 0x10FF1CE1 (LE: E1 1C FF 10)
    version      @ 0x04 (4B)   = 0x00000001
    nonce[12]    @ 0x08        = {3C,0,0,0, 02,0,0,0, 00,0,0,0}
    cipher_len   @ 0x14 (4B)   = 0 (dùng file_size-120)
    kdf_salt[16] @ 0x20        = {92,3C,CE,F7,E3,AE,3A,A3,09,78,4C,AB,98,A1,C9,0B}
    module_id[16]@ 0x38        = {08,0,0,0,D2,D4,E0,45,94,8A,42,06,66,91,A4,94}
    sha256_exp   @ 0x48 (32B)  = SHA-256 của plaintext WASM
    ciphertext   @ 120 (0x78)  = AES-GCM cipher || 16B tag (libsodium convention)

Mặc định dùng g_Ks = 0x41 * 32 (key fix từ V9.5). Nếu GCM tag fail, cung cấp
g_Ks thật từ runtime bằng argument --ks-hex.

Cách lấy g_Ks thật (trên thiết bị JB hoặc debug server):
  Đặt breakpoint ngay sau AuthSession::handshake() thành công (ninja @0x128F20),
  dump 32 bytes tại g_Ks runtime VM = slide + 0x108000 + 0x0FC9.

Usage:
  python3 decrypt_wasm.py \
    ./ipa_extracted/Payload/pool.app/j1O1pP4cpnaLPxs2xoSf/uTPEauDexK34zwVRiCRp \
    --output cheat_decoded.wasm \
    [--ks-hex XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX]
"""
import os
import sys
import struct
import hashlib
import argparse

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("ERROR: pip install cryptography")
    sys.exit(1)


def blake2b_hash(data: bytes, digest_size: int = 32) -> bytes:
    """Wrapper có thể thay bằng libsodium native nếu cần"""
    h = hashlib.blake2b(data, digest_size=digest_size)
    return h.digest()


def derive_env_aes_key(g_Ks: bytes, kdf_salt: bytes, module_id: bytes) -> bytes:
    """env_aes_key = BLAKE2b(g_Ks || kdf_salt || module_id || b"ENV_DATA_V1\x00")"""
    info = b"ENV_DATA_V1" + b"\x00"
    material = g_Ks + kdf_salt + module_id + info
    return blake2b_hash(material, digest_size=32)


def parse_header(data: bytes):
    """Parse NinjaDeliveryEnvelope header 120 bytes
    Structure CONFIRMED từ hex dump thực của uTPEauDexK34zwVRiCRp:
      [0x00] magic        = 0x10FF1CE1 (LE)
      [0x04] version      = u32
      [0x08] nonce[12]    = AES-GCM nonce
      [0x14] cipher_len   = u32 (thường =0, dùng file_size - 120)
      [0x18] reserved_u64 = u32 + u32 (placeholder)
      [0x20] kdf_salt[16] = BLAKE2b KDF salt (CONFIRMED: 923CCEF7E3AE3AA309784CAB98A1C90B)
      [0x30] u32_pair     = 0x00000003, 0x00000004 (struct metadata)
      [0x38] module_id[16]= CONFIRMED {08,0,0,0,D2,D4,E0,45,94,8A,42,06,66,91,A4,94}
      [0x48] sha256_plain[32] = SHA-256 expected của plaintext sau decrypt
      [0x68] reserved[8]
      [0x70] reserved[8]
      [0x78] (120)        = bắt đầu ciphertext (ciphertext || 16B GCM tag)
    """
    assert len(data) >= 120, f"File quá nhỏ: {len(data)} < 120"

    magic, ver = struct.unpack_from("<II", data, 0)
    assert magic == 0x10FF1CE1, f"Magic sai: 0x{magic:08X}, expected 0x10FF1CE1 (E1 1C FF 10)"

    nonce      = data[0x08 : 0x08 + 12]
    kdf_salt   = data[0x20 : 0x20 + 16]
    module_id  = data[0x38 : 0x38 + 16]
    sha256_exp = data[0x48 : 0x48 + 32]

    cipher_len_hdr = struct.unpack_from("<I", data, 0x14)[0]
    actual_cipher_len = len(data) - 120

    print("=" * 70)
    print("  HEADER NinjaDeliveryEnvelope")
    print("=" * 70)
    print(f"  [0x00] magic        = 0x{magic:08X}  ({'OK' if magic == 0x10FF1CE1 else 'FAIL'})")
    print(f"  [0x04] version      = {ver}")
    print(f"  [0x08] nonce[12]    = {nonce.hex()}")
    print(f"  [0x14] cipher_len   = {cipher_len_hdr}  (actual file-120 = {actual_cipher_len})")
    print(f"  [0x20] kdf_salt[16] = {kdf_salt.hex()}")
    print(f"  [0x38] module_id[16]= {module_id.hex()}")
    mod_uuid = "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" % struct.unpack_from(">IHH8B", module_id, 0)
    print(f"                     (UUID: {mod_uuid})")
    expected_modid = bytes.fromhex("08000000D2D4E045948A42066691A494")
    match = (module_id == expected_modid)
    print(f"                     (V9.5 expected match: {'OK' if match else '!! DIFF'})")
    print(f"  [0x48] sha256_exp   = {sha256_exp.hex()}")
    print(f"  [0x78] cipher_start = actual {actual_cipher_len} bytes")
    print("=" * 70)

    return dict(
        ver=ver, nonce=nonce, kdf_salt=kdf_salt, module_id=module_id,
        sha256_exp=sha256_exp,
        cipher_len_hdr=cipher_len_hdr,
        actual_cipher_len=actual_cipher_len,
        cipher_with_possible_tag=data[120:],  # cipher + tag (libsodium: tag cuối)
    )


def decrypt_env(input_path: str, output_path: str, g_Ks: bytes):
    with open(input_path, "rb") as f:
        data = f.read()

    sz = len(data)
    print(f"\n[*] Input : {input_path}")
    print(f"[*] Size  : {sz:,} bytes ({sz/1024/1024:.2f} MB)")

    hdr = parse_header(data)

    env_key = derive_env_aes_key(g_Ks, hdr["kdf_salt"], hdr["module_id"])
    print(f"\n[+] env_aes_key (BLAKE2b KDF) = {env_key.hex()}")

    aesgcm = AESGCM(env_key)
    cipher_blob = hdr["cipher_with_possible_tag"]
    module_id = hdr["module_id"]
    nonce = hdr["nonce"]

    # Strategy 1: libsodium convention = cipher_text || tag[16] (tag ở cuối)
    plaintext = None
    strategy_used = None
    errors = []

    if len(cipher_blob) > 16:
        try:
            plaintext = aesgcm.decrypt(nonce, cipher_blob, module_id)
            strategy_used = "STRAT1: libsodium convention (cipher || tag@EOF)"
        except InvalidTag as e:
            errors.append(f"STRAT1 fail: {e}")

    # Strategy 2: tách cipher và tag rời rạc. Tag trong data[0x18:0x28] (16 bytes).
    if plaintext is None:
        sep_tag = data[0x18 : 0x18 + 16]
        pure_cipher = cipher_blob  # entire rest = cipher only, no tag appended
        # AES-GCM định dạng tách rời: dùng cipher_blob + tag với associated_data
        # cryptography lib format: ciphertext_with_tag = cipher + tag
        sep_blob = pure_cipher + sep_tag
        try:
            plaintext = aesgcm.decrypt(nonce, sep_blob, module_id)
            strategy_used = f"STRAT2: tag at header[0x18], pure cipher@120"
        except InvalidTag as e:
            errors.append(f"STRAT2 fail: {e}")

    # Strategy 3: AD là nonce + module_id, hoặc không có AD
    if plaintext is None:
        for ad in [b"", module_id, nonce + module_id]:
            for blob in [cipher_blob, data[120:] + data[0x18:0x28]]:
                try:
                    plaintext = aesgcm.decrypt(nonce, blob, ad)
                    strategy_used = f"STRAT3: AD={len(ad)} bytes, blob variant"
                    break
                except InvalidTag:
                    pass
            if plaintext:
                break

    if plaintext is None:
        print("\n" + "=" * 70)
        print("  !!️  AES-GCM DECRYPT FAILED (GCM TAG INVALID)")
        print("=" * 70)
        print("  Nguyên nhân có thể:")
        print("    1. g_Ks không đúng (đang dùng g_Ks = 0x41 * 32 = bypass key)")
        print("    2. nonce/tag/header parse chưa chính xác 100%")
        print("")
        print("  [OK] GIẢI PHÁP:")
        print("    -> Cung cấp g_Ks runtime thật qua:")
        print("         --ks-hex <64 ký tự hex>")
        print("    -> Hoặc trên thiết bị đã JB/debug:")
        print("         breakpoint sau AuthSession::handshake() @ninja 0x128F20")
        print("         dump g_Ks[32] tại VM = 0x108000 + 0x0FC9 + slide")
        print("")
        print("  Errors:")
        for e in errors:
            print(f"    - {e}")
        print("=" * 70)
        sys.exit(2)

    # Verify SHA-256
    sha_actual = hashlib.sha256(plaintext).digest()
    sha_match = (sha_actual == hdr["sha256_exp"])
    print(f"\n[+] Strategy OK: {strategy_used}")
    print(f"[+] Plaintext size : {len(plaintext):,} bytes ({len(plaintext)/1024/1024:.2f} MB)")
    print(f"[+] SHA-256 actual  : {sha_actual.hex()}")
    print(f"[+] SHA-256 expected: {hdr['sha256_exp'].hex()}")
    print(f"[+] SHA-256 match   : {'[OK] YES' if sha_match else '!!️  NO (module có thể OK nếu SHA từ version khác)'}")

    # Kiểm tra WASM magic bytes
    if len(plaintext) >= 8:
        wasm_magic = plaintext[:4]
        print(f"[+] First 8 bytes  : {plaintext[:8].hex()}  (WASM magic: 00 61 73 6D = \\0asm)")
        if wasm_magic == b"\x00asm":
            print(f"[+] [OK] WASM VALID MAGIC BYTES: \\0asm (version {int.from_bytes(plaintext[4:8], 'little')})")
        else:
            print(f"[!] !!️  Không phải WASM magic bytes. Kiểm tra lại g_Ks.")

    with open(output_path, "wb") as f:
        f.write(plaintext)
    print(f"\n[[OK]] Decrypt OK -> {output_path}")
    return output_path


def main():
    ap = argparse.ArgumentParser(description="Decrypt Ninja WASM delivery envelope")
    ap.add_argument("input", help="Path tới file mã hóa (uTPEauDexK34zwVRiCRp)")
    ap.add_argument("--output", "-o", required=True, help="Output WASM file")
    ap.add_argument("--ks-hex", default=None,
                    help="g_Ks 32 bytes dạng hex (64 ký tự). Nếu bỏ qua, dùng 0x41*32 (V9.5 bypass key)")
    ap.add_argument("--ks-bytes", type=lambda x: bytes(x, "utf-8"), default=None,
                    help="g_Ks dạng raw bytes string thay cho hex")
    args = ap.parse_args()

    if args.ks_hex:
        g_Ks = bytes.fromhex(args.ks_hex.strip())
        assert len(g_Ks) == 32, f"g_Ks phải 32 bytes, got {len(g_Ks)}"
    elif args.ks_bytes:
        g_Ks = args.ks_bytes
        if len(g_Ks) < 32:
            g_Ks = g_Ks + b"\x00" * (32 - len(g_Ks))
        g_Ks = g_Ks[:32]
    else:
        g_Ks = b"\x41" * 32
        print("[i] Không có --ks-hex -> dùng g_Ks = 0x41*32 (V9.5 SharedKey32 fix)")

    decrypt_env(args.input, args.output, g_Ks)


if __name__ == "__main__":
    main()

