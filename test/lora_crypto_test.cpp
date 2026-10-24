// The arithmetic under the LoRa decoders -- src/lora_crypto.cpp -- against
// the published vectors: FIPS-197 for AES, RFC 4493 for CMAC, the SHA-2
// examples, RFC 4231 for HMAC, the CRC check strings, and the two Meshtastic
// numbers this firmware recomputes (the frequency slot and the key). A slip
// in any of these decodes every packet wrongly and never says so.
#include "lora_crypto.h"
#include "test_util.h"
#include <cstring>

using namespace LoraCrypto;

static bool hexIs(const uint8_t* p, size_t n, const char* hex) {
    char buf[130];
    toHex(p, n, buf);
    return strcmp(buf, hex) == 0;
}

int main() {
    suite("AES-128 (FIPS-197 C.1)");
    {
        uint8_t key[16], pt[16], ct[16], back[16];
        fromHex("000102030405060708090a0b0c0d0e0f", key, 16);
        fromHex("00112233445566778899aabbccddeeff", pt, 16);
        Aes128 a; a.setKey(key);
        a.encryptBlock(pt, ct);
        ck("encrypt", hexIs(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));
        a.decryptBlock(ct, back);
        ck("decrypt round trip", memcmp(back, pt, 16) == 0);
    }

    suite("AES-256 (FIPS-197 C.3)");
    {
        uint8_t key[32], pt[16], ct[16];
        fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
        fromHex("00112233445566778899aabbccddeeff", pt, 16);
        Aes256 a; a.setKey(key);
        a.encryptBlock(pt, ct);
        ck("encrypt", hexIs(ct, 16, "8ea2b7ca516745bfeafc49904b496089"));
    }

    suite("AES-256-CCM, 13-byte nonce, 8-byte tag (vector from Python's cryptography)");
    {
        uint8_t key[32], nonce[13], pt[40], ct[40], tag[8], back[40];
        fromHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", key, 32);
        fromHex("a0a1a2a3a4a5a6a7a8a9aaabac", nonce, 13);
        for (int i = 0; i < 40; i++) pt[i] = (uint8_t)i;
        Aes256 a; a.setKey(key);
        ccmSeal(a, nonce, pt, 40, ct, tag);
        ck("ciphertext", hexIs(ct, 40, "c2c7fca38eeb5eea02618589b190c76857839dd71f9f8c3be9a4671a2da393fdfb080d0a79f37c15"));
        ck("tag", hexIs(tag, 8, "531671729d9efa68"));
        ck("opens", ccmOpen(a, nonce, ct, 40, tag, back) && memcmp(back, pt, 40) == 0);
        ct[7] ^= 0x01;
        ck("a flipped bit is refused", !ccmOpen(a, nonce, ct, 40, tag, back));
        ct[7] ^= 0x01; tag[0] ^= 0x80;
        ck("a flipped tag bit is refused", !ccmOpen(a, nonce, ct, 40, tag, back));
        uint8_t inPlace[40]; memcpy(inPlace, pt, 40);
        ccmSeal(a, nonce, inPlace, 40, inPlace, tag);
        ck("sealing in place gives the same bytes", hexIs(inPlace, 40, "c2c7fca38eeb5eea02618589b190c76857839dd71f9f8c3be9a4671a2da393fdfb080d0a79f37c15"));
    }

    suite("X25519 (RFC 7748)");
    {
        uint8_t k[32], u[32], out[32];
        fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
        fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
        ck("section 5.2, first vector", x25519(out, k, u) &&
           hexIs(out, 32, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
        uint8_t ap[32], bp[32], apub[32], bpub[32], s1[32], s2[32];
        fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ap, 32);
        fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bp, 32);
        x25519Base(apub, ap); x25519Base(bpub, bp);
        ck("section 6.1, Alice's public key", hexIs(apub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        ck("section 6.1, Bob's public key",   hexIs(bpub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        ck("section 6.1, the shared secret both ways",
           x25519(s1, ap, bpub) && x25519(s2, bp, apub) && memcmp(s1, s2, 32) == 0 &&
           hexIs(s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
        uint8_t zero[32] = {0};
        ck("a low-order point is refused (all-zero result)", !x25519(out, ap, zero));
    }

    suite("AES-CMAC (RFC 4493)");
    {
        uint8_t key[16], msg[64], mac[16];
        fromHex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        fromHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", msg, 64);
        Aes128 a; a.setKey(key);
        cmac(a, msg, 0, mac);  ck("empty",    hexIs(mac, 16, "bb1d6929e95937287fa37d129b756746"));
        cmac(a, msg, 16, mac); ck("16 bytes", hexIs(mac, 16, "070a16b46b4d4144f79bdd9dd04a287c"));
        cmac(a, msg, 40, mac); ck("40 bytes", hexIs(mac, 16, "dfa66747de9ae63030ca32611497c827"));
        cmac(a, msg, 64, mac); ck("64 bytes", hexIs(mac, 16, "51f0bebf7e3b9d92fc49741779363cfe"));
    }

    suite("SHA-256 and HMAC");
    {
        uint8_t out[32];
        sha256((const uint8_t*)"abc", 3, out);
        ck("sha256(abc)", hexIs(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        sha256((const uint8_t*)"", 0, out);
        ck("sha256(empty)", hexIs(out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        // RFC 4231 case 1 and case 2.
        uint8_t k1[20]; memset(k1, 0x0b, 20);
        hmacSha256(k1, 20, (const uint8_t*)"Hi There", 8, out);
        ck("hmac case 1", hexIs(out, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
        hmacSha256((const uint8_t*)"Jefe", 4, (const uint8_t*)"what do ya want for nothing?", 28, out);
        ck("hmac case 2", hexIs(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    }

    suite("CRCs, djb2, codings");
    {
        const uint8_t* s = (const uint8_t*)"123456789";
        ck("crc32 check string", crc32(s, 9) == 0xCBF43926u);
        ck("crc16 ccitt-false (UKHAS seed)", crc16ccitt(s, 9, 0xFFFF) == 0x29B1);
        ck("crc16 xmodem (beacon seed)", crc16ccitt(s, 9, 0x0000) == 0x31C3);
        // Meshtastic's US LongFast slot: 104 slots of 250 kHz, hash 5381*33...
        ck("djb2(LongFast) % 104 == 19", djb2("LongFast") % 104 == 19);
        uint8_t b[32];
        ck("base64 AQ== is one byte 0x01", fromBase64("AQ==", b, sizeof b) == 1 && b[0] == 0x01);
        ck("base64 MeshCore public key", fromBase64("izOH6cXN6mrJ5e26oRXNcg==", b, sizeof b) == 16 &&
                                          hexIs(b, 16, "8b3387e9c5cdea6ac9e5edbaa115cd72"));
        ck("hex with colons", fromHex("d4:f1:bb:3a", b, sizeof b) == 4 && b[3] == 0x3a);
        ck("hex rejects a bad digit", fromHex("d4g1", b, sizeof b) == 0);
    }

    return report();
}
