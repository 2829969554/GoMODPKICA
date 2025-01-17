package cipher

import (
    "testing"
    "crypto/aes"

    cryptobin_test "modcrypto/tool/test"
)

func Test_OFBNLF(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    mode := NewOFBNLFEncrypter(aes.NewCipher, key, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewOFBNLFDecrypter(aes.NewCipher, key, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "NewOFBNLF")

    assertEqual(plaintext2, plaintext, "NewOFBNLF-Equal")
}
