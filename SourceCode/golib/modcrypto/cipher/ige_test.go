package cipher

import (
    "testing"
    "crypto/aes"

    cryptobin_test "modcrypto/tool/test"
)

func Test_IGE(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := []byte("kkinjkijeel22plo")
    iv := []byte("11injkijkol22plo11injkijkol22plo")
    plaintext := []byte("kjinjkijkolkdplo")

    c, err := aes.NewCipher(key)
    assertError(err, "NewIGEEncrypter")

    mode := NewIGEEncrypter(c, iv)
    ciphertext := make([]byte, len(plaintext))
    mode.CryptBlocks(ciphertext, plaintext)

    mode2 := NewIGEDecrypter(c, iv)
    plaintext2 := make([]byte, len(ciphertext))
    mode2.CryptBlocks(plaintext2, ciphertext)

    assertNotEmpty(plaintext2, "NewIGEEncrypter")

    assertEqual(plaintext2, plaintext, "NewIGEEncrypter-Equal")
}
