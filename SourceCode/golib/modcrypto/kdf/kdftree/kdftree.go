package kdftree

import (
    "hash"
    "crypto/hmac"
    "encoding/binary"

    "modcrypto/hash/gost/gost34112012256"
)

// KDFTree implements KDF_TREE_GOSTR3411_2012_256 algorithm for r = 1.
// https://tools.ietf.org/html/rfc7836#section-4.5
func KDFTree(secret []byte, label, seed []byte, length int) []byte {
    return Key(gost34112012256.New, secret, label, seed, length)
}

// Key implements KDF_TREE_GOSTR3411_2012_256 algorithm for r = 1.
// https://tools.ietf.org/html/rfc7836#section-4.5
func Key(h func() hash.Hash, secret []byte, label, seed []byte, length int) []byte {
    mdSize := h().Size()

    if length == 0 ||
        length%mdSize != 0 ||
        length > mdSize*(1<<8-1) {
        panic("KDFtree wrong length parameter")
    }

    out := make([]byte, 0, length)

    L := uint16(8 * length)
    Lb := make([]byte, 2)
    binary.BigEndian.PutUint16(Lb, L)

    // The number of iterations, n <= 255
    n := uint8(length / mdSize)

    mac := hmac.New(h, secret)

    for i := uint8(1); i <= n; i++ {
        mac.Reset()
        mac.Write([]byte{i})
        mac.Write(label)
        mac.Write([]byte{0x00})
        mac.Write(seed)
        mac.Write(Lb)

        out = mac.Sum(out)
    }

    return out
}
