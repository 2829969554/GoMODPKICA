package shacal2

import (
    "bytes"
    "testing"
    "math/rand"
    "encoding/hex"
    "modcrypto/cipher"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Cipher(t *testing.T) {
    random := rand.New(rand.NewSource(99))
    max := 10

    var encrypted [32]byte
    var decrypted [32]byte

    for i := 0; i < max; i++ {
        key := make([]byte, 64)
        random.Read(key)
        value := make([]byte, 32)
        random.Read(value)

        cipher1, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher1.Encrypt(encrypted[:], value)

        if bytes.Equal(encrypted[:], value[:]) {
            t.Errorf("fail: encrypted equal plaintext \n")
        }

        cipher2, err := NewCipher(key)
        if err != nil {
            t.Fatal(err.Error())
        }

        cipher2.Decrypt(decrypted[:], encrypted[:])

        if !bytes.Equal(decrypted[:], value[:]) {
            t.Errorf("encryption/decryption failed: % 02x != % 02x\n", decrypted, value)
        }
    }
}

var cipTests = []struct {
    key    []byte
    plain  []byte
    cipher []byte
}{
    // From Bouncy Castle
    {
        fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        fromHex("98BCC10405AB0BFC686BECECAAD01AC19B452511BCEB9CB094F905C51CA45430"),
        fromHex("00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F"),
    },

    // Tests for short key handling
    {
        fromHex("80000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE"),
    },
    {
        fromHex("8000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE"),
    },

    // From NESSIE submission package via Crypto++
    {
        fromHex("80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("361AB6322FA9E7A7BB23818D839E01BDDAFDF47305426EDD297AEDB9F6202BAE"),
    },
    {
        fromHex("40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("F3BAF53E5301E08813F8BE6F651BB19E9722151FF15063BA42A6FEF7CF3BF3D7"),
    },
    {
        fromHex("20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("E485005217441B60EE5B48EE8AF924B268B6B952D7F593E6102AC83D7DA72838"),
    },
    {
        fromHex("00100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("77CEC8EA64BB7FAE966D030FE4CF318C318DBEBAEB896F31FAA3C9CBA0AE125D"),
    },
    {
        fromHex("00000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
        fromHex("B38604950FA73165F940D4DB527D09CD0B233276CD3808B5CADCCB9FA859AEEB"),
    },
    {
        fromHex("2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C"),
        fromHex("2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C"),
        fromHex("DBF9B56BBF2E50DF321CA687F8BE0E6222E7DF52B4A142174058CC119D9EC0DA"),
    },
    {
        fromHex("2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D"),
        fromHex("2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D2D"),
        fromHex("8B2757374F778FE0B30D11AD7116CE37E2AB858A4E1C50D1115B6E328F3635F5"),
    },
    {
        fromHex("50505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050"),
        fromHex("5050505050505050505050505050505050505050505050505050505050505050"),
        fromHex("BE28CB05EEEEDA8FD8971E9970ECBCA25856F66E95AC8B987C69F04BE3276CD7"),
    },
    {
        fromHex("EFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEF"),
        fromHex("EFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEF"),
        fromHex("5F45E7F72A64C66269F83714A88A0701561C3E7AF33BB48887D4439F5DE4A82D"),
    },
    {
        fromHex("F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8"),
        fromHex("F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8F8"),
        fromHex("B67638D30578AB2319FE275D0B833B50D7ABF01E8760F566D0D441D8EAFDF8AA"),
    },
    {
        fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        fromHex("0598127BAF11706F77402000D730C54A0B84C868A98C6CA4D7F3C0FA06A78B7A"),
    },

    // Randomly generated by Crypto++
    {
        fromHex("67C6697351FF4AEC29CDBAABF2FBE3467CC254F81BE8E78D765A2E63339FC99A"),
        fromHex("66320DB73158A35A255D051758E95ED4ABB2CDC69BB454110E827441213DDC8770E93EA141E1FC673E017E97EADC6B968F385C2AECB03BFB32AF3C54EC18DB5C021AFE43FBFAAA3AFB29D1E6053C7C9475D8BE6189F95CBBA8990F95B1EBF1B305EFF700E9A13AE5CA0BCBD0484764BD1F231EA81C7B64C514735AC55E4B79633B706424119E09DCAAD4ACF21B10AF3B33CDE3504847155CBB6F2219BA9B7DF50BE11A1C7F23F829F8A41B13B5CA4EE8983238E0794D3D34BC5F4E77FACB6C05AC86212BAA1A55A2BE70B5733B045CD33694B3AFE2F0E49E4F321549FD824EA90870D4B28A2954489A0ABCD50E18A844AC5BF38E4CD72D9B0942E506C433AFCDA3847F2DADD47647DE321CEC4AC430F62023856CFBB20704F4EC0BB920BA86C33E05F1ECD96733B79950A3E314D3D934F75EA0F210A8F6059401BEB4BC4478FA4969E623D01ADA696A7E4C7E5125B34884533A94FB319990325744EE9BBCE9E525CF08F5E9E25E5360AAD2B2D085FA54D835E8D466826498D9A8877565705A8A3F62802944DE7CA5894E5759D351ADAC869580EC17E485F18C0C66F17CC07CBB22FCE466DA610B63AF62BC83B4692F3AFFAF271693AC071FB86D11342D8DEF4F89D4B66335C1C7E4248367D8ED9612EC453902D8E50AF89D7709D1A596C1F41F95AA82CA6C49AE90CD1668BAAC7AA6F2B4A8CA99B2C2372ACB08CF61C9C3805E"),
        fromHex("3E60F958F89E79DF1E70ECF03CE6244A71D892D1855833296E4B245FA3CC18F688F97D9E44AF7CD887BB95DB93C34DE08CAC4F6CC5E41E53F7733BFF48C19C12F06B00EA2517D735A5F939B89B908C281B9121A6C1B26CA6C5465FC0BDCD07CA0C9284A9014BF58395875A4BCFFA523131E84F77D288FEFCEE1B4D4229FB0F31075573250C08ED6A5870C6E3779DF375F869401B4C4ABD4407011EA2F5540A7E572AC2EDAD80F94C5D35C322D2C2934F305B2CDB31B6B890595C80464AA5B32721FBB204EF72AC1F11384318D73D3C79D05A9946103416C4881374182E4D569EC2729610D02993D8888985EB4D1334449D5421ED3E9FE81EFDC5B2F28863F8E480CAB18845D48A436FBA35C1A920443ACA8DD4A5F0D88F0E10C87E45409C28654CB5E630F173453AF4D4540AA85DB48A242B779FBCF6F602700EE165AF5D8775DB665CFA858F92F66B471220C117A5A9A3B51F6C7DE5E41C8551ED101930A57FE38D81F36E7457D0F447023C8A09D97E30760AA0317559C5180239C616539164433A10D6DB2D2D69D23B8506E5D6D9B51B7501458F760B8D17B49324A9931D2A6911B75CFB4AADD58AF1928F723E939BEE1048DA8CA8F1FE7749FDDCE1F707AF151BB88431695926FD81F871A0148C63BA2BD7B369D8C797C71FD86D4F5572820204037132A2BED192FBB4D88EDF6FBD12D43D91E8363EF026056E684A8EB9B5"),
    },

}

func Test_Check(t *testing.T) {
    for _, tt := range cipTests {
        c, err := NewCipher(tt.key)
        if err != nil {
            t.Fatal(err)
        }

        b := make([]byte, len(tt.plain))
        cipher.NewECBEncrypter(c).
            CryptBlocks(b[:], tt.plain)
        if !bytes.Equal(b[:], tt.cipher) {
            t.Errorf("encrypt failed: got %x, want %x", b, tt.cipher)
        }

        cipher.NewECBDecrypter(c).
            CryptBlocks(b[:], tt.cipher)
        if !bytes.Equal(b[:], tt.plain) {
            t.Errorf("decrypt failed: got %x, want %x", b, tt.plain)
        }
    }
}
