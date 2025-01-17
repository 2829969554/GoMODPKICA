package tool

import (
    "errors"
    "testing"

    "modcrypto/tool/test"
)

func Test_Recover(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotErrorNil := test.AssertNotErrorNilT(t)

    err := Recover(func() {
        panic("test panic")
    })

    assertNotErrorNil(err, "Test_Recover-assertNotErrorNil")
    assertEqual(err, errors.New("test panic"), "Test_Recover-assertEqual")
}
