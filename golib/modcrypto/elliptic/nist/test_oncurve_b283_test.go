package nist

import (
    "testing"

    "github.com/deatil/go-cryptobin/elliptic/base_elliptic"
)

func Test_IsOnCurve_B283(t *testing.T) {
    testPoint(t, testcase_B283_PKV, B283())
}

// //////////////////////////////////////////////////////////////////////////////////////////////////
// ECDH_B-283_PKV.txt
var testcase_B283_PKV = []testCase{
    {
        Qx:   base_elliptic.HI(`1F8250C0C74BA7F603A92086EA347D59B33E11D8AC8E2C257D18CE89AFE45D157C07295`),
        Qy:   base_elliptic.HI(`760BD32BE889751DB0704585FE53DDD49B0DB6A457071AA437B07F68C139709AFCD83B4`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`774A0E425212DAD44163090E18D1D5D0370057390A01DD6686759CC2F1AD4180D880A14`),
        Qy:   base_elliptic.HI(`423D25937F28E336CD46A3F012B35DFE8FA00784C279BAF0FA35FFE89AC33F53A2F6E48`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`34993FEE1D671056139175CD043468C4F56FD88230ADDDFD9160F08B724F57FD5EE257A`),
        Qy:   base_elliptic.HI(`5BD977058BFD0151077295C377B05CE2845F4F29E1FE0D402E49F3A42CF1AD21B1B4171`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`29974B06D7698F13074AAE5D279EC75BD18A83F01EDAA945E8D8303A6E20E80AE34F151`),
        Qy:   base_elliptic.HI(`FB07B0B88DE46885B85D755EA570426E8309C1592D96A9C80D91B2F02E126D61356D96`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`7D39D371DC81A34D4A3BBBEC4E6988E4B17C3797E0A624B0F434D1176ED78AC4A866240`),
        Qy:   base_elliptic.HI(`357EEB81140479055DF7EBE247E7C28B6D5229E585CDF357DDDF069F1932B8EB2E04E96`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`18DBE63EBA7CE4B9E1ABD89BE33035EF6013C7BFD50CC710525376DB42F099A325BE6A`),
        Qy:   base_elliptic.HI(`1F0C0638FD2288EA01A94C2A9FCC87671EA9E4A025ED0D74624375F599E227E75C319BB`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`627EE9A884A580354EB42AFE691E0A9DFE8A4AC2A00D3B5BC5DB1F2B71E305155D81638`),
        Qy:   base_elliptic.HI(`462EDC4650EF61CB4CC8D9AE995DF3B462DADCB6C96DBC9BFA733124FFADC390B9A0451`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`1EBC4705DE4EB5475C8F5CD61FF8B98EAB39CD65353CB01609BBBAA912AA2FE1BBD6C5E`),
        Qy:   base_elliptic.HI(`1D59E2FB55AFE671992237B39B55EF056CA57530AED7F6D8EFF549BC37D00F74C66251F`),
        Fail: true,
    },
    {
        Qx:   base_elliptic.HI(`9050576BDC08FFFBBC68215CE73402E4744397CD34011E27BAD262C390D4D5CCE5B401`),
        Qy:   base_elliptic.HI(`5D34D253C8BC0A11CCDDD5FEA915FE735DC799477CD95349AAECC2F00A83B04606E35C`),
        Fail: false,
    },
    {
        Qx:   base_elliptic.HI(`4209CBD5E672F3746261A5D98C06952AA894BE1761267C84BD4DAC2BC269E455A1A1A14`),
        Qy:   base_elliptic.HI(`7BB8B1C56950B7A6ADF1975385E6CD91E0960EB3523690E04A756F37A7B3DD13F568E84`),
        Fail: false,
    },
}
