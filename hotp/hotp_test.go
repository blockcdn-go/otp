package hotp

import (
	"encoding/base32"
	"testing"

	"github.com/blockcdn-go/otp"
	"github.com/gotoxu/assert"
)

var secSha1 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

type tc struct {
	Counter uint64
	HOTP    string
	Mode    otp.Algorithm
	Secret  string
}

var rfcMatrixTCs = []tc{
	{0, "755224", otp.AlgorithmSHA1, secSha1},
	{1, "287082", otp.AlgorithmSHA1, secSha1},
	{2, "359152", otp.AlgorithmSHA1, secSha1},
	{3, "969429", otp.AlgorithmSHA1, secSha1},
	{4, "338314", otp.AlgorithmSHA1, secSha1},
	{5, "254676", otp.AlgorithmSHA1, secSha1},
	{6, "287922", otp.AlgorithmSHA1, secSha1},
	{7, "162583", otp.AlgorithmSHA1, secSha1},
	{8, "399871", otp.AlgorithmSHA1, secSha1},
	{9, "520489", otp.AlgorithmSHA1, secSha1},
}

func TestValidate(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.HOTP, tx.Counter, tx.Secret, Options{
			Digits:    otp.DigitsSix,
			Algorithm: tx.Mode,
		})

		assert.Nil(t, err)
		assert.True(t, valid)
	}
}

func TestGenerateCode(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, tx.Counter, Options{
			Digits:    otp.DigitsSix,
			Algorithm: tx.Mode,
		})

		assert.Nil(t, err)
		assert.DeepEqual(t, passcode, tx.HOTP)
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "BlockCDN",
		AccountName: "alice@example.com",
	})

	assert.Nil(t, err)
	assert.DeepEqual(t, k.Issuer(), "BlockCDN")
	assert.DeepEqual(t, k.AccountName(), "alice@example.com")
	assert.Len(t, k.Secret(), 16)
}
