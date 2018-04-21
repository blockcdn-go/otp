package totp

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/blockcdn-go/otp"
	"github.com/gotoxu/assert"
)

type tc struct {
	TS     int64
	TOTP   string
	Mode   otp.Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []tc{
		{59, "94287082", otp.AlgorithmSHA1, secSha1},
		{59, "46119246", otp.AlgorithmSHA256, secSha256},
		{59, "90693936", otp.AlgorithmSHA512, secSha512},
		{1111111109, "07081804", otp.AlgorithmSHA1, secSha1},
		{1111111109, "68084774", otp.AlgorithmSHA256, secSha256},
		{1111111109, "25091201", otp.AlgorithmSHA512, secSha512},
		{1111111111, "14050471", otp.AlgorithmSHA1, secSha1},
		{1111111111, "67062674", otp.AlgorithmSHA256, secSha256},
		{1111111111, "99943326", otp.AlgorithmSHA512, secSha512},
		{1234567890, "89005924", otp.AlgorithmSHA1, secSha1},
		{1234567890, "91819424", otp.AlgorithmSHA256, secSha256},
		{1234567890, "93441116", otp.AlgorithmSHA512, secSha512},
		{2000000000, "69279037", otp.AlgorithmSHA1, secSha1},
		{2000000000, "90698825", otp.AlgorithmSHA256, secSha256},
		{2000000000, "38618901", otp.AlgorithmSHA512, secSha512},
		{20000000000, "65353130", otp.AlgorithmSHA1, secSha1},
		{20000000000, "77737706", otp.AlgorithmSHA256, secSha256},
		{20000000000, "47863826", otp.AlgorithmSHA512, secSha512},
	}
)

func TestValidate(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Secret, time.Unix(tx.TS, 0).UTC(), Options{
			Digits:    otp.DigitsEight,
			Algorithm: tx.Mode,
		})

		assert.Nil(t, err)
		assert.True(t, valid)
	}
}

func TestGenerateCode(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, time.Unix(tx.TS, 0).UTC(), Options{
			Digits:    otp.DigitsEight,
			Algorithm: tx.Mode,
		})

		assert.Nil(t, err)
		assert.DeepEqual(t, passcode, tx.TOTP)
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
