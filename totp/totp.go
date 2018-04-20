package totp

import (
	"crypto/rand"
	"encoding/base32"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/blockcdn-go/otp"
	"github.com/blockcdn-go/otp/hotp"
)

// Options 提供了TOTP的配置
type Options struct {
	// Period 表示TOTP的有效时间，单位为秒
	// 默认为30秒
	Period    uint
	Skew      uint
	Digits    otp.Digits
	Algorithm otp.Algorithm
}

// GenerateCode 使用默认配置生成TOTP密码
func GenerateCode(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, Options{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// GenerateCodeCustom 使用自定义配置生成TOTP密码
func GenerateCodeCustom(secret string, t time.Time, opts Options) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}
	counter := uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))
	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.Options{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})

	if err != nil {
		return "", err
	}

	return passcode, nil
}

// Validate 使用默认配置验证TOTP密码
func Validate(passcode string, secret string) bool {
	rv, _ := ValidateCustom(passcode, secret, time.Now().UTC(), Options{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	return rv
}

// ValidateCustom 使用自定义配置验证一个TOTP密码
func ValidateCustom(passcode string, secret string, t time.Time, opts Options) (bool, error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	counters := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	counters = append(counters, uint64(counter))
	for i := 1; i <= int(opts.Skew); i++ {
		counters = append(counters, uint64(counter+int64(i)))
		counters = append(counters, uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		rv, err := hotp.ValidateCustom(passcode, counter, secret, hotp.Options{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if rv {
			return true, nil
		}
	}

	return false, nil
}

// GenerateOpts 为Generate()方法提供配置
type GenerateOpts struct {
	Issuer      string
	AccountName string
	Period      uint
	SecretSize  uint
	Digits      otp.Digits
	Algorithm   otp.Algorithm
}

// Generate 生成TOTP的密钥
func Generate(opts GenerateOpts) (*otp.Key, error) {
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 10
	}

	if opts.Digits == 0 {
		opts.Digits = otp.DigitsSix
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	v := url.Values{}
	secret := make([]byte, opts.SecretSize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}

	v.Set("secret", strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "="))
	v.Set("issuer", opts.Issuer)
	v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: v.Encode(),
	}

	return otp.NewKeyFromURL(u.String())
}
