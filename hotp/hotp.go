package hotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"math"
	"net/url"
	"strings"

	"github.com/blockcdn-go/otp"
)

// Options 为GenerateCodeCustom函数提供了options
type Options struct {
	// Digits 表示最终计算结果的位数，默认是6位
	Digits otp.Digits
	// Algorithm 表示计算时使用的哈希算法，默认是SHA1
	Algorithm otp.Algorithm
}

// GenerateCode 使用默认配置生成一次性密码
func GenerateCode(secret string, counter uint64) (string, error) {
	return GenerateCodeCustom(secret, counter, Options{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// GenerateCodeCustom 生成一个HOTP密码
func GenerateCodeCustom(secret string, counter uint64, opts Options) (passcode string, err error) {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}

	secret = strings.ToUpper(secret)

	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", otp.ErrValidateSecretInvalidBase32
	}

	buf := make([]byte, 8)
	mac := hmac.New(opts.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)

	mac.Write(buf)
	sum := mac.Sum(nil)

	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) | ((int(sum[offset+1]) & 0xff) << 16) | ((int(sum[offset+2]) & 0xff) << 8) | (int(sum[offset+3]) & 0xff))

	l := opts.Digits.Length()
	mod := int32(value % int64(math.Pow10(l)))

	return opts.Digits.Format(mod), nil
}

// Validate 使用默认配置验证HOTP密码
func Validate(passcode string, counter uint64, secret string) bool {
	rv, _ := ValidateCustom(passcode, counter, secret, Options{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	return rv
}

// ValidateCustom 使用自定义配置验证HOTP密码
func ValidateCustom(passcode string, counter uint64, secret string, opts Options) (bool, error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != opts.Digits.Length() {
		return false, otp.ErrValidateInputInvalidLength
	}

	otpstr, err := GenerateCodeCustom(secret, counter, opts)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otpstr), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}

// GenerateOpts 为Generate()方法提供配置
type GenerateOpts struct {
	Issuer      string
	AccountName string
	SecretSize  uint
	Digits      otp.Digits
	Algorithm   otp.Algorithm
}

// Generate 生产HOTP的密钥
func Generate(opts GenerateOpts) (*otp.Key, error) {
	if opts.Issuer == "" {
		return nil, otp.ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, otp.ErrGenerateMissingAccountName
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 20
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
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     "/" + opts.Issuer + ":" + opts.AccountName,
		RawQuery: v.Encode(),
	}

	return otp.NewKeyFromURL(u.String())
}
