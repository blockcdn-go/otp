package otp

import (
	"image"
	"net/url"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

// Key 表示一个HOTP或TOTP的密钥
// 一般用于谷歌验证器
type Key struct {
	orig string
	url  *url.URL
}

// NewKeyFromURL 基于TOTP或HOTP URL创建一个密钥
func NewKeyFromURL(orig string) (*Key, error) {
	s := strings.TrimSpace(orig)
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return &Key{orig: s, url: u}, nil
}

func (k *Key) String() string {
	return k.orig
}

// Image 创建一个二维码图片
func (k *Key) Image(width int, height int) (image.Image, error) {
	b, err := qr.Encode(k.orig, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, width, height)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Type 返回"hotp"或者"totp"
func (k *Key) Type() string {
	return k.url.Host
}

// Issuer 返回发布者
func (k *Key) Issuer() string {
	q := k.url.Query()
	issuer := q.Get("issuer")
	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

// AccountName 返回用户帐号
func (k *Key) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

// Secret 返回密钥中包含的secret
func (k *Key) Secret() string {
	q := k.url.Query()
	return q.Get("secret")
}

// URL 返回OTP的URL字符串
func (k *Key) URL() string {
	return k.url.String()
}
