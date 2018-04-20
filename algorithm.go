package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Algorithm 表示计算一次性密码时使用的哈希函数
type Algorithm int

// consts
const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}

	panic("unreached")
}

// Hash 返回算法对应的hash.Hash
func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}

	panic("unreached")
}
