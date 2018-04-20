package otp

import (
	"errors"
)

// ErrValidateSecretInvalidBase32 在我们尝试将secret从base32字符串转换为原始字节数组时发生错误，就返回该error
var ErrValidateSecretInvalidBase32 = errors.New("Decoding of secret as base32 failed")

// ErrValidateInputInvalidLength 在用户提供了错误的密码长度时，返回该error
var ErrValidateInputInvalidLength = errors.New("Input length unexpected")

// ErrGenerateMissingIssuer 在生成一个密钥时如果未指定issuer，则返回该error
var ErrGenerateMissingIssuer = errors.New("Issuer must be set")

// ErrGenerateMissingAccountName 在生成一个密钥时如果未指定Account Name，则返回该error
var ErrGenerateMissingAccountName = errors.New("AccountName must be set")
