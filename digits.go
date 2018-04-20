package otp

import (
	"fmt"
)

// Digits 表示最终生成的一次性密码位数
// 6或8位是最常见的
type Digits int

// consts
const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// Format 将一个整数使用0填充为具有d位的字符串
func (d Digits) Format(in int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, in)
}

// Length 返回此数字的字符数
func (d Digits) Length() int {
	return int(d)
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}
