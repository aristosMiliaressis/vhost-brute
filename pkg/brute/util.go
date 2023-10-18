package brute

import "math/rand"

func RandomString(length int) string {
	var chars = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, length)
	for i := range s {
		s[i] = chars[rand.Intn(len(chars))]
	}
	return string(s)
}

func Contains[T string | int](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
