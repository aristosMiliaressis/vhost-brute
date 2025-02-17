package brute

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
)

func RandomString(length int) string {
	var chars = []rune("abcdefghijklmnopqrstuvwxyz")
	s := make([]rune, length)
	for i := range s {
		s[i] = chars[rand.Intn(len(chars))]
	}
	return string(s)
}

func StripParamas(url string) string {
	return strings.Split(strings.Split(url, "?")[0], "#")[0]
}

func Contains[T string | int](s []T, e T) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func StoreResponse(response *http.Response, baseDir string) {
	if baseDir != "" {
		err := os.MkdirAll(baseDir, 0750)
		if err != nil {
			if !os.IsExist(err) {
				gologger.Error().Msgf("Error while storing response: %s", err.Error())
				return
			}
		}
	}

	fileName := fmt.Sprintf("%s_%s.%s.txt", response.Request.URL.Hostname(), response.Request.URL.Port(), response.Request.Host)

	responseText, _ := httputil.DumpResponse(response, true)
	filePath := path.Join(baseDir, fileName)
	err := os.WriteFile(filePath, []byte(responseText), 0640)
	if err != nil {
		gologger.Error().Msgf("Error while storing response: %s", err.Error())
	}
}
