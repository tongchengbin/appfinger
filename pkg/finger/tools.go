package finger

import (
	"bytes"
	"encoding/base64"
	"github.com/spaolacci/murmur3"
)

func InsertInto(s string, interval int, sep rune) string {
	var buffer bytes.Buffer
	before := interval - 1
	last := len(s) - 1
	for i, char := range s {
		buffer.WriteRune(char)
		if i%interval == before && i != last {
			buffer.WriteRune(sep)
		}
	}
	buffer.WriteRune(sep)
	return buffer.String()
}
func mmh3(data []byte) int32 {
	hash := murmur3.New32WithSeed(0)
	_, err := hash.Write([]byte(base64Py(data)))
	if err != nil {
		return 0
	}
	return int32(hash.Sum32())
}

func base64Py(data []byte) string {
	// python encodes to base64 with lines of 76 bytes terminated by new line "\n"
	stdBase64 := base64.StdEncoding.EncodeToString(data)
	return InsertInto(stdBase64, 76, '\n')
}
