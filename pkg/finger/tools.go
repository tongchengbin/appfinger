package finger

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/spaolacci/murmur3"
)

func Mmh3(data []byte) string {
	var h32 = murmur3.New32WithSeed(0)
	_, err := h32.Write(stdBase64(data))
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func stdBase64(bRaw []byte) []byte {
	bd := base64.StdEncoding.EncodeToString(bRaw)
	var buffer bytes.Buffer
	for i := 0; i < len(bd); i++ {
		ch := bd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
