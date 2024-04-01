package finger

import (
	"encoding/base64"
	"github.com/spaolacci/murmur3"
	"strings"
)

func mmh3(data []byte) int32 {
	hash := murmur3.New32WithSeed(0)
	_, err := hash.Write([]byte(base64Py(data)))
	if err != nil {
		return 0
	}
	return int32(hash.Sum32())
}

func base64Py(data []byte) string {
	// Python encodes to base64 with lines of 76 bytes terminated by new line "\n"
	stdBase64 := base64.StdEncoding.EncodeToString(data)

	// 将编码后的结果拆分成多行，每行 76 个字符
	var buf strings.Builder
	for i := 0; i < len(stdBase64); i += 76 {
		end := i + 76
		if end > len(stdBase64) {
			end = len(stdBase64)
		}
		buf.WriteString(stdBase64[i:end])
		buf.WriteByte('\n')
	}

	return buf.String()
}
