package rule

import "crypto/tls"

type Banner struct {
	Uri         string               `json:"uri"`
	BodyHash    int32                `json:"body_hash"`
	Body        string               `json:"body"`
	Header      string               `json:"header"`
	Headers     map[string]string    `json:"-"`
	Title       string               `json:"title"`
	StatusCode  int                  `json:"status_code"`
	Response    string               `json:"_"`
	SSL         bool                 `json:"ssl"`
	Certificate string               `json:"certificate"`
	IconHash    int32                `json:"icon_hash"`
	IconType    string               `json:"icon_type"`
	Charset     string               `json:"-"`
	Cert        *tls.ConnectionState `json:"-"`
	IconURI     string               `json:"icon_uri"`
	IconBytes   []byte               `json:"-"`
}
