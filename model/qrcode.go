package model

type Qrcode struct {
	Data []byte `json:"qrcode"`
	Code string `json:"code"`
	Type string `json:"type,omitempty"`
}
