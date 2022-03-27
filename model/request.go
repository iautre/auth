package model

type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Code      string `json:"code"`
}
