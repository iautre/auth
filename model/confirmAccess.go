package model

type ConfirmAccess struct {
	Auid       uint   `json:"auid,omitempty"`
	Token      string `json:"token,omitempty"`
	State      string `json:"state,omitempty"`
	ClientId   string `json:"client,omitempty"`
	ClientName string `json:"clientName,omitempty"`
}
