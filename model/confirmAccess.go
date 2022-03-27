package model

type ConfirmAccess struct {
	Auid       uint   `json:"auid"`
	Token      string `json:"token"`
	State      string `json:"state"`
	ClientId   string `json:"client"`
	ClientName string `json:"clientName"`
}
