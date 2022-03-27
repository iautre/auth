package model

// type read write
type Policy struct {
	Type      string      `json:"type"`
	Apps      []*App      `json:"apps"`
	Resources []*Resource `json:"resources"`
}
