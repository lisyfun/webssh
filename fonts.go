package main

// LocalFont describes an installed font family.
type LocalFont struct {
	Family    string `json:"family"`
	Monospace bool   `json:"monospace"`
}
