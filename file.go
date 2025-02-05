package main

// Files is a slice of [File] pointers.
type Files []*File

// File is a struct that encapsulates metadata, checksuhms, and entropy results.
type File struct {
	Path      string     `json:"path"`
	Name      string     `json:"name"`
	Entropy   float64    `json:"entropy"`
	IsELF     bool       `json:"elf"`
	Checksums *Checksums `json:"checksums"`
}
