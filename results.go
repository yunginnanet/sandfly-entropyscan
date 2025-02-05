package main

import "bytes"

// Results is a struct that holds the results of an entropy scan. It contains a slice of [File] and a [csvSchema].
type Results struct {
	Files
	csvSchema csvSchema
}

// NewResults creates a new [Results] struct with an empty slice of [File] and the default [csvSchema].
func NewResults() *Results {
	return &Results{Files: make(Files, 0), csvSchema: defCSVHeader}
}

// WithDelimiter sets the delimiter for the [Results] struct for purposes of CSV marshalling.
func (r *Results) WithDelimiter(delim string) *Results {
	r.csvSchema.delim = delim
	return r
}

// Add adds a [File] to the [Results] struct.
func (r *Results) Add(f *File) {
	r.Files = append(r.Files, f)
}

// MarshalCSV marshals the [Results] struct to CSV format using the [r.csvSchema].
func (r *Results) MarshalCSV() ([]byte, error) {
	buf := new(bytes.Buffer)
	write := func(data []byte) { _, _ = buf.Write(data) }
	write(r.csvSchema.header())
	write([]byte("\n"))
	for _, file := range r.Files {
		entry, err := r.csvSchema.parse(file)
		if err != nil {
			return nil, err
		}
		write(entry)
	}
	return buf.Bytes(), nil
}
