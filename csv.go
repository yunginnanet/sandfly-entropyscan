package main

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

type csvHeaderStructMapping struct {
	header    string // key in CSV header
	structTag string // borrow JSON struct tag for CSV
}

type csvSchema struct {
	keys  map[int]csvHeaderStructMapping
	delim string
}

func (csv csvSchema) header() []byte {
	var buf = new(bytes.Buffer)
	for i := 0; i < len(csv.keys); i++ {
		_, _ = buf.WriteString(csv.keys[i].header)
		if i < len(csv.keys)-1 {
			_, _ = buf.WriteString(csv.delim)
		}
	}
	return buf.Bytes()
}

var (
	// ErrUnsupportedType is returned when a type is not supported during CSV reflection.
	ErrUnsupportedType = errors.New("unsupported type")
	// ErrNilPointer is returned when a pointer is nil during CSV reflection.
	ErrNilPointer = errors.New("nil pointer")
)

func (csv csvSchema) parse(in any) ([]byte, error) {
	var buf = new(bytes.Buffer)
	write := func(s string) { _, _ = buf.WriteString(s) }
	ref := reflect.ValueOf(in)
	if ref.Kind() == reflect.Ptr && !ref.IsNil() {
		ref = ref.Elem()
	}
	if ref.Kind() == reflect.Ptr && ref.IsNil() {
		return nil, ErrNilPointer
	}

	var finErr error

outerIter:
	for i := 0; i < len(csv.keys); i++ {
		var field = reflect.ValueOf(nil)
	iter:
		for j := 0; j < ref.NumField(); j++ {
			structTag := ref.Type().Field(j).Tag.Get("json")
			target := csv.keys[i].structTag
			if strings.Contains(target, ".") {
				target = strings.Split(target, ".")[0]
			}
			switch structTag {
			case target:
				field = ref.Field(j)
				if field.Kind() == reflect.Ptr && !field.IsNil() {
					field = field.Elem()
				}
				break iter
			default:
			}
		}

		if (field.Kind() == reflect.Pointer || field.Kind() == reflect.Interface) && field.IsNil() {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			write(field.String())
		case reflect.Float64:
			write(strconv.FormatFloat(field.Float(), 'f', 2, 64))
		case reflect.Float32:
			write(strconv.FormatFloat(field.Float(), 'f', 2, 32))
		case reflect.Bool:
			write(strconv.FormatBool(field.Bool()))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			write(strconv.Itoa(int(field.Int())))
		case reflect.Struct:
			targetTag := csv.keys[i].structTag
			if strings.Contains(targetTag, ".") {
				targetTag = strings.Split(targetTag, ".")[1]
			}
			write(field.FieldByName(targetTag).String())
		case reflect.Ptr:
			finErr = ErrUnsupportedType
		default:
			finErr = fmt.Errorf("csv: %w: %s", ErrUnsupportedType, field.Kind().String())
		}

		if i < len(csv.keys)-1 {
			write(csv.delim)
		}

		if i == len(csv.keys)-1 {
			write("\n")
		}

		if finErr != nil {
			break outerIter
		}
	}

	return buf.Bytes(), finErr
}

// (filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)
var defCSVHeader = csvSchema{
	keys: map[int]csvHeaderStructMapping{
		0: {"filename", "name"},
		1: {"path", "path"},
		2: {"entropy", "entropy"},
		3: {"elf_file", "elf"},
		4: {"md5", "checksums.MD5"},
		5: {"sha1", "checksums.SHA1"},
		6: {"sha256", "checksums.SHA256"},
		7: {"sha512", "checksums.SHA512"},
	},
	delim: constDelimeterDefault,
}
