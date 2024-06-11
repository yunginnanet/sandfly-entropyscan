package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCsvSchemaHeader(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	expected := []byte("filename,path")
	result := csv.header()

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("expected %s but got %s", string(expected), string(result))
	}
}

func TestResultChecksums(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "yeet")
	if err != nil {
		t.Errorf("\n\nunexpected error:\n %v", err)
	}
	if _, err = f.WriteString("yeeterson mcgee"); err != nil {
		t.Errorf("\n\nunexpected error:\n %v", err)
	}
	path := f.Name()
	if err = f.Close(); err != nil {
		t.Errorf("\n\nunexpected error:\n %v", err)
	}

	yeet := &File{
		Path:      path,
		Name:      "yeet",
		Entropy:   0.5,
		IsELF:     false,
		Checksums: new(Checksums),
	}

	results := NewResults()

	cfg := newConfigFromFlags()
	cfg.sumMD5 = true
	cfg.sumSHA1 = true
	cfg.sumSHA256 = true
	cfg.sumSHA512 = true
	if err = cfg.runEnabledHashers(yeet); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, h := range []string{yeet.Checksums.MD5, yeet.Checksums.SHA1, yeet.Checksums.SHA256, yeet.Checksums.SHA512} {
		chkName := "md5"
		switch i {
		case 1:
			chkName = "sha1"
		case 2:
			chkName = "sha256"
		case 3:
			chkName = "sha512"
		}
		if strings.TrimSpace(h) == "" {
			t.Errorf("expected %s hash but got empty string", chkName)
		}
		t.Logf("%s: %s", chkName, h)
	}

	results.Add(yeet)

	expected := []byte("filename,path,entropy,elf_file,md5,sha1,sha256,sha512\n" +
		"yeet," + path + "," + "0.50,false," + yeet.Checksums.MD5 + "," +
		yeet.Checksums.SHA1 + "," + yeet.Checksums.SHA256 + "," +
		yeet.Checksums.SHA512 + "\n",
	)

	result, err := results.MarshalCSV()

	if err != nil {
		t.Errorf("\n\nunexpected error:\n %v", err)
	}

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("\n\nexpected:\n"+
			"%s \n"+
			"got: \n"+
			"%s\n\n",
			string(expected),
			string(result),
		)
	}
}

func TestResultsCustomSchema(t *testing.T) {
	results := NewResults()
	results.Add(&File{
		Path:      "test/path",
		Name:      "testfile",
		Checksums: new(Checksums),
	})
	results.csvSchema = csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ";",
	}

	expected := []byte("filename;path\n" +
		"testfile;test/path\n")
	result, err := results.MarshalCSV()

	if err != nil {
		t.Errorf("\n\nunexpected error:\n %v", err)
	}

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("\n\nexpected:\n"+
			"%s \n"+
			"got: \n"+
			"%s\n\n", string(expected), string(result))
	}
}

func TestResultsAdd(t *testing.T) {
	results := NewResults()
	results.Add(&File{
		Path:      "test/path",
		Name:      "testfile",
		Checksums: new(Checksums),
	})

	if len(results.Files) != 1 {
		t.Errorf("expected length of 1 but got %d", len(results.Files))
	}
}

func TestParseHappyPath(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	in := File{
		Path: "test/path",
		Name: "testfile",
	}

	expected := []byte("testfile,test/path\n")
	result, err := csv.parse(in)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("Expected %s but got %s", string(expected), string(result))
	}
}

func TestParseUnsupportedType(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	in := struct {
		Path complex128
		Name string
	}{
		Path: complex128(1 + 2i),
		Name: "testfile",
	}

	_, err := csv.parse(in)

	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Expected ErrRecheck but got %v", err)
	}
}

func TestParseInlineStruct(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	in := struct {
		Yeeterson string `json:"path"`
		Mcgee     string `json:"name"`
	}{
		Yeeterson: "test/path",
		Mcgee:     "testfile",
	}

	expected := []byte("testfile,test/path\n")
	result, err := csv.parse(in)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("Expected %s but got %s", string(expected), string(result))
	}
}

func TestParseNilPointer(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	var in *File = nil

	_, err := csv.parse(in)

	if !errors.Is(err, ErrNilPointer) {
		t.Errorf("Expected ErrNilPointer but got %v", err)
	}
}

func TestParseNonNilPointer(t *testing.T) {
	csv := csvSchema{
		keys: map[int]csvHeaderStructMapping{
			0: {"filename", "name"},
			1: {"path", "path"},
		},
		delim: ",",
	}

	in := &File{
		Path: "test/path",
		Name: "testfile",
	}

	expected := []byte("testfile,test/path\n")
	result, err := csv.parse(in)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !strings.EqualFold(string(result), string(expected)) {
		t.Errorf("Expected %s but got %s", string(expected), string(result))
	}
}

func TestJSONCSVParityAndCheckOwnPID(t *testing.T) {
	csv := defCSVHeader
	cfg := newConfigFromFlags()
	cfg.sumMD5 = true
	cfg.sumSHA1 = true
	cfg.sumSHA256 = true
	cfg.sumSHA512 = true

	myPID := os.Getpid()
	procfsTarget := filepath.Join(constProcDir, strconv.Itoa(myPID), "/exe")
	file, err := cfg.checkFilePath(procfsTarget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var jDat []byte

	if jDat, err = json.Marshal(file); err != nil {
		t.Fatalf("unexpected json error: %v", err)
	}

	t.Logf("my PID json data: \n %s", string(jDat))

	expected := [][]byte{
		[]byte("filename,path,entropy,elf_file,md5,sha1,sha256,sha512\n"),
		[]byte(file.Name + "," + file.Path + "," + strconv.FormatFloat(file.Entropy, 'f', 2, 64) + "," +
			strconv.FormatBool(file.IsELF) + "," + file.Checksums.MD5 + "," + file.Checksums.SHA1 + "," +
			file.Checksums.SHA256 + "," + file.Checksums.SHA512 + "\n"),
	}

	result, err := csv.parse(file)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.EqualFold(string(result), string(expected[1])) {
		t.Errorf("Expected %s but got %s", string(expected[1]), string(result))
	}

	results := NewResults()
	results.Add(file)

	result, err = results.MarshalCSV()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedJoined := bytes.Join(expected, []byte(""))

	if !strings.EqualFold(string(result), string(expectedJoined)) {
		t.Errorf("Expected %s but got %s", string(expectedJoined), string(result))
	}
}

func TestErroneous(t *testing.T) {
	t.Run("IsElfType", func(t *testing.T) {
		isElf, err := IsElfType("")
		if err == nil {
			t.Errorf("expected error on empty file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on empty file passed, got true")
		}
		if isElf, err = IsElfType("/dev/nope"); err == nil {
			t.Errorf("expected error on non-existent file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on non-existent file passed, got true")
		}
		if isElf, err = IsElfType("/dev/null"); err == nil {
			t.Errorf("expected error on non-regular file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on non-regular file passed, got true")
		}
		smallFilePath := filepath.Join(t.TempDir(), "smol")
		if err = os.WriteFile(smallFilePath, []byte{0x05}, 0644); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isElf, err = IsElfType(smallFilePath); err == nil {
			t.Errorf("expected error on small file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on small file passed, got true")
		}

	})
}
