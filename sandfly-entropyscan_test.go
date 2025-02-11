package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"git.tcp.direct/kayos/common/squish"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var (
	/*
		filename: hello
		path: ./hello
		entropy: 7.28
		elf: true
		sha512: 6493cee41a2eb14446a73c7ad5bcca3f727563ecd0ff50a8581c20813d4b6960ff1d11a3265cbd97a6bc95948e676d805465a8a059fe5698b6bb5e34d7893a4a
		md5: 2eb2551fcf5cee81b0f646b74cab600f
		sha1: 9314ae92b4181697a4dd21034d0253a942034168
		sha256: e3ac3dacd6141d711255a8aaac09b41e68e0b10b8eb836e0c3355e361ff12dfe
	*/
	testELFCompressed     = `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`
	testELF               []byte
	goldenMasterChecksums = map[HashType]string{
		HashTypeMD5:    "2eb2551fcf5cee81b0f646b74cab600f",
		HashTypeSHA1:   "9314ae92b4181697a4dd21034d0253a942034168",
		HashTypeSHA256: "e3ac3dacd6141d711255a8aaac09b41e68e0b10b8eb836e0c3355e361ff12dfe",
		HashTypeSHA512: "6493cee41a2eb14446a73c7ad5bcca3f727563ecd0ff50a8581c20813d4b6960ff1d11a3265cbd97a6bc95948e676d805465a8a059fe5698b6bb5e34d7893a4a",
	}
	goldenMasterIsElf   = true
	goldenMasterEntropy = 7.28
	initOnce            sync.Once
)

func unpackTestELF() {
	initOnce.Do(func() {
		var err error
		unb64 := squish.B64d(testELFCompressed)
		if testELF, err = squish.Gunzip(unb64); err != nil {
			panic(err)
		}
	})
}

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

func TestGoldenMaster(t *testing.T) {
	unpackTestELF()

	t.Run("checksums", func(t *testing.T) {
		hashers := []HashType{HashTypeMD5, HashTypeSHA1, HashTypeSHA256, HashTypeSHA512}
		mh := NewMultiHasher(hashers...)

		var (
			results map[HashType]string
			err     error
		)

		if results, err = mh.Hash(bytes.NewReader(testELF)); err != nil {
			t.Fatalf(err.Error())
		}

		for ht, h := range results {
			if h != goldenMasterChecksums[ht] {
				t.Errorf("bad %s hash; expected '%s' but got '%s'", ht, goldenMasterChecksums[ht], h)
			}
		}
	})

	t.Run("isELF", func(t *testing.T) {
		isELF, err := IsELF(bytes.NewReader(testELF))
		if err != nil {
			t.Fatal(err)
		}
		if isELF != goldenMasterIsElf {
			t.Errorf("bad isELF; expected '%v' but got '%v'", goldenMasterIsElf, isELF)
		}
	})

	t.Run("entropy", func(t *testing.T) {
		entropy, err := Entropy(bytes.NewReader(testELF), int64(len(testELF)))
		if err != nil {
			t.Fatal(err)
		}
		if entropy != goldenMasterEntropy {
			t.Errorf("bad entropy; expected '%f' but got '%f'", goldenMasterEntropy, entropy)
		}
	})
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

	t.Run("all", func(t *testing.T) {
		results := NewResults()

		cfg := newConfigFromFlags()
		cfg.hashers = []HashType{HashTypeMD5, HashTypeSHA1, HashTypeSHA256, HashTypeSHA512}

		if err = cfg.runEnabledHashersOnPath(yeet); err != nil {
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

		t.Run("csv", func(t *testing.T) {
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
		})
	})

	t.Run("some", func(t *testing.T) {
		yeet.Checksums = new(Checksums)
		results := NewResults()

		cfg := newConfigFromFlags()
		cfg.hashers = []HashType{HashTypeMD5, HashTypeSHA1}

		if err = cfg.runEnabledHashersOnPath(yeet); err != nil {
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
			if (i < 2) && strings.TrimSpace(h) == "" {
				t.Errorf("expected %s hash but got empty string", chkName)
			}
			if i > 2 && strings.TrimSpace(h) != "" {
				t.Errorf("expected empty string but got %s", h)
			}
		}

		results.Add(yeet)

		t.Run("csv", func(t *testing.T) {
			expected := []byte("filename,path,entropy,elf_file,md5,sha1,sha256,sha512\n" +
				"yeet," + path + "," + "0.50,false," + yeet.Checksums.MD5 + "," +
				yeet.Checksums.SHA1 + "," + "" + "," +
				"" + "\n",
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
		})
	})
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

	//goland:noinspection GoRedundantConversion
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
	cfg.hashers = []HashType{HashTypeMD5, HashTypeSHA1, HashTypeSHA256, HashTypeSHA512}

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
	t.Run("IsFileElf", func(t *testing.T) {
		isElf, err := IsFileElf("")
		if err == nil {
			t.Errorf("expected error on empty file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on empty file passed, got true")
		}
		if isElf, err = IsFileElf("/dev/nope"); err == nil {
			t.Errorf("expected error on non-existent file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on non-existent file passed, got true")
		}
		if isElf, err = IsFileElf("/dev/null"); err == nil {
			t.Errorf("expected error on non-regular file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on non-regular file passed, got true")
		}
		smallFilePath := filepath.Join(t.TempDir(), "smol")
		if err = os.WriteFile(smallFilePath, []byte{0x05}, 0644); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isElf, err = IsFileElf(smallFilePath); err == nil {
			t.Errorf("expected error on small file passed, got nil")
		}
		if isElf {
			t.Errorf("expected isElf == false on small file passed, got true")
		}

	})
}

func TestIsElf(t *testing.T) {
	IAmElf := runtime.GOOS == "linux"
	myPID := os.Getpid()
	procfsTarget := filepath.Join(constProcDir, strconv.Itoa(myPID), "/exe")
	isElf, err := IsFileElf(procfsTarget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isElf != IAmElf {
		t.Errorf("expected self pid isElf == %t, got %t", IAmElf, isElf)
	}
}
