// Sandfly Security Linux Entropy Scanning Utility
package main

/*
This utility will help find packed or encrypted files or processes on a Linux system by calculating the entropy
to see how random they are. Packed or encrypted malware often appears to be a very random executable file and this
utility can help identify potential intrusions.

You can calculate entropy on all files, or limit the search just to Linux ELF executables that have an entropy of
your threshold. Linux processes can be scanned as well automatically.

Sandfly Security produces an agentless endpoint detection and incident response platform (EDR) for Linux. You can
find out more about how it works at: https://www.sandflysecurity.com

MIT License

Copyright (c) 2019-2022 Sandfly Security Ltd.
https://www.sandflysecurity.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Version: 1.1.1
Author: @SandflySecurity
*/

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/panjf2000/ants/v2"
)

const (
	// constVersion Version
	constVersion = "1.2.0"
	// constProcDir default /proc dir for processes.
	constProcDir = "/proc"
	// constDelimeterDefault default delimiter for CSV output.
	constDelimeterDefault = ","
	// constMinPID minimum PID value allowed for process checks.
	constMinPID = 1
	// constMaxPID maximum PID value allowed for process checks. 64bit linux is 2^22. This value is a limiter.
	constMaxPID = 4194304
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
	ErrUnsupportedType = errors.New("unsupported type")
	ErrNilPointer      = errors.New("nil pointer")
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

type Results struct {
	Files
	csvSchema csvSchema
}

func NewResults() *Results {
	return &Results{Files: make(Files, 0), csvSchema: defCSVHeader}
}

func (r *Results) WithDelimiter(delim string) *Results {
	r.csvSchema.delim = delim
	return r
}

func (r *Results) Add(f *File) {
	r.Files = append(r.Files, f)
}

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

type Files []*File

type File struct {
	Path      string     `json:"path"`
	Name      string     `json:"name"`
	Entropy   float64    `json:"entropy"`
	IsELF     bool       `json:"elf"`
	Checksums *Checksums `json:"checksums"`
}

type Checksums struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	SHA512 string `json:"sha512"`
}

type config struct {
	filePath            string
	dirPath             string
	delimChar           string
	entropyMaxVal       float64
	elfOnly             bool
	procOnly            bool
	csvOutput           bool
	jsonOutput          bool
	printInterimResults bool
	outputFile          string
	version             bool
	sumMD5              bool
	sumSHA1             bool
	sumSHA256           bool
	sumSHA512           bool
	results             *Results
	goFast              bool
}

var cfgOnce sync.Once

func newConfigFromFlags() *config {
	cfg := new(config)

	cfgOnce.Do(func() {
		flag.StringVar(&cfg.filePath, "file", "", "full path to a single file to analyze")
		flag.StringVar(&cfg.dirPath, "dir", "", "directory name to analyze")
		flag.StringVar(&cfg.delimChar, "delim", constDelimeterDefault, "delimeter for CSV output")
		flag.StringVar(&cfg.outputFile, "output", "", "output file to write results to (default stdout) (only json and csv formats supported)")

		flag.Float64Var(&cfg.entropyMaxVal, "entropy", 0, "show any file with entropy greater than or equal to this value (0.0 - 8.0 max 8.0, default is 0)")

		flag.BoolVar(&cfg.elfOnly, "elf", false, "only check ELF executables")
		flag.BoolVar(&cfg.procOnly, "proc", false, "check running processes")
		flag.BoolVar(&cfg.csvOutput, "csv", false, "output results in CSV format (filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)")
		flag.BoolVar(&cfg.jsonOutput, "json", false, "output results in JSON format")
		flag.BoolVar(&cfg.printInterimResults, "print", false, "print interim results to stdout even if output file is specified")
		flag.BoolVar(&cfg.version, "version", false, "show version and exit")
		flag.BoolVar(&cfg.sumMD5, "md5", true, "calculate and show MD5 checksum of file(s)")
		flag.BoolVar(&cfg.sumSHA1, "sha1", true, "calculate and show SHA1 checksum of file(s)")
		flag.BoolVar(&cfg.sumSHA256, "sha256", true, "calculate and show SHA256 checksum of file(s)")
		flag.BoolVar(&cfg.sumSHA512, "sha512", true, "calculate and show SHA512 checksum of file(s)")

		flag.BoolVar(&cfg.goFast, "fast", false, "use worker pool for concurrent file processing (experimental)")

		flag.Parse()
	})

	switch {
	case cfg.version:
		fmt.Printf("sandfly-entropyscan Version %s\n", constVersion)
		fmt.Printf("Copyright (c) 2019-2022 Sandlfy Security - www.sandflysecurity.com\n\n")
		os.Exit(0)
	case cfg.entropyMaxVal > 8:
		log.Fatal("max entropy value is 8.0")
	case cfg.entropyMaxVal < 0:
		log.Fatal("min entropy value is 0.0")
	default:
		// proceed
	}

	return cfg
}

func main() {
	cfg := newConfigFromFlags()

	if cfg.csvOutput || cfg.jsonOutput {
		cfg.results = NewResults()
		if cfg.delimChar != constDelimeterDefault {
			cfg.results = cfg.results.WithDelimiter(cfg.delimChar)
		}
	}

	if !cfg.csvOutput && !cfg.jsonOutput {
		cfg.printInterimResults = true
	}

	if cfg.csvOutput && cfg.jsonOutput {
		log.Fatal("csv and json output options are mutually exclusive")
	}

	defer func() {
		var res []byte
		switch {
		case cfg.csvOutput:
			var err error
			if res, err = cfg.results.MarshalCSV(); err != nil {
				log.Fatal(err.Error())
			}
		case cfg.jsonOutput:
			var err error
			if res, err = json.Marshal(cfg.results); err != nil {
				log.Fatal(err.Error())
			}
		default:
		}
		if len(res) > 0 {
			switch {
			case cfg.outputFile != "":
				if err := os.WriteFile(cfg.outputFile, res, 0644); err != nil {
					log.Fatal(err.Error())
				}
			default:
				_, _ = os.Stdout.Write(res)
			}
		}
	}()

	switch {
	case cfg.procOnly:
		if runtime.GOOS == "windows" {
			log.Fatalf("process checking option is not supported on Windows")
		}
		if os.Geteuid() != 0 {
			log.Fatalf("process checking option requires UID/EUID 0 (root) to run")
		}

		results := NewResults()

		// TODO: D.R.Y myself off, not to mention fix the reflection `onOff` mess

		myPID := os.Getpid()

		synchronous := func(pid int) {
			if pid == myPID {
				return
			}
			procfsTarget := filepath.Join(constProcDir, strconv.Itoa(pid), "/exe")
			// Only check elf files which should be all these will be anyway.
			file, err := cfg.checkFilePath(procfsTarget)
			// anything that is not an error is a valid /proc/*/exe link we could see and process. We will analyze it.
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil {
				log.Printf("(!) could not read /proc/%d/exe: %s", pid, err)
				return
			}
			if (file.Entropy < cfg.entropyMaxVal) || (!file.IsELF && cfg.elfOnly) {
				return
			}
			results.Add(file)
			cfg.printResults(file)
		}

		hedgehog := func() {
			wg := new(sync.WaitGroup)
			wg.Add(constMaxPID - constMinPID)

			workers, _ := ants.NewPool(runtime.NumCPU())
			printSync := &sync.Mutex{}

			for pid := constMinPID; pid < constMaxPID; pid++ {
				if pid == myPID {
					continue
				}
				_ = workers.Submit(func() {
					defer wg.Done()
					procfsTarget := filepath.Join(constProcDir, strconv.Itoa(pid), "/exe")
					// Only check elf files which should be all these will be anyway.
					file, err := cfg.checkFilePath(procfsTarget)
					// anything that is not an error is a valid /proc/*/exe link we could see and process. We will analyze it.
					if errors.Is(err, os.ErrNotExist) {
						return
					}
					if err != nil {
						printSync.Lock()
						log.Printf("(!) could not read /proc/%d/exe: %s", pid, err)
						printSync.Unlock()
						return
					}
					if (file.Entropy < cfg.entropyMaxVal) || (!file.IsELF && cfg.elfOnly) {
						return
					}

					printSync.Lock()
					results.Add(file)
					cfg.printResults(file)
					printSync.Unlock()
				})
			}

			wg.Wait()
		}

		switch cfg.goFast {
		case true:
			fmt.Println("gotta go fast!")
			hedgehog()
		case false:
			for pid := constMinPID; pid < constMaxPID; pid++ {
				synchronous(pid)
			}
		}
	case cfg.filePath != "":
		fileInfo, err := cfg.checkFilePath(cfg.filePath)
		if err != nil {
			log.Fatalf("error processing file (%s): %v\n", cfg.filePath, err)
		}
		if fileInfo.Entropy >= cfg.entropyMaxVal {
			cfg.printResults(fileInfo)
		}
	case cfg.dirPath != "":
		var search = func(filePath string, info os.FileInfo, err error) error {
			dir, _ := filepath.Split(filePath)
			if err != nil {
				return fmt.Errorf("error walking directory (%s): %v\n", dir, err)
			}
			// If info comes back as nil we don't want to read it or we panic.
			if info == nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			// Only check regular files. Checking devices, etc. won't work.
			if !info.Mode().IsRegular() {
				return nil
			}
			fileInfo, err := cfg.checkFilePath(filePath)
			if err != nil {
				return fmt.Errorf("error processing file (%s): %v\n", filePath, err)
			}

			if fileInfo.Entropy >= cfg.entropyMaxVal {
				cfg.printResults(fileInfo)
			}

			return nil
		}
		err := filepath.Walk(cfg.dirPath, search)
		if err != nil {
			log.Fatalf("error walking directory (%s): %v\n", cfg.dirPath, err)
		}
	}
}

func (cfg *config) printResults(file *File) {
	switch {
	case (cfg.csvOutput || cfg.jsonOutput) && cfg.outputFile == "":
		cfg.results.Add(file)
	case (cfg.csvOutput || cfg.jsonOutput) && cfg.outputFile != "":
		cfg.results.Add(file)
		fallthrough
	case cfg.printInterimResults:
		format := "filename: %s\npath: %s\nentropy: %.2f\nelf: %v\n"
		str := fmt.Sprintf(format,
			file.Name,
			file.Path,
			file.Entropy,
			file.IsELF,
		)
		if cfg.sumMD5 {
			str += "md5: " + file.Checksums.MD5 + "\n"
		}
		if cfg.sumSHA1 {
			str += "sha1: " + file.Checksums.SHA1 + "\n"
		}
		if cfg.sumSHA256 {
			str += "sha256: " + file.Checksums.SHA256 + "\n"
		}
		if cfg.sumSHA512 {
			str += "sha512: " + file.Checksums.SHA512 + "\n"
		}
		fmt.Print(str + "\n")
	}
}

type hasher struct {
	enabled bool
	target  *string
	f       func(string) (string, error)
}

func (h hasher) sum(file *File) error {
	if !h.enabled {
		return nil
	}
	var res string
	var err error
	if res, err = h.f(file.Path); err == nil {
		*h.target = res
	}
	if err != nil {
		return fmt.Errorf("error calculating checksum for file (%s): %w", file.Path, err)
	}
	return nil
}

func (cfg *config) runEnabledHashers(file *File) error {
	wg := new(sync.WaitGroup)

	if file.Checksums == nil {
		file.Checksums = new(Checksums)
	}

	do := []hasher{
		{cfg.sumMD5, &file.Checksums.MD5, HashMD5},
		{cfg.sumSHA1, &file.Checksums.SHA1, HashSHA1},
		{cfg.sumSHA256, &file.Checksums.SHA256, HashSHA256},
		{cfg.sumSHA512, &file.Checksums.SHA512, HashSHA512},
	}
	wg.Add(len(do))
	var errs = make(chan error, len(do))
	for _, v := range do {
		go func(chk hasher, fi *File, vwg *sync.WaitGroup) {
			errs <- chk.sum(fi)
			vwg.Done()
		}(v, file, wg)
	}
	wg.Wait()
	close(errs)
	var errsSlice = make([]error, 0, len(do))
	for e := range errs {
		if e != nil {
			errsSlice = append(errsSlice, e)
		}
	}
	return errors.Join(errsSlice...)
}

func (cfg *config) checkFilePath(filePath string) (file *File, err error) {
	file = new(File)
	file.Checksums = new(Checksums)

	file.Path = filePath

	if file.IsELF, err = IsElfType(filePath); err != nil {
		return file, err
	}

	// handle procfs links
	if _, file.Name = filepath.Split(filePath); file.Name == "exe" {
		if file.Name, err = os.Readlink(filePath); err != nil {
			log.Printf("(!) could not read link (%s): %s\n", filePath, err)
			file.Name = "unknown"
		} else {
			file.Name = filepath.Base(file.Name)
		}
	}

	switch {
	case cfg.elfOnly && !file.IsELF:
		return &File{}, nil
	case !cfg.elfOnly || (cfg.elfOnly && file.IsELF):
		var entropy float64
		if entropy, err = Entropy(filePath); err != nil {
			log.Fatalf("error calculating entropy for file (%s): %v\n", filePath, err)
		}
		file.Entropy = entropy
	}

	if file.Entropy < cfg.entropyMaxVal {
		return file, nil
	}

	err = cfg.runEnabledHashers(file)

	return file, err
}
