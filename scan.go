package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/sandflysecurity/sandfly-entropyscan/pkg/ssh"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
)

func (cfg *config) walkFunc(filePath string, info os.FileInfo, err error) error {
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

func (cfg *config) concurrentProcEntropy() {
	wg := new(sync.WaitGroup)

	workers, _ := ants.NewPool(runtime.NumCPU())
	printSync := &sync.Mutex{}

	for pid := constMinPID; pid < constMaxPID; pid++ {
		if pid == os.Getpid() && cfg.ignoreSelf {
			continue
		}
		wg.Add(1)
		_ = workers.Submit(func() {
			// Only check elf files which should be all these will be anyway.
			file, err := cfg.checkFilePath(filepath.Join(constProcDir, strconv.Itoa(pid), "/exe"))
			// anything that is not an error is a valid /proc/*/exe link we could see and process. We will analyze it.
			if errors.Is(err, os.ErrNotExist) {
				wg.Done()
				return
			}

			if err != nil {
				printSync.Lock()
				log.Printf("(!) could not read /proc/%d/exe: %s", pid, err)
				printSync.Unlock()
				wg.Done()
				return
			}

			if (file.Entropy < cfg.entropyMaxVal) || (!file.IsELF && cfg.elfOnly) {
				wg.Done()
				return
			}

			cfg.results.Add(file)

			printSync.Lock()
			cfg.printResults(file)
			printSync.Unlock()

			wg.Done()
		})
	}

	wg.Wait()
}

func (cfg *config) synchronous(pid int) {
	if pid == os.Getpid() {
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

	cfg.results.Add(file)

	cfg.printResults(file)
}

func (cfg *config) checkData(path string, data []byte) (file *File, err error) {
	file = new(File)
	file.Checksums = new(Checksums)

	if file.IsELF, err = IsELF(bytes.NewReader(data)); err != nil {
		return file, err
	}

	if !file.IsELF && cfg.elfOnly {
		return &File{}, nil
	}

	var entropy float64
	var len64 = int64(len(data))

	if entropy, err = Entropy(bytes.NewReader(data), len64); err != nil {
		log.Fatalf("error calculating entropy for file: %v\n", err)
	}

	file.Entropy = entropy

	if file.Entropy < cfg.entropyMaxVal {
		return file, nil
	}

	file.Path = path

	err = cfg.runEnabledHashers(file)

	return file, err
}

func (cfg *config) checkFilePath(filePath string) (file *File, err error) {
	file = new(File)
	file.Checksums = new(Checksums)

	file.Path = filePath

	if file.IsELF, err = IsFileElf(filePath); err != nil {
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
		if entropy, err = FileEntropy(filePath); err != nil {
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

var (
	// ErrNotElf represents an error when a file is not an ELF file.
	ErrNotElf = errors.New("file is not an ELF file")
	// ErrLowEntropy represents an error when a file's entropy is too low.
	ErrLowEntropy = errors.New("file entropy is too low")
)

func (cfg *config) sshPID(pid int) (pidPath string, pidData []byte, err error) {
	if pidPath, pidData, err = cfg.inCfg.sshConn.ReadProc(pid); err != nil {
		err = fmt.Errorf("error reading pid from SSH host (%d)(%s): %w", pid, pidPath, err)
		return
	}

	return
}

func (cfg *config) sshProcess(pid int, pidPath string, pidData []byte) (err error) {
	var file *File

	if file, err = cfg.checkData(pidPath, pidData); err != nil {
		return fmt.Errorf("error processing pid from SSH host (%d)(%s): %w", pid, pidPath, err)
	}

	if file.Entropy < cfg.entropyMaxVal {
		return ErrLowEntropy
	}

	if !file.IsELF && cfg.elfOnly {
		return ErrNotElf
	}

	cfg.results.Add(file)

	cfg.printSync.Lock()
	cfg.printResults(file)
	cfg.printSync.Unlock()

	return nil
}

func (cfg *config) scanSSH(parallel bool) error {
	wg := new(sync.WaitGroup)
	workers, _ := ants.NewPool(runtime.NumCPU())

	var errs = make([]error, 0, constMaxPID-constMinPID)
	errMu := new(sync.Mutex)

	synchronous := func(pid int) {
		pidPath, pidData, err := cfg.sshPID(pid)
		if err != nil {
			errs = append(errs, err)
			return
		}
		perr := cfg.sshProcess(pid, pidPath, pidData)
		if errors.Is(perr, ErrNotElf) || errors.Is(perr, ErrLowEntropy) {
			log.Println(perr.Error())
			return
		}
		errs = append(errs, perr)
	}

	syncWork := func(pid int, pidPath string, pidData []byte) {
		perr := cfg.sshProcess(pid, pidPath, pidData)
		if errors.Is(perr, ErrNotElf) || errors.Is(perr, ErrLowEntropy) {
			log.Println(perr.Error())
			wg.Done()
			return
		}
		errMu.Lock()
		errs = append(errs, perr)
		errMu.Unlock()
		wg.Done()
	}

	concurrent := func(pid int) {
		pidPath, pidData, err := cfg.sshPID(pid)
		if err != nil {
			errMu.Lock()
			errs = append(errs, err)
			errMu.Unlock()
			return
		}

		wg.Add(1)

		_ = workers.Submit(func() { syncWork(pid, pidPath, pidData) })
	}

	for pid := constMinPID; pid < constMaxPID; pid++ {
		switch parallel {
		case false:
			synchronous(pid)
		case true:
			concurrent(pid)
		}
	}

	if parallel {
		wg.Wait()
	}

	errs = append(errs, cfg.inCfg.sshConn.Close())

	return errors.Join(errs...)
}

func (cfg *config) sshInit() {
	cfg.inCfg.sshConn = ssh.NewSSH(cfg.inCfg.sshConfig.Host, cfg.inCfg.sshConfig.User).
		WithPort(cfg.inCfg.sshConfig.Port).WithTimeout(cfg.inCfg.sshConfig.Timeout).
		WithVersion(constVersion)

	if cfg.inCfg.sshConfig.Agent {
		cfg.inCfg.sshConn = cfg.inCfg.sshConn.WithAgent()
	}

	if cfg.inCfg.sshConfig.KeyFile != "" {
		switch {
		case cfg.inCfg.sshConfig.KeyFilePassphrase == "":
			cfg.inCfg.sshConn =
				cfg.inCfg.sshConn.WithKeyFile(cfg.inCfg.sshConfig.KeyFile)
		case cfg.inCfg.sshConfig.KeyFilePassphrase != "":
			cfg.inCfg.sshConn =
				cfg.inCfg.sshConn.WithEncryptedKeyFile(cfg.inCfg.sshConfig.KeyFile, cfg.inCfg.sshConfig.KeyFilePassphrase)
		}
	}

	if cfg.inCfg.sshConfig.Passwd != "" {
		cfg.inCfg.sshConn = cfg.inCfg.sshConn.WithPassword(cfg.inCfg.sshConfig.Passwd)
	}

	if err := cfg.inCfg.sshConn.Connect(); err != nil {
		log.Fatalf("error connecting to SSH host (%s): %v\n", cfg.inCfg.sshConfig.Host, err)
	}
}

func (cfg *config) sshPIDs() error {
	cfg.sshInit()
	return cfg.scanSSH(false)
}

func (cfg *config) concurrentSSHPIDs() error {
	cfg.sshInit()
	return cfg.scanSSH(true)
}
