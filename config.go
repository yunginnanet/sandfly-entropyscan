package main

import (
	"flag"
	"fmt"
	"github.com/sandflysecurity/sandfly-entropyscan/pkg/ssh"
	"golang.org/x/term"
	"log"
	"os"
	"sync"
	"time"
)

type sshConfig struct {
	Host              string
	User              string
	Passwd            string
	KeyFile           string
	KeyFilePassphrase string
	Version           string
	Port              int
	Agent             bool
	Prompt            bool
	Verbose           bool
	Trace             bool
	Timeout           time.Duration
}

type outputConfig struct {
	delimChar           string
	csvOutput           bool
	jsonOutput          bool
	printInterimResults bool
	outputFile          string
}

type inputConfig struct {
	filePath string
	dirPath  string

	sshConfig sshConfig

	sshConn *ssh.SSH
}

type config struct {
	entropyMaxVal float64
	elfOnly       bool
	procOnly      bool

	inCfg  inputConfig
	outCfg outputConfig

	hashers []HashType

	version bool

	results *Results

	goFast     bool
	ignoreSelf bool

	printSync sync.Mutex
}

var cfgOnce sync.Once

func (scfg *sshConfig) prompt() {
ploop:
	for {
		switch {
		case scfg.Host == "":
			_, _ = fmt.Printf("Host: ")
			_, _ = fmt.Scanln(&scfg.Host)
		case scfg.User == "":
			_, _ = fmt.Printf("[%s] User: ", scfg.Host)
			_, _ = fmt.Scanln(&scfg.User)
		case scfg.KeyFile != "" && scfg.KeyFilePassphrase == "":
			_, _ = fmt.Printf("[%s] Pass: ", scfg.KeyFile)
			pb, _ := term.ReadPassword(int(os.Stdin.Fd()))
			scfg.KeyFilePassphrase = string(pb)
		case scfg.KeyFile == "" && scfg.Passwd == "":
			_, _ = fmt.Printf("[%s] Pass: ", scfg.Host)
			pb, _ := term.ReadPassword(int(os.Stdin.Fd()))
			scfg.Passwd = string(pb)
		default:
			break ploop
		}
	}
	print("\n")
}

func (cfg *config) parseFlags() {
	sumMD5, sumSHA1, sumSHA256, sumSHA512 := true, true, true, true

	var hashAlgos = map[*bool]HashType{
		&sumMD5:    HashTypeMD5,
		&sumSHA1:   HashTypeSHA1,
		&sumSHA256: HashTypeSHA256,
		&sumSHA512: HashTypeSHA512,
	}

	// ----------------------------------------------------------------------

	// # Strings

	flag.StringVar(&cfg.inCfg.filePath, "file", "", "full path to a single file to analyze")
	flag.StringVar(&cfg.inCfg.dirPath, "dir", "", "directory name to analyze")
	flag.StringVar(&cfg.outCfg.delimChar, "delim", constDelimeterDefault, "delimeter for CSV output")
	flag.StringVar(
		&cfg.outCfg.outputFile, "output", "",
		"output file to write results to (default stdout) (only json and csv formats supported)",
	)

	// ----------------------------------------------------------------------

	// # Floats

	flag.Float64Var(
		&cfg.entropyMaxVal, "entropy", 5.0,
		"show any file with entropy greater than or equal to this value (0.0 - 8.0, max 8.0) (def: 5.0)",
	)

	// ----------------------------------------------------------------------

	// # Bools

	flag.BoolVar(&cfg.elfOnly, "elf", true, "only check ELF executables (def: true)")
	flag.BoolVar(&cfg.procOnly, "proc", false, "check running processes (def: false)")
	flag.BoolVar(
		&cfg.outCfg.csvOutput, "csv", false,
		"output results in CSV format (def: false)\n"+
			"(filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)",
	)
	flag.BoolVar(&cfg.outCfg.jsonOutput, "json", false, "output results in JSON format (def: false)")
	flag.BoolVar(
		&cfg.outCfg.printInterimResults, "print", false,
		"print interim results to stdout even if output file is specified (def: false)",
	)
	flag.BoolVar(&cfg.version, "version", false, "show version and exit (def: false)")
	flag.BoolVar(&sumMD5, "md5", true, "calculate and show MD5 checksum of file(s) (def: true)")
	flag.BoolVar(&sumSHA1, "sha1", true, "calculate and show SHA1 checksum of file(s) (def: true)")
	flag.BoolVar(
		&sumSHA256, "sha256", true,
		"calculate and show SHA256 checksum of file(s) (def: true)",
	)
	flag.BoolVar(
		&sumSHA512, "sha512", true,
		"calculate and show SHA512 checksum of file(s) (def: true)",
	)
	flag.BoolVar(&cfg.ignoreSelf, "ignore-self", true, "ignore self process (def: true)")
	flag.BoolVar(
		&cfg.goFast, "fast", false,
		"use worker pool for concurrent file processing (experimental)",
	)

	// ----------------------------------------------------------------------

	// # SSH

	flag.StringVar(
		&cfg.inCfg.sshConfig.Host, "ssh-host", "", "SSH host to connect to",
	)
	flag.StringVar(
		&cfg.inCfg.sshConfig.User, "ssh-user", "", "SSH user name",
	)
	flag.StringVar(
		&cfg.inCfg.sshConfig.Passwd, "ssh-pass", "", "SSH password",
	)
	flag.StringVar(
		&cfg.inCfg.sshConfig.KeyFile, "ssh-key", "", "SSH private key file",
	)
	flag.StringVar(
		&cfg.inCfg.sshConfig.KeyFilePassphrase,
		"ssh-key-pass", "", "SSH private key passphrase",
	)
	flag.DurationVar(
		&cfg.inCfg.sshConfig.Timeout, "ssh-timeout", 30*time.Second, "SSH connection timeout",
	)
	flag.StringVar(
		&cfg.inCfg.sshConfig.Version, "ssh-version", ssh.DefaultSSHVersion, "SSH version string",
	)
	flag.IntVar(
		&cfg.inCfg.sshConfig.Port, "ssh-port", ssh.DefaultSSHPort, "SSH port",
	)
	flag.BoolVar(
		&cfg.inCfg.sshConfig.Agent, "ssh-agent", false, "use SSH agent",
	)
	flag.BoolVar(
		&cfg.inCfg.sshConfig.Prompt, "ssh-prompt", false,
		"prompt for credentials (def: false)",
	)
	flag.BoolVar(
		&cfg.inCfg.sshConfig.Verbose, "v",
		false, "SSH verbose output (def: false)",
	)
	flag.BoolVar(
		&cfg.inCfg.sshConfig.Trace, "vv",
		false, "SSH trace output (def: false)",
	)

	// ----------------------------------------------------------------------

	flag.Parse()

	for k, v := range hashAlgos {
		if *k {
			cfg.hashers = append(cfg.hashers, v)
		}
	}
}

func newConfigFromFlags() *config {
	cfg := new(config)
	cfg.hashers = make([]HashType, 0, 4)

	cfgOnce.Do(func() { cfg.parseFlags() })

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

	if cfg.inCfg.filePath != "" && cfg.inCfg.dirPath != "" && cfg.inCfg.sshConfig.Host != "" {
		log.Fatal("only one of -file, -dir, or -ssh-host can be specified")
	}

	if cfg.inCfg.sshConfig.Prompt {
		cfg.inCfg.sshConfig.prompt()
	}

	if cfg.inCfg.sshConfig.Host != "" && cfg.inCfg.sshConfig.User == "" {
		log.Fatal("ssh-host requires ssh-user")
	}

	if cfg.inCfg.sshConfig.User != "" && cfg.inCfg.sshConfig.Host == "" {
		log.Fatal("ssh-user requires ssh-host")
	}

	if cfg.inCfg.sshConfig.Host != "" &&
		!cfg.inCfg.sshConfig.Agent &&
		cfg.inCfg.sshConfig.KeyFile == "" &&
		cfg.inCfg.sshConfig.Passwd == "" {

		log.Fatal("ssh mode requires ssh-key, ssh-pass, or ssh-agent")
	}

	return cfg
}
