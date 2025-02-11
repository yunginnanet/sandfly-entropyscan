// Sandfly Security Linux FileEntropy Scanning Utility
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
	"log"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// constVersion Version
	constVersion = "1.3.0"
	// constProcDir default /proc dir for processes.
	constProcDir = "/proc"
	// constDelimeterDefault default delimiter for CSV output.
	constDelimeterDefault = ","
	// constMinPID minimum PID value allowed for process checks.
	constMinPID = 1
	// constMaxPID maximum PID value allowed for process checks. 64bit linux is 2^22. This value is a limiter.
	constMaxPID = 4194304
)

func (cfg *config) run() {
	cfg.results = NewResults()

	switch {

	case cfg.procOnly:
		if runtime.GOOS == "windows" {
			log.Fatalf("process checking option is not supported on Windows")
		}

		if os.Geteuid() != 0 {
			log.Fatalf("process checking option requires UID/EUID 0 (root) to run")
		}

		switch cfg.goFast {
		case true:
			cfg.concurrentProcEntropy()

		case false:
			for pid := constMinPID; pid < constMaxPID; pid++ {
				cfg.synchronous(pid)
			}
		}

	case cfg.inCfg.filePath != "":
		fileInfo, err := cfg.checkFilePath(cfg.inCfg.filePath)
		if err != nil {
			log.Fatalf("error processing file (%s): %v\n", cfg.inCfg.filePath, err)
		}

		if fileInfo.Entropy >= cfg.entropyMaxVal {
			cfg.printResults(fileInfo)
		}

	case cfg.inCfg.dirPath != "":
		if err := filepath.Walk(cfg.inCfg.dirPath, cfg.walkFunc); err != nil {
			log.Fatalf("error walking directory (%s): %v\n", cfg.inCfg.dirPath, err)
		}

	case cfg.inCfg.sshConfig.Host != "":
		if err := cfg.sshPIDs(); err != nil {
			log.Printf("error scanning SSH host: %v\n", err)
		}
	}
}

func main() {
	cfg := newConfigFromFlags()

	if cfg.outCfg.csvOutput || cfg.outCfg.jsonOutput {
		cfg.results = NewResults()
		if cfg.outCfg.delimChar != constDelimeterDefault {
			cfg.results = cfg.results.WithDelimiter(cfg.outCfg.delimChar)
		}
	}

	if !cfg.outCfg.csvOutput && !cfg.outCfg.jsonOutput {
		cfg.outCfg.printInterimResults = true
	}

	if cfg.outCfg.csvOutput && cfg.outCfg.jsonOutput {
		log.Fatal("csv and json output options are mutually exclusive")
	}

	cfg.run()

	cfg.output()

}
