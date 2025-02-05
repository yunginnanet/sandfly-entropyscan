package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func (cfg *config) printResults(file *File) {
	switch {
	case (cfg.outCfg.csvOutput || cfg.outCfg.jsonOutput) && cfg.outCfg.outputFile == "":
		cfg.results.Add(file)
	case (cfg.outCfg.csvOutput || cfg.outCfg.jsonOutput) && cfg.outCfg.outputFile != "":
		cfg.results.Add(file)
		fallthrough
	case cfg.outCfg.printInterimResults:
		format := "filename: %s\npath: %s\nentropy: %.2f\nelf: %v\n"
		str := fmt.Sprintf(format,
			file.Name,
			file.Path,
			file.Entropy,
			file.IsELF,
		)
		for _, ht := range cfg.hashers {
			str += fmt.Sprintf("%s: %s\n", ht.String(), file.Checksums.Get(ht))
		}
		fmt.Print(str + "\n")
	}
}

func (cfg *config) output() {
	var res []byte
	switch {
	case cfg.outCfg.csvOutput:
		var err error
		if res, err = cfg.results.MarshalCSV(); err != nil {
			log.Fatal(err.Error())
		}
	case cfg.outCfg.jsonOutput:
		var err error
		if res, err = json.Marshal(cfg.results); err != nil {
			log.Fatal(err.Error())
		}
	default:
	}
	if len(res) > 0 {
		switch {
		case cfg.outCfg.outputFile != "":
			if err := os.WriteFile(cfg.outCfg.outputFile, res, 0644); err != nil {
				log.Fatal(err.Error())
			}
		default:
			_, _ = os.Stdout.Write(res)
		}
	}
}
