package main

import (
	"github.com/aristosMiliaressis/vhost-brute/internal/brute"
	"github.com/aristosMiliaressis/vhost-brute/internal/input"
	"github.com/projectdiscovery/gologger"
)

func main() {
	conf, err := input.ParseCliFlags()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	scnr := brute.NewScanner(conf)

	scnr.Scan()
}
