package main

import (
	"github.com/aristosMiliaressis/vhost-brute/pkg/brute"
	"github.com/aristosMiliaressis/vhost-brute/pkg/input"
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
