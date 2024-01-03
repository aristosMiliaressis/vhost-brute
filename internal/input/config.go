package input

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const version = "1.0.0"

type Config struct {
	Url       *url.URL
	Hostnames []string

	Silent        bool
	Debug         bool
	OnlyUnindexed bool
	FilterCodes   []int

	Http httpc.ClientOptions
}

func ParseCliFlags(git_hash string) (Config, error) {
	dfltOpts := Config{}
	dfltOpts.Http = httpc.DefaultOptions
	dfltOpts.Http.MaintainCookieJar = false
	dfltOpts.Http.Redirection.FollowRedirects = false
	dfltOpts.Http.Connection.DisableKeepAlives = true
	dfltOpts.Http.ErrorHandling.PercentageThreshold = 80
	dfltOpts.Http.ErrorHandling.HandleErrorCodes = []int{}
	dfltOpts.Http.ErrorHandling.ReverseErrorCodeHandling = true
	var headers goflags.StringSlice
	var hostnameFile string
	var statusCodes string
	var targetUrl string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("vhost-brute - v" + version + "+" + git_hash)

	flagSet.CreateGroup("general", "General",
		flagSet.StringVarP(&targetUrl, "url", "u", "", "Target Url."),
		flagSet.StringVarP(&hostnameFile, "file", "f", "", "File containing hostnames to test."),
		flagSet.StringVarP(&dfltOpts.Http.Connection.ProxyUrl, "proxy", "p", dfltOpts.Http.Connection.ProxyUrl, "Proxy URL. For example: http://127.0.0.1:8080."),
		flagSet.StringSliceVarP(&headers, "header", "H", nil, "Add request header.", goflags.FileStringSliceOptions),
		flagSet.IntVarP(&dfltOpts.Http.Performance.RequestsPerSecond, "rps", "r", 10, "Request per second."),
		flagSet.IntVarP(&dfltOpts.Http.Performance.Timeout, "timeout", "t", 4, "Requests timeout."),
		flagSet.BoolVarP(&dfltOpts.OnlyUnindexed, "only-unindexed", "oU", false, "Only shows VHosts that dont have a public dns record."),
		flagSet.StringVarP(&statusCodes, "filter-codes", "fc", "", "Filter status codes (e.g. \"429,503,504\")."),
		flagSet.BoolVarP(&dfltOpts.Silent, "silent", "s", false, "Suppress stderr output."),
		flagSet.BoolVarP(&dfltOpts.Debug, "debug", "d", false, "Enable debug logging on stderr."),
	)
	flagSet.SetCustomHelpText(fmt.Sprintf(`EXAMPLE:
	%s -u https://1.2.3.4 -f hostnames.txt
	
	%s -s --only-unindexed -fc 403,429,502,503,504,409,523,422 -u https://1.2.3.4 -f hostnames.txt
`, os.Args[0], os.Args[0]))

	err := flagSet.Parse()
	if err != nil {
		return Config{}, fmt.Errorf("could not parse options: %s", err)
	}

	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	if dfltOpts.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelError)
	} else if dfltOpts.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}

	dfltOpts.Hostnames, err = ReadWordlist(hostnameFile)
	if err != nil {
		gologger.Fatal().Msgf("Failed to read hostname file: %s", err)
	}

	dfltOpts.Url, err = url.Parse(targetUrl)
	if err != nil || strings.Contains(dfltOpts.Url.Hostname(), "*") || targetUrl == "" {
		return Config{}, fmt.Errorf("invalid url provided: %s", err)
	}

	for _, code := range strings.Split(statusCodes, ",") {
		c, err := strconv.Atoi(code)
		if err == nil {
			dfltOpts.FilterCodes = append(dfltOpts.FilterCodes, c)
		}
	}

	for _, v := range headers {
		if headerParts := strings.SplitN(v, ":", 2); len(headerParts) >= 2 {
			dfltOpts.Http.DefaultHeaders[strings.Trim(headerParts[0], " ")] = strings.Trim(headerParts[1], " ")
		}
	}

	return dfltOpts, nil
}

func ReadWordlist(file string) ([]string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.Replace(string(data), "\r", "", -1), "\n")

	return lines, nil
}
