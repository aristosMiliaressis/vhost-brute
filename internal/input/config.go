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

const version = "1.0.1"

type Config struct {
	Url       *url.URL
	Hostnames []string

	Silent        bool
	Debug         bool
	OnlyUnindexed bool
	IncludeSNI    bool
	FilterCodes   []int

	Http httpc.ClientOptions
}

func ParseCliFlags(git_hash string) (Config, error) {
	dfltOpts := Config{}
	dfltOpts.Http = httpc.DefaultOptions
	dfltOpts.Http.MaintainCookieJar = false
	dfltOpts.Http.Redirection.FollowRedirects = false
	dfltOpts.Http.Connection.DisableKeepAlives = true
	dfltOpts.Http.ErrorHandling.ConsecutiveThreshold = 20
	dfltOpts.Http.ErrorHandling.HandleErrorCodes = []int{429, 529}
	dfltOpts.Http.ErrorHandling.ReverseErrorCodeHandling = true
	var headers goflags.StringSlice
	var hostnameFile string
	var statusCodes string
	var targetUrl string

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("vhost-brute - v" + version + "+" + git_hash)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringVarP(&targetUrl, "url", "u", "", "Target webserver base URL."),
		flagSet.StringVarP(&hostnameFile, "file", "f", "", "File containing hostnames."),
	)
	
	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&dfltOpts.Silent, "silent", "s", false, "Suppress stderr output."),
		flagSet.BoolVarP(&dfltOpts.Debug, "debug", "d", false, "Enable debug logging on stderr."),
	)
	
	flagSet.CreateGroup("filtering", "Filtering",
		flagSet.BoolVarP(&dfltOpts.OnlyUnindexed, "only-unindexed", "oU", false, "Only shows VHosts that dont have a corresponding dns record."),
		flagSet.StringVarP(&statusCodes, "filter-codes", "fc", "", "Filter status codes (e.g. \"403,502,503,504,530\")."),
	)
	
	flagSet.CreateGroup("performance", "Performance",
		flagSet.IntVarP(&dfltOpts.Http.Performance.RequestsPerSecond, "rps", "r", 10, "Requests per second."),
		flagSet.IntVarP(&dfltOpts.Http.Performance.Timeout, "timeout", "t", 4, "Request timeout in seconds."),
	)
	
	flagSet.CreateGroup("misc", "Misc",
		flagSet.StringVarP(&dfltOpts.Http.Connection.ProxyUrl, "proxy", "p", dfltOpts.Http.Connection.ProxyUrl, "Proxy URL (e.g. \"http://127.0.0.1:8080\")"),
		flagSet.StringSliceVarP(&headers, "header", "H", nil, "Add request header.", goflags.FileStringSliceOptions),
		flagSet.BoolVarP(&dfltOpts.IncludeSNI, "include-sni", "iS", false, "Includes corresponding SNI."),
	)
	flagSet.SetCustomHelpText(fmt.Sprintf(`EXAMPLE:
	%s -u https://1.2.3.4 -f hostnames.txt
	
	%s -s --only-unindexed -fc 403,502,503,504,409,521,523,422,530 -u https://1.2.3.4 -f hostnames.txt
`, os.Args[0], os.Args[0]))

	err := flagSet.Parse()
	if err != nil {
		return Config{}, fmt.Errorf("input: could not parse options: %s", err)
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
		return Config{}, fmt.Errorf("input: invalid url provided: %s", err)
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
