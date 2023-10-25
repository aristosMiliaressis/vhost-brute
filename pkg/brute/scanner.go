package brute

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	neturl "net/url"
	"sync"

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/aristosMiliaressis/vhost-brute/pkg/input"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/publicsuffix"
)

type NotFoundSample struct {
	Response  *http.Response
	Threshold int
}

type Scanner struct {
	Config          input.Config
	client          *httpc.HttpClient
	context         context.Context
	NotFoundPerApex map[string]*NotFoundSample
	notFoundMutex   sync.Mutex
	failingApexs    []string
}

func NewScanner(conf input.Config) Scanner {
	ctx := context.Background()

	return Scanner{
		Config:          conf,
		client:          httpc.NewHttpClient(conf.Http, ctx),
		context:         ctx,
		NotFoundPerApex: map[string]*NotFoundSample{},
		failingApexs:    []string{},
	}
}

func (s *Scanner) Scan() {

	var wg sync.WaitGroup
	for i, hostname := range s.Config.Hostnames {
		idx := i
		lHostname := hostname

		apexHostname, err := publicsuffix.EffectiveTLDPlusOne(lHostname)
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}

		wg.Add(1)

		go func() {
			defer wg.Done()

			s.notFoundMutex.Lock()
			notFound := s.NotFoundPerApex[apexHostname]

			if notFound == nil {
				notFoundResponse, threshold := s.getNotFoundVHost(s.Config.Url, apexHostname, 3)
				notFound = &NotFoundSample{
					Response:  notFoundResponse,
					Threshold: threshold,
				}
				s.NotFoundPerApex[apexHostname] = notFound
			}
			s.notFoundMutex.Unlock()

			response := s.getVHostResponse(s.Config.Url, lHostname, 1)
			if response == nil {
				gologger.Error().Msgf("No Response for %s", lHostname)
				return
			}

			body, _ := ioutil.ReadAll(response.Body)

			response.Body = io.NopCloser(bytes.NewBuffer(body))

			gologger.Info().Msgf("[#%d]\tstatus:%d\tcl:%d\tct:%s\tloc:%s\thost:%s", idx, response.StatusCode, len(body), response.Header.Get("Content-Type"), response.Header.Get("Location"), lHostname)

			if ok, reason := isDiffResponse(notFound.Response, response, notFound.Threshold); ok {

				for i := 0; response.StatusCode >= 300 && response.StatusCode <= 400; i++ {
					location := response.Header.Get("Location")
					locUrl, err := url.Parse(location)
					if err != nil {
						gologger.Error().Msgf("Error while following redirect[%s] %s", location, err)
						return
					}

					redirectHost := locUrl.Host
					locUrl.Scheme = s.Config.Url.Scheme
					locUrl.Host = s.Config.Url.Host
					redirectResponse := s.getVHostResponse(locUrl, redirectHost, 2)
					if redirectResponse == nil {
						gologger.Error().Msgf("No Response while following redirect %s -> %s", locUrl, redirectHost)
						return
					}

					if redirectResponse.StatusCode < 300 || redirectResponse.StatusCode >= 400 {
						break
					} else if i >= 5 {
						return
					}
				}

				if Contains(s.Config.FilterCodes, response.StatusCode) {
					gologger.Info().Msgf("VHost %s found on %s but status code %d is filtered.\n", lHostname, s.Config.Url.Hostname(), response.StatusCode)
					return
				}

				if err != nil || Contains(s.failingApexs, apexHostname) {
					return
				}

				notFoundRetry, retryThreshold := s.getNotFoundVHost(s.Config.Url, apexHostname, 4)
				if ok, _ := isDiffResponse(notFound.Response, notFoundRetry, retryThreshold); ok {
					gologger.Error().Msgf("Possible IP ban, Ratelimit or server overload detected, status %d.", notFoundRetry.StatusCode)
					s.failingApexs = append(s.failingApexs, apexHostname)
					return
				}

				if s.Config.OnlyUnindexed {
					ips := getIPs(lHostname, 5)
					if Contains(ips, s.Config.Url.Hostname()) {
						gologger.Info().Msgf("VHost %s found on %s but dns record exists.\n", lHostname, s.Config.Url.Hostname())
						return
					}
				}

				fmt.Printf("%s %s cause %s\n", lHostname, s.Config.Url, reason)
			}
		}()
	}

	wg.Wait()
}

func (s *Scanner) getNotFoundVHost(url *neturl.URL, hostname string, priority int) (*http.Response, int) {
	responses := []*http.Response{}
	for {
		resp := s.getVHostResponse(url, RandomString(12)+"."+hostname, priority)

		if resp == nil {
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("ERR: %s", err)
			continue
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body))

		responses = append(responses, resp)

		if len(responses) == 3 {
			break
		}
	}

	body1, err := ioutil.ReadAll(responses[0].Body)
	responses[0].Body = io.NopCloser(bytes.NewBuffer(body1))
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}

	body2, err := ioutil.ReadAll(responses[1].Body)
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}
	max := levenshteinDistance([]rune(string(body1)), []rune(string(body2)))

	body3, err := ioutil.ReadAll(responses[2].Body)
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}

	lev := levenshteinDistance([]rune(string(body2)), []rune(string(body3)))
	if lev > max {
		max = lev
	}

	lev = levenshteinDistance([]rune(string(body1)), []rune(string(body3)))

	if lev > max {
		max = lev
	}

	// Add extra eddit distance to account for hostnames being reflected
	max = max + 263 - len(hostname) - 13

	return responses[0], max
}

func (s *Scanner) getVHostResponse(url *neturl.URL, hostname string, priority int) *http.Response {
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		gologger.Error().Msg("Failed to create request.")
	}

	req.Host = hostname
	opts := s.client.Options
	opts.RequestPriority = httpc.Priority(priority)

	msg := s.client.SendWithOptions(req, opts)
	<-msg.Resolved

	return msg.Response
}

func getIPs(hostname string, tries int) []string {
	// use retries to mitigate false positives from dns loadbalancing

	strIps := []string{}

	for i := 0; i < tries; i++ {
		ips, _ := net.LookupIP(hostname)
		for _, ip := range ips {
			if !Contains(strIps, ip.String()) {
				strIps = append(strIps, ip.String())
			}
		}
	}

	return strIps
}

func isDiffResponse(r1, r2 *http.Response, diffThreshold int) (bool, string) {
	if r1.Status != r2.Status {
		return true, fmt.Sprintf("status: %d", r2.StatusCode)
	}

	if r1.Header.Get("Location") != r2.Header.Get("Location") {
		return true, "location"
	}

	body1, _ := ioutil.ReadAll(r1.Body)
	r1.Body = io.NopCloser(bytes.NewBuffer(body1))

	body2, _ := ioutil.ReadAll(r2.Body)
	diff := levenshteinDistance([]rune(string(body1)), []rune(string(body2)))

	return diff > diffThreshold, fmt.Sprintf("edit-distance: %d", diff)
}
