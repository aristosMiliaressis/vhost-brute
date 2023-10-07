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

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/aristosMiliaressis/vhost-brute/pkg/input"
	"github.com/projectdiscovery/gologger"
)

type Scanner struct {
	Config  input.Config
	client  *httpc.HttpClient
	context context.Context
}

func NewScanner(conf input.Config) Scanner {
	ctx := context.Background()

	return Scanner{
		Config:  conf,
		client:  httpc.NewHttpClient(conf.Http, ctx),
		context: ctx,
	}
}

func (s Scanner) Scan() {
	notFoundResponse, threshold := s.getNotFoundVHost(s.Config.Url)

	for _, hostname := range s.Config.Hostnames {
		response := s.getVHostResponse(s.Config.Url, hostname)
		gologger.Info().Msgf("status:%d\tcl:%d\tct:%s\tloc:%s - %s", response.StatusCode, response.ContentLength, response.Header.Get("Content-Type"), response.Header.Get("Location"), hostname)

		if ok, reason := isDiffResponse(notFoundResponse, response, threshold); ok {

			if response.StatusCode >= 300 && response.StatusCode <= 400 {
				location := response.Header.Get("Location")
				locUrl, err := url.Parse(location)
				if err != nil {
					gologger.Error().Msgf("Error while following redirect[%s] %s", location, err)
					continue
				}

				count := 0
				maxRedirects := 15
				for {
					response := s.getVHostResponse(locUrl, locUrl.Host)
					if response == nil || (response.StatusCode < 300 && response.StatusCode >= 400) {
						break
					}
					count++
					if count == maxRedirects {
						break
					}
				}

				if ok, _ := isDiffResponse(notFoundResponse, response, threshold); count == maxRedirects || !ok {
					continue
				}
			} else if Contains(s.Config.FilterCodes, response.StatusCode) {
				gologger.Info().Msgf("VHost %s found on %s but status code %d is filtered.\n", hostname, s.Config.Url.Hostname(), response.StatusCode)
				continue
			}

			if s.Config.OnlyUnindexed {
				ips := getIPs(hostname)
				if Contains(ips, s.Config.Url.Hostname()) {
					gologger.Info().Msgf("VHost %s found on %s but dns record exists.\n", hostname, s.Config.Url.Hostname())
					continue
				}
			}

			fmt.Printf("%s %s cause %s\n", hostname, s.Config.Url, reason)
		}
	}
}

func (s Scanner) getNotFoundVHost(url *neturl.URL) (*http.Response, int) {
	responses := []*http.Response{}
	for {
		resp := s.getVHostResponse(url, RandomString(24)+".skroutz.gr")

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

	return responses[0], max
}

func (s Scanner) getVHostResponse(url *neturl.URL, hostname string) *http.Response {
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		gologger.Error().Msg("Failed to create request.")
	}

	req.Host = hostname
	msg := s.client.Send(req)
	<-msg.Resolved

	return msg.Response
}

func getIPs(hostname string) []string {
	strIps := []string{}
	ips, _ := net.LookupIP(hostname)
	for _, ip := range ips {
		strIps = append(strIps, ip.String())
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
