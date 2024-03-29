package brute

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/aristosMiliaressis/httpc/pkg/httpc"
	"github.com/aristosMiliaressis/vhost-brute/internal/input"
	"github.com/projectdiscovery/cdncheck"
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
	NotFoundPerApex map[string][]NotFoundSample
	notFoundMutex   sync.RWMutex
	cdncheck        *cdncheck.Client
}

type VHost struct {
	Address   string
	Hostname  string
	Comparison ComparisonResult
	WafBypass string `json:"WafBypass,omitempty"`
	Detection string
}

type ComparisonResult int
const (  
	SAME ComparisonResult = iota 
	DIFFERENT
	NEW
)

func (cr ComparisonResult) String() string {
    return []string{"SAME", "DIFFERENT", "NEW"}[cr]
}

func (cr ComparisonResult) MarshalJSON() ([]byte, error) {
    return json.Marshal(cr.String())
}

func NewScanner(conf input.Config) Scanner {
	ctx := context.Background()

	return Scanner{
		Config:          conf,
		client:          httpc.NewHttpClient(conf.Http, ctx),
		context:         ctx,
		NotFoundPerApex: map[string][]NotFoundSample{},
		cdncheck:        cdncheck.New(),
	}
}

func (s *Scanner) Scan() {

	var wg sync.WaitGroup
	for i, hostname := range s.Config.Hostnames {
		if hostname == "" {
			continue
		}

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

			if len(s.NotFoundPerApex[apexHostname]) == 0 {
				notFoundSample := s.getNotFoundSample(s.Config.Url, apexHostname, 3)

				s.NotFoundPerApex[apexHostname] = []NotFoundSample{notFoundSample}
			}
			notFound := s.NotFoundPerApex[apexHostname][0]
			s.notFoundMutex.Unlock()

			response := s.probeVHost(s.Config.Url, lHostname, 1)
			if response == nil {
				gologger.Error().Msgf("No Response for %s", lHostname)
				return
			}

			body, _ := io.ReadAll(response.Body)

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

					if locUrl.Host != "" && locUrl.Host != response.Request.Host {
						gologger.Info().Msgf("VHost %s found on %s but redirects cross origin to %s.\n", lHostname, s.Config.Url.Hostname(), locUrl)
						return
					}

					redirectHost := locUrl.Host
					locUrl.Scheme = s.Config.Url.Scheme
					locUrl.Host = s.Config.Url.Host
					redirectResponse := s.probeVHost(locUrl, redirectHost, 2)
					if redirectResponse == nil {
						gologger.Error().Msgf("No Response while following redirect %s -> %s", locUrl, redirectHost)
						return
					}

					if redirectResponse.StatusCode < 300 || redirectResponse.StatusCode >= 400 {
						break
					} else if i >= 5 {
						gologger.Error().Msgf("Too many Redirects %s -> %s", locUrl, redirectHost)
						return
					}
				}

				s.notFoundMutex.RLock()
				for _, notFound := range s.NotFoundPerApex[apexHostname] {
					if ok, _ := isDiffResponse(response, notFound.Response, notFound.Threshold); !ok {
						s.notFoundMutex.RUnlock()
						return
					}
				}
				s.notFoundMutex.RUnlock()

				notFoundSample := s.getNotFoundSample(s.Config.Url, apexHostname, 4)
				if ok, ipBanReason := isDiffResponse(response, notFoundSample.Response, notFoundSample.Threshold); !ok {
					gologger.Error().Msgf("Possible IP ban for %s, Ratelimit or server overload detected, %s.", apexHostname, ipBanReason)
					s.notFoundMutex.Lock()
					s.NotFoundPerApex[apexHostname] = append(s.NotFoundPerApex[apexHostname], notFoundSample)
					s.notFoundMutex.Unlock()
					return
				}

				ips := getIPs(lHostname, 5)
				if s.Config.OnlyUnindexed {
					if Contains(ips, s.Config.Url.Hostname()) {
						gologger.Info().Msgf("VHost %s found on %s but dns record exists.\n", lHostname, s.Config.Url.Hostname())
						return
					}
				}

				vhost := VHost{
					Address:   s.Config.Url.String(),
					Hostname:  lHostname,
					Detection: reason,
					Comparison: NEW,
				}

				if len(ips) != 0 {
					s.testWafBypass(vhost, ips, response, notFoundSample.Threshold)
				}
				
				if vhost.Comparison != SAME && Contains(s.Config.FilterCodes, response.StatusCode) {
					gologger.Info().Msgf("VHost %s found on %s but status code %d is filtered.\n", lHostname, s.Config.Url.Hostname(), response.StatusCode)
					return
				}

				jRes, _ := json.Marshal(vhost)

				fmt.Println(string(jRes))
			}
		}()
	}

	wg.Wait()
}

func (s *Scanner) getNotFoundSample(url *url.URL, hostname string, priority int) NotFoundSample {
	responses := []*http.Response{}
	for {
		resp := s.probeVHost(url, RandomString(1)+"."+hostname, priority)

		if resp == nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("ERR: %s", err)
			continue
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body))

		responses = append(responses, resp)

		break
	}

	for {
		resp := s.probeVHost(url, RandomString(62)+"."+hostname, priority)

		if resp == nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("ERR: %s", err)
			continue
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body))

		responses = append(responses, resp)

		break
	}

	for {
		resp := s.probeVHost(url, RandomString(62)+"."+RandomString(62)+"."+hostname, priority)

		if resp == nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("ERR: %s", err)
			continue
		}

		resp.Body = io.NopCloser(bytes.NewBuffer(body))

		responses = append(responses, resp)

		break
	}

	body1, err := io.ReadAll(responses[0].Body)
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}
	responses[0].Body = io.NopCloser(bytes.NewBuffer(body1))

	body2, err := io.ReadAll(responses[1].Body)
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}
	responses[1].Body = io.NopCloser(bytes.NewBuffer(body2))
	max := levenshteinDistance([]rune(string(body1)), []rune(string(body2)))

	body3, err := io.ReadAll(responses[2].Body)
	if err != nil {
		gologger.Error().Msgf("ERR: %s", err)
	}
	responses[2].Body = io.NopCloser(bytes.NewBuffer(body3))

	lev := levenshteinDistance([]rune(string(body2)), []rune(string(body3)))
	if lev > max {
		max = lev
	}

	lev = levenshteinDistance([]rune(string(body1)), []rune(string(body3)))

	if lev > max {
		max = lev
	}

	max = max + 10

	return NotFoundSample{responses[2], max}
}

func (s *Scanner) probeVHost(url *url.URL, hostname string, priority int) *http.Response {
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		gologger.Error().Msg("Failed to create request.")
	}

	req.Host = hostname
	opts := s.client.Options
	opts.RequestPriority = httpc.Priority(priority)

	if s.Config.IncludeSNI {
		opts.Connection.SNI = hostname
	}
	
	msg := s.client.SendWithOptions(req, opts)
	<-msg.Resolved
	if msg.Response == nil {
		gologger.Error().Msgf("Transport Error %s", msg.TransportError)
	}

	return msg.Response
}

func isDiffResponse(r1, r2 *http.Response, diffThreshold int) (bool, string) {
	if r1 == nil || r2 == nil {
		return false, ""
	}
	if r1.Status != r2.Status {
		return true, fmt.Sprintf("status: %s/%s", r1.Status, r2.Status)
	}

	if r1.Header.Get("Location") != r2.Header.Get("Location") {
		return true, "location"
	}

	body1, _ := io.ReadAll(r1.Body)
	r1.Body = io.NopCloser(bytes.NewBuffer(body1))

	body2, _ := io.ReadAll(r2.Body)
	r2.Body = io.NopCloser(bytes.NewBuffer(body2))

	diff := levenshteinDistance([]rune(string(body1)), []rune(string(body2)))

	if diff > diffThreshold {
		return true, fmt.Sprintf("edit-distance: %d", diff)
	}

	// if !strings.EqualFold(r1.Header.Get("Content-Type"), r2.Header.Get("Content-Type")) {
	// 	return true, "Content-Type"
	// }

	return false, ""
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

func (s *Scanner) testWafBypass(vhost VHost, ips []string, response *http.Response, retryThreshold int) {
	opts := s.client.Options
	opts.RequestPriority = httpc.Priority(3)
	if s.Config.IncludeSNI {
		opts.Connection.SNI = vhost.Hostname
	}
	req, _ := http.NewRequest("GET", "https://"+vhost.Hostname, nil)
	msg := s.client.SendWithOptions(req, opts)
	<-msg.Resolved
	if msg.Response == nil {
		req, _ := http.NewRequest("GET", "http://"+vhost.Hostname, nil)
		msg = s.client.SendWithOptions(req, opts)
		<-msg.Resolved
	}

	diff, _ := isDiffResponse(response, msg.Response, retryThreshold)
	vhost.Comparison = DIFFERENT
	if !diff {
		vhost.Comparison = SAME
		matched, waf, err := s.cdncheck.CheckWAF(net.ParseIP(ips[0]))
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		ip := net.ParseIP(s.Config.Url.Hostname())
		if ip == nil {
			dnsIps, _ := net.LookupIP(s.Config.Url.Hostname())
			ip = dnsIps[0]
		}
		_, waf2, err2 := s.cdncheck.CheckWAF(ip)
		if err2 != nil {
			gologger.Error().Msg(err2.Error())
		}
		if err == nil && err2 == nil && matched && waf != waf2 {
			vhost.WafBypass = waf
		}
	}
}