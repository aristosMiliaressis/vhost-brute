vhost-brute
==

Virtual host detection tool.  

<br>

**Features**
- integrates with cdncheck to detect waf bypass
- differentiates not-found responses per apex hostname.
  - some servers return different not found responses for subdomains of specific apex domains
- follows redirects on host, and filters redirect loops.
- filters cross origin redirects.
- option to filter virtual hosts with public dns records.
  - uses retries to mitigate false positives from dns loadbalancing.
- option to filter status codes.
- request rate control.

<br>

**Help Page**
```
vhost-brute - v1.0.1+040f40d

Usage:
  ./vhost-brute [flags]

Flags:
INPUT:
   -u, -url string   Target webserver base URL.
   -f, -file string  File containing hostnames.

OUTPUT:
   -l, -log value             Stderr log level (silent/default/verbose) (default default)
   -d, -debug                 Prints statistics at the end.
   -rD, -response-dir string  Store matched responses at this directory

FILTERING:
   -oU, -only-unindexed       Only shows VHosts that dont have a corresponding dns record.
   -fc, -filter-codes string  Filter status codes (e.g. "409,421,422,502,503,504,521,523,530").

PERFORMANCE:
   -r, -rps int      Requests per second. (default 20)
   -t, -timeout int  Request timeout in seconds. (default 5)

MISC:
   -p, -proxy string     Proxy URL (e.g. "http://127.0.0.1:8080")
   -H, -header string[]  Add request header.


EXAMPLE:
	./vhost-brute -u https://1.2.3.4 -f hostnames.txt
	
	./vhost-brute -s --only-unindexed -sR ./responses -fc 502,503,504,409,521,523,422,530 -u https://1.2.3.4 -f hostnames.txt

```
