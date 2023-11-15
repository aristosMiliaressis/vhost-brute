vhost-brute
==

Virtual host detection tool.  

<br>

**Features**
- differentiates not-found responses per apex hostname.
- follows redirects as vhosts on target url, and filters redirect loops.
- option to filter virtual hosts with public dns records.
  - uses retries to mitigate false positives from dns loadbalancing.
- option to filter status codes.
- request rate control.
- integrates with cdncheck to detect waf bypass

<br>

**Help Page**
```
vhost-brute - v1.0.0

Usage: 
  ./vhost-brute [flags]

Flags:
GENERAL:
    -u, -url string            Target Url.
    -f, -file string           File containing hostnames to test. 
    -p, -proxy string          Proxy URL. For example: http://127.0.0.1:8080.
    -H, -header string[]       Add request header. 
    -r, -rps int               Request per second.
    -oU, -only-unindexed       Only shows VHosts that dont have a public dns record.
    -fc, -filter-codes string  Filter status codes. (e.g. "429,503,504")
    -s, -silent                Suppress stderr output.


EXAMPLE:
    ./vhost-brute -u https://1.2.3.4 -f hostnames.txt

    ./vhost-brute -s --only-unindexed -u https://1.2.3.4 -f hostnames.txt
```
