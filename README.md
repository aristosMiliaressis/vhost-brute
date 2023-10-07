vhost-brute
==

Virtual host detection tool.  

<br>

**Features**
- filters false positive redirect responses.
- option to filter status codes.
- option to filter virtual hosts with public dns records.   

<br>

**Help Page**
```
vhost-brute - v1.0.0

Usage: /opt/vhost-brute/vhost-brute [flags]

Flags:
GENERAL:
	-u, -url 	string		Target Url.
	-f, -file 	string 		File containing hostnames to test. 
	-s, -silent 			Suppress stderr output.
	-H, -header 	string[]	Add request header. 
	-oU, -only-unindexed 		Only shows VHosts that dont have a public dns record.
	-fc, -filter-codes string 	Filter status codes. (e.g. "429,502,503")


EXAMPLE:
	/opt/vhost-brute/vhost-brute -u https://1.2.3.4 -f hostnames.txt

	/opt/vhost-brute/vhost-brute -s --only-unindexed \
                -fc 429,502,503,504,409,523,422 \
                -u https://1.2.3.4 -f hostnames.txt

```