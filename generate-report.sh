#!/bin/bash
# Dependencies: gowitness, httpx, parallel, jq

dnsfile=`mktemp`
vhostfile=`mktemp`
trap "rm $dnsfile $vhostfile" EXIT

cat * | grep '^{"' | jq -r .Hostname | httpx > $dnsfile
gowitness file -f $dnsfile --disable-db -F -P ./dns_screenshots
cat $dnsfile | parallel -j 5 "curl -s -I -k {} > dns_screenshots/\$(echo {} | sed 's,://,-,').headers"

cp /etc/hosts ./hosts.bak
trap "cat ./hosts.bak > /etc/hosts" EXIT
cat * | grep '^{"' | jq -r '. | "\(.Address) \(.Hostname)"' | sed -E 's,https?://,,' | sed -E 's,:[0-9]+ , ,' >> /etc/hosts

cat * | grep '^{"' | jq -r .Hostname | httpx > $vhostfile
gowitness file -f $vhostfile --disable-db -F -P ./vhost_screenshots
cat $vhostfile | parallel -j 5 "curl -s -I -k {} > vhost_screenshots/\$(echo {} | sed 's,://,-,').headers"

generate_report_row() {
	dnsHeaders=$(cat dns_screenshots/$(echo $1 | sed 's/.png$/.headers/'))
	vhostHeaders=$(cat vhost_screenshots/$(echo $1 | sed 's/.png$/.headers/'))
	hostname=$(echo $1 | sed 's/.png$//' | sed -E 's/https?-//')
	address=$(cat * | grep '^{\"' | jq -r "select(.Hostname == \"$hostname\") | .Address" | head -n 1)
	bypass=$(cat * | grep '^{\"' | jq -r "select(.Hostname == \"$hostname\") | .WafBypass" | head -n 1)
	header="<b>$hostname at $address</b><br/><br/>"
	headerColumn="$header<b>DNS Headers</b><pre>$dnsHeaders</pre><b>VHOST Headers</b><pre>$vhostHeaders</pre>$bypass"
	
	echo "<tr><td>$headerColumn</td><td><img alt='N/A' src='dns_screenshots/$1'/></td><td><img src='vhost_screenshots/$1'/></td></tr>"
}

tablehtml=$(ls vhost_screenshots/*.png | sed 's,vhost_screenshots/,,' | while read file; do generate_report_row $file; done)

cat >report.html <<EOF
<!DOCTYPE html>
<html>
    <head>
		<style>
			table, td {
				border: 1px solid black;
				background-color: #d5f4e6;
				table-layout:fixed;
				width: 100%;
			}
			img { width: 100%; }
			pre, b { font-size: 16px; white-space: pre-wrap; }
		</style>
	</head>
	<body>
		<table>
			$tablehtml
		</table>
	</body>
</html>
EOF