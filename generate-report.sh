#!/bin/bash

dnsfile=`mktemp`
vhostfile=`mktemp`
trap "rm $dnsfile $vhostfile" EXIT

grep -hr '{"' | jq -r .Hostname | httpx > $dnsfile
gowitness file -f $dnsfile --disable-db -F -P ./dns_screenshots

cp /etc/hosts /etc/hosts.bak
trap "mv /etc/hosts.bak /etc/hosts" EXIT
grep -hr '{"' | jq -r '. | "\(.Address) \(.Hostname)"' | sed -E 's,https?://,,' | sed -E 's,:[0-9]+ , ,' >> /etc/hosts

grep -hr '{"' | jq -r .Hostname | httpx > $vhostfile
gowitness file -f $vhostfile --disable-db -F -P ./vhost_screenshots

tablehtml=$(ls vhost_screenshots | while read file; do echo "<tr><td><b>$file</b></td><td><img src='dns_screenshots/$file'/></td><td><img src='vhost_screenshots/$file'/></td></tr>"; done)

cat >report.html <<EOF
<!DOCTYPE html>
<html>
    <head>
		<style>
			table, td {
				border: 1px solid black;
			}
		</style>
	</head>
	<body>
		<table>
			$tablehtml
		</table>
	</body>
</html>
EOF