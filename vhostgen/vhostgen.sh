#!/bin/bash
# Dependencies: unfurl, altdns

if [[ $# -lt 1 ]]
then
    echo "USAGE: $0 <hostnamelist>"
    exit 1
fi

hostnames=$1
tld_wordlist="$(dirname $(realpath $0))/tlds.txt"
alt_wordlist="$(dirname $(realpath $0))/alts.txt"
sub_wordlist="$(dirname $(realpath $0))/subs.txt"
tld_alts=`mktemp`
sub_alts=`mktemp`
trap "rm $tld_alts $sub_alts *_altdns.out" EXIT

for domain in $(cat $hostnames)
do
    cat $tld_wordlist | xargs -I% echo "$(echo $domain | unfurl format %S.%r).%"
done > $tld_alts

while read domain
do
    altdns -i $hostnames -o ${domain}_altdns.out -w $alt_wordlist
    cat $sub_wordlist | xargs -I% echo "%s.$(echo $domain | unfurl format %r.%t)" >> $sub_alts
done < <(cat $hostnames | unfurl format %r.%t | sort -u)

cat $tld_alts $sub_alts *_altdns.out | grep -v '^\.' | tr -d '\r' | sort -u
