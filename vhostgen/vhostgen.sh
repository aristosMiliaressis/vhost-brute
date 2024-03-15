#!/bin/bash

if [[ $# -lt 1 ]]
then
    echo "USAGE: $0 <hostnamelist>"
    exit 1
fi

hostnames=$1
tld_wordlist='tlds.txt'
alt_wordlist='alts.txt'
sub_wordlist='subs.txt'
tld_alts=`mktemp`
sub_alts=`mktemp`

for domain in $(cat $hostnames)
do
    cat $tld_wordlist | xargs -I% echo "$(echo $domain | unfurl format %S.%r).%"
done > $tld_alts

while read domain
do
    gotator -silent -sub $hostnames -perm $alt_wordlist -depth 1 -numbers 2 > ${domain}_gotator.out
    cat $sub_wordlist | xargs -I% echo "%s.$(echo $domain | unfurl format %r.%t)" >> $sub_alts
done < <(cat $hostnames | unfurl format %r.%t | sort -u)

cat $tld_alts $sub_alts *_gotator.out | sort -u
rm $tld_alts $sub_alts *_gotator.out