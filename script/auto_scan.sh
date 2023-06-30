#!/bin/bash

target=$(cat target.txt)

# Asset Discovery
assetfindertarget >> discovered_domains.txt
sublist3r -d $target >> discovered_domains.txt
amass enum -d $target >> discovered_domains.txt
subfinder -d $target >> discovered_domains.txt
waybackurls $target | tee wayback_output.txt
gitGraber -k $target -dir output

# Link Discovery
cat discovered_domains.txt | sort -u | httprobe | tee live_domains.txt
linkfinder -i 'live_domains.txt' -o 'links_output.txt'
reconspider -i 'live_domains.txt' -o 'recon_output.txt'

# Directory and File Scanning
gobuster dir -w /path/to/wordlist -u $target -o gobuster_output.txt
ffuf -w /path/to/wordlist -u $target/FUZZ -o ffuf_output.txt
dalfox file -b -o dalfox_output.txt
hakrawler -url $target -plain -depth 3 -timeout 10 -o hakrawler_output.txt
dirsearch -u $target -o dirsearch_output.txt
sn1per -t $target -o sn1per_output.txt
snitch -t $target -o snitch_output.txt
arjun -u $target -o arjun_output.txt
dirhunt --url $target -o dirhunt_output.txt
meg -d 1000 $target >> meg_output.txt
dnsprobe -l discovered_domains.txt -r CNAME >> dnsprobe_output.txt

# Exploitation and Vulnerability Assessment
xsstrike -u $target -o xsstrike_output.txt
subjack -w discovered_domains.txt -c /path/to/fingerprints.json -o subjack_output.txt
massdns -r /path/to/resolvers.txt -t A -o S -w massdns_output.txt discovered_domains.txt
gitdorker -t $target -o gitdorker_output.txt
wpscan --url $target --enumerate --log wpscan_output.txt
joomscan -u $target -ec -ecp -o joomscan_output.txt
pwnback -d $target -o pwnback_output.txt

echo "Automated scanning completed!"
