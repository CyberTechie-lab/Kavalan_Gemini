#!/usr/bin/env bash
# Download the public corpora Kavalan's tactic model trains on, into data/.
set -e
mkdir -p data && cd data
B=https://raw.githubusercontent.com
curl -sfSLO  $B/Morzeux/HttpParamsDataset/master/payload_full.csv
curl -sfSLO  $B/danielmiessler/SecLists/master/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt
curl -sfSLO  $B/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt
curl -sfSLO  $B/danielmiessler/SecLists/master/Fuzzing/command-injection-commix.txt
curl -sfSL -o ssrf_README.md "$B/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md"
echo "data fetched:"; ls -la
