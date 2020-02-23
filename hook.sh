#!/usr/bin/env bash

# DNS-01 challenge hook for Freenom used in dehydrated, a Let's Encrypt client

# Copyright © 2020 Ivan Vatlin <jenrus@tuta.io>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -euo pipefail

freenom_email="" # Enter your login here
freenom_passwd="" # Enter your password here
httpAttempts="3"
userAgents=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.10586,gzip(gfe)"
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"
    "Mozilla/5.0 (IE 11.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko"
    "Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 12_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Android 9.0; Mobile; rv:61.0) Gecko/61.0 Firefox/61.0"
)

cookie_file="$(mktemp)"
trap 'rm -f $cookie_file' EXIT HUP INT TERM
curl_common_args=(-s -A "${userAgents[RANDOM%11]}" --compressed -L)

subdomain="_acme-challenge."

_login() {
    local counter=1
    while [ "$counter" -le "$httpAttempts" ]; do
        authToken="$(curl "${curl_common_args[@]}" \
        -c "$cookie_file" "https://my.freenom.com/clientarea.php" \
        | grep "<input type=\"hidden\" name=\"token\" value=" \
        | head -n 1 | awk -F \" '{print $6}')"
        loginResult="$(curl "${curl_common_args[@]}" \
        -e 'https://my.freenom.com/clientarea.php' -c "$cookie_file" \
        -F "username=$freenom_email" \
        -F "password=\"$freenom_passwd\"" \
        -F "token=$authToken" \
        "https://my.freenom.com/dologin.php")"
        if [ -z "$(echo -e "$loginResult" | grep -E "Location: /clientarea.php\?incorrect=true|Login Details Incorrect")" ]; then
            break
        else
            if [ "$counter" -eq "$httpAttempts" ]; then
                echo "[HOOK_ERROR]: Login failed!"
                exit 1
            fi
            ((counter++))
        fi
    done
    echo "[HOOK_INFO]: Login successful"
} 

_getDomainID() {
    local counter=1
    mapfile -t domains < <(curl "${curl_common_args[@]}" -b "$cookie_file" \
    "https://my.freenom.com/clientarea.php?action=domains&itemlimit=all&token=$authToken" \
    | grep second | awk -F \> '{print $3}')
    mapfile -t domainIds < <(curl "${curl_common_args[@]}" -b "$cookie_file" \
    "https://my.freenom.com/clientarea.php?action=domains&itemlimit=all&token=$authToken" \
    | grep '<a class="smallBtn whiteBtn pullRight"' | awk -F = '{print $5}' | awk -F \" '{print $1}')
    for i in "${!domains[@]}"; do
        if [[ "${domains[$i]}" = "$domain" ]]; then
            domainId="${domainIds[$i]}"
            break
        fi
    done
    echo "[HOOK_INFO]: DomainID for $domain is $domainId"
} 

_getDNSInfo() {
    local counter=1
    mapfile -t dnsInfo < <(curl "${curl_common_args[@]}" -b "$cookie_file" \
    "https://my.freenom.com/clientarea.php?managedns=${domain}&domainid=${domainId}" | tr '<' '\n' \
    | grep -E "input type=\"(text|hidden)\" name=\"records\[([0-9]+)\]\[(type|name|ttl|value)\]\" value=\"" \
    | awk -F \" '{print $6}')
    if [[ "${#dnsInfo[@]} % 4" -ne "0" ]]; then
        echo "[HOOK_ERROR]: DNS records can not be obtained!"
    fi
} 

_splitDomain() {
    mapfile -t -O 1 subdomain_parts < <(echo "${domain}" | tr '.' '\n')
    if [[ ${#subdomain_parts[@]} -gt 2 ]]; then
        subdomain=$subdomain$(echo "$domain" | awk -F . '{i = 1; while (i < NF-1) {print $i "."; i++}}' | tr -d '\n')
        domain=$(echo "$domain" | awk -F . '{print $(NF-1) "." $NF}')
    fi
}

_searchDNSRecord() {
    for (( i=1; i<=${#dnsInfo[@]}; i+=4 )); do
        if [[ "$(echo "${dnsInfo[$i]}." | tr [[:upper:]] [[:lower:]])" = "$subdomain" ]]; then
            subdomainIndex="$i"
            subdomainValue="${dnsInfo[$i+2]}"
            ((recordIndex=$i/4))
            break
        fi
    done
}

_checkDNSRecord() {
    printf "[HOOK_INFO]: Waiting for DNS update..."
    minutes=1
    while [[ $(dig +short -t txt "$subdomain""$domain" | tr -d "\"" | grep "$dnsToken") == "" ]]; do
        sleep 1m
        printf \\r
        printf "[HOOK_INFO]: Waiting DNS update for %s minutes" "$minutes"
        ((minutes++))
    done
    printf \\n
}

_addDNSRecord() {
    local counter=1
    addResult=$(curl "${curl_common_args[@]}" -e 'https://my.freenom.com/clientarea.php' -b "$cookie_file" \
        -F "dnsaction=add" \
        -F "addrecord[0][name]=${subdomain}" \
        -F "addrecord[0][type]=TXT" \
        -F "addrecord[0][ttl]=3600" \
        -F "addrecord[0][value]=${dnsToken}" \
        -F "token=$authToken" \
        "https://my.freenom.com/clientarea.php?managedns=${domain}&domainid=${domainId}")
    if [ -z "$(echo -e "$addResult" | grep "<li class=\"dnssuccess\">Record added successfully</li>")" ]; then
        echo "[HOOK_ERROR]: DNS record was not added!"
    fi
    echo "[HOOK_INFO]: DNS record was successfully added"
}

case "$1" in
    "deploy_challenge")
        domain=$2
        dnsToken=$4
        _splitDomain
        _login
        _getDomainID
        _getDNSInfo
        _searchDNSRecord
        _addDNSRecord
        _checkDNSRecord
    ;;
    "clean_challenge")
        echo "clean_challenge was requested"
    ;;
    "invalid_challenge")
        echo "invalid_challenge was requested"
    ;;
    "sync_cert")
        echo "sync_cert was requested"
    ;;
    "deploy_cert")
        echo "deploy_cert was requested"
    ;;
    "unchanged_cert")
        echo "unchanged_cert was requested"
    ;;
    "request_failure")
        echo "request_failure was requested"
    ;;
    "startup_hook")
        echo "startup_hook was requested"
    ;;
    "exit_hook")
        echo "exit_hook was requested"
    ;;
    *)
        echo "Unknown hook \"${1}\""
    ;;
esac

exit 0
