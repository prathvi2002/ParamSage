#!/bin/bash

echo ""
echo "Usage: cat urls.txt | paramsage --nocolour --nostrict | sqli.sh --proxy"
echo "--proxy is optional"
echo ""

PROXY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy)
            PROXY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Read from stdin line-by-line
grep 'sqli:' | while read -r line; do
    url=$(echo "$line" | cut -d' ' -f1)
    params=$(echo "$line" | sed -n 's/.*sqli: \[\(.*\)\]/\1/p' | tr -d ' ')

    [[ -z "$params" ]] && continue

    echo "[+] URL: $url"
    IFS=',' read -ra param_array <<< "$params"
    for param in "${param_array[@]}"; do
        echo "    Param: $param"
        if [[ -z "$PROXY" ]]; then
          sqlmap -u "$url" -p "$param" --batch --level=5 --risk=3 --random-agent --smart
        else
          sqlmap -u "$url" -p "$param" --batch --level=5 --risk=3 --random-agent --smart --proxy "$PROXY"
        fi
    done
done

