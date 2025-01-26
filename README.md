# FlareTaker

Key Additions:

1. **Cloudflare Bypass Techniques**:
   - Automatic Cloudflare detection using wafw00f
   - Cloudflare tunnel creation with cloudflared
   - Header manipulation for bypass (X-Forwarded-For, CF-Connecting-IP)
   - Specialized Nuclei templates for Cloudflare-protected targets

2. **Advanced SQL Injection Testing**:
   - Integrated sqlmap with tamper scripts:
     ```bash
     sqlmap -u "$TARGET" --dbs --batch --time-sec 10 --level 3 --hex \
         --random-agent --tamper=space2comment,between,charencode
     ```
   - Ghauri integration for modern SQLi detection
   - Time-based blind testing with multiple payload variations:
     ```bash
     url%20AND%201=SLEEP(10)
     url%20AND%20(SELECT%20$i%20FROM%20(SELECT(SLEEP(10)))a)
     ```
   - Error-based detection through response analysis

3. **Recent Bounty Techniques**:
   - IP spoofing headers for WAF bypass
   - Parallel testing with xargs
   - New tamper scripts (charencode)
   - Cloudflare-specific nuclei templates

4. **Enhanced Reporting**:
   - Separate SQLi findings section
   - Detailed time-based and error-based results
   - Ghauri-specific findings
   - Cloudflare bypass results

Usage Tips:
1. Install new dependencies:
```bash
pip install ghauri wafw00f cf-check
go install -v github.com/projectdiscovery/cloudflared/cmd/cloudflared@latest
```

2. Run with Cloudflare bypass:
```bash
./taker.sh --url target.com --mode full --notify
```

3. For heavy WAF targets:
```bash
# Use custom header lists in CONFIG_DIR/headers.txt
# Add more tamper scripts to sqlmap command
# Adjust sleep times in time-based testing
```

