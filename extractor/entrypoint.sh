$content = @'
#!/bin/sh
set -e

# Create out dirs
mkdir -p "${OUT_DIR:-/data/out}"
mkdir -p "${PCAP_DIR:-/data/pcap}"

# Run extractor
exec python /opt/extractor/extractor.py \
  --pcap-dir "${PCAP_DIR:-/data/pcap}" \
  --cowrie-json "${COWRIE_JSON:-/cowrie/log/cowrie.json}" \
  --out-dir "${OUT_DIR:-/data/out}"
'@
Set-Content -Path extractor/entrypoint.sh -Encoding utf8 -Value $content

# 2) Convert CRLF -> LF
(Get-Content extractor/entrypoint.sh -Raw) -replace "`r`n","`n" |
  Set-Content extractor/entrypoint.sh -NoNewline -Encoding utf8

# 3) Make it executable in Git
git update-index --chmod=+x extractor/entrypoint.sh
git add extractor/entrypoint.sh
git commit -m "fix: restore entrypoint.sh (LF, +x, valid sh)"
git push
