#!/bin/bash
# Run Snort on all CIC-IDS2017 PCAP files
set -e

PCAP_DIR="${PCAP_DIR:-/path/to/your/PCAPs}"
OUT_BASE="/tmp/snort_results"
PROJECT="${PROJECT_DIR:-/path/to/project/data/pcap}"

mkdir -p "$PROJECT"

for day in Monday Tuesday Wednesday Thursday; do
    pcap_file=$(find "$PCAP_DIR" -maxdepth 1 -iname "${day}*.pcap" | head -1)
    if [ -z "$pcap_file" ]; then
        echo "[$day] PCAP not found, skipping"
        continue
    fi

    outdir="${OUT_BASE}/${day}"
    mkdir -p "$outdir"

    echo "[$day] Analyzing: $(basename "$pcap_file")..."
    snort -r "$pcap_file" -A fast -l "$outdir" -c /etc/snort/snort.conf -q 2>&1 || true

    if [ -f "$outdir/alert" ]; then
        count=$(wc -l < "$outdir/alert")
        echo "[$day] Alerts: $count"
        echo "[$day] Top rules:"
        grep -oP '\[\d+:\d+:\d+\] [^\[]+' "$outdir/alert" | sort | uniq -c | sort -rn | head -5
        # Copy to project directory
        lower_day=$(echo "$day" | tr '[:upper:]' '[:lower:]')
        cp "$outdir/alert" "$PROJECT/${lower_day}_snort_alerts.txt"
    else
        echo "[$day] No alerts generated"
    fi
    echo "---"
done

echo ""
echo "=== ALL DAYS SUMMARY ==="
for day in Monday Tuesday Wednesday Thursday; do
    f="${OUT_BASE}/${day}/alert"
    if [ -f "$f" ]; then
        count=$(wc -l < "$f")
        echo "$day: $count alerts"
    else
        echo "$day: 0 alerts"
    fi
done
# Friday was analyzed separately
f="/tmp/snort_friday/alert"
if [ -f "$f" ]; then
    count=$(wc -l < "$f")
    echo "Friday: $count alerts"
fi

echo ""
echo "=== GRAND TOTAL ==="
total=0
for f in ${OUT_BASE}/*/alert /tmp/snort_friday/alert; do
    if [ -f "$f" ]; then
        c=$(wc -l < "$f")
        total=$((total + c))
    fi
done
echo "Total alerts: $total"
