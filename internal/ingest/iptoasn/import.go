// Package iptoasn imports the published local IP-to-ASN interval files.
package iptoasn

import (
	"bufio"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

const maxInputBytes = 64 << 20

// Metadata identifies the exact archived upstream input.
type Metadata struct{ Revision, Digest string }

// Interval is an inclusive family-specific address interval.
type Interval struct {
	Start, End               netip.Addr
	ASN                      uint32
	CountryCode, Description string
	SourceID, RecordRef      string
	Revision, Digest         string
}

// ParseV4 parses the unsigned-integer IPv4 TSV form.
func ParseV4(data []byte, metadata Metadata) ([]Interval, error) { return parse(data, true, metadata) }

// ParseV6 parses the textual IPv6 TSV form.
func ParseV6(data []byte, metadata Metadata) ([]Interval, error) { return parse(data, false, metadata) }

func parse(data []byte, v4 bool, metadata Metadata) ([]Interval, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty IPtoASN input")
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("IPtoASN input exceeds %d byte limit", maxInputBytes)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var intervals []Interval
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == "" {
			return nil, fmt.Errorf("line %d: blank lines are not permitted", line)
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 5 {
			return nil, fmt.Errorf("line %d: expected five TSV fields", line)
		}
		start, err := parseAddress(fields[0], v4)
		if err != nil {
			return nil, fmt.Errorf("line %d start: %w", line, err)
		}
		end, err := parseAddress(fields[1], v4)
		if err != nil {
			return nil, fmt.Errorf("line %d end: %w", line, err)
		}
		if start.Compare(end) > 0 {
			return nil, fmt.Errorf("line %d: interval end precedes start", line)
		}
		asn, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("line %d ASN: %w", line, err)
		}
		interval := Interval{Start: start, End: end, ASN: uint32(asn), CountryCode: fields[3], Description: fields[4], SourceID: sourceID(v4), RecordRef: strconv.Itoa(line), Revision: metadata.Revision, Digest: metadata.Digest}
		if len(intervals) > 0 && intervals[len(intervals)-1].End.Compare(start) >= 0 {
			return nil, fmt.Errorf("line %d: interval overlaps or is unordered", line)
		}
		intervals = append(intervals, interval)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read IPtoASN input: %w", err)
	}
	if len(intervals) == 0 {
		return nil, fmt.Errorf("IPtoASN input contains no intervals")
	}
	return intervals, nil
}
func sourceID(v4 bool) string {
	if v4 {
		return "iptoasn-v4"
	}
	return "iptoasn-v6"
}
func parseAddress(raw string, v4 bool) (netip.Addr, error) {
	if v4 {
		n, e := strconv.ParseUint(raw, 10, 32)
		if e != nil {
			return netip.Addr{}, e
		}
		if n > math.MaxUint32 {
			return netip.Addr{}, fmt.Errorf("IPv4 integer out of range")
		}
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), nil
	}
	a, e := netip.ParseAddr(raw)
	if e != nil {
		return netip.Addr{}, e
	}
	if a.Is4() {
		return netip.Addr{}, fmt.Errorf("expected IPv6 address")
	}
	return a, nil
}
