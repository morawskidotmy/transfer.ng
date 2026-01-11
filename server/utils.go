package server

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang/gddo/httputil/header"
)

func formatNumber(format string, s uint64) string {
	return renderFloat(format, float64(s))
}

var renderFloatPrecisionMultipliers = [10]float64{
	1,
	10,
	100,
	1000,
	10000,
	100000,
	1000000,
	10000000,
	100000000,
	1000000000,
}

var renderFloatPrecisionRounders = [10]float64{
	0.5,
	0.05,
	0.005,
	0.0005,
	0.00005,
	0.000005,
	0.0000005,
	0.00000005,
	0.000000005,
	0.0000000005,
}

func renderFloat(format string, n float64) string {
	// Handle special cases
	if special := handleSpecialCases(n); special != "" {
		return special
	}

	// Parse format and get formatting parameters
	precision, decimalStr, thousandStr, positiveStr, negativeStr := parseFormatString(format)

	// Generate sign part
	signStr, n := generateSignPart(n, positiveStr, negativeStr)

	// Split number and generate integer/fractional parts
	intf, fracf := math.Modf(n + renderFloatPrecisionRounders[precision])
	intStr := strconv.Itoa(int(intf))

	// Add thousand separator if required
	if len(thousandStr) > 0 {
		intStr = addThousandSeparator(intStr, thousandStr)
	}

	// No fractional part, return early
	if precision == 0 {
		return signStr + intStr
	}

	// Generate fractional part with padding
	fracStr := strconv.Itoa(int(fracf * renderFloatPrecisionMultipliers[precision]))
	if len(fracStr) < precision {
		fracStr = "000000000000000"[:precision-len(fracStr)] + fracStr
	}

	return signStr + intStr + decimalStr + fracStr
}

func handleSpecialCases(n float64) string {
	if math.IsNaN(n) {
		return "NaN"
	}
	if n > math.MaxFloat64 {
		return "Infinity"
	}
	if n < -math.MaxFloat64 {
		return "-Infinity"
	}
	return ""
}

func parseFormatString(format string) (precision int, decimalStr, thousandStr, positiveStr, negativeStr string) {
	precision = 2
	decimalStr = "."
	thousandStr = ","
	positiveStr = ""
	negativeStr = "-"

	if len(format) == 0 {
		return
	}

	precision = 9
	thousandStr = ""

	formatDirectiveChars := []rune(format)
	formatDirectiveIndices := make([]int, 0)
	for i, char := range formatDirectiveChars {
		if char != '#' && char != '0' {
			formatDirectiveIndices = append(formatDirectiveIndices, i)
		}
	}

	if len(formatDirectiveIndices) == 0 {
		return
	}

	if formatDirectiveIndices[0] == 0 {
		if formatDirectiveChars[formatDirectiveIndices[0]] != '+' {
			return
		}
		positiveStr = "+"
		formatDirectiveIndices = formatDirectiveIndices[1:]
	}

	if len(formatDirectiveIndices) >= 2 {
		if (formatDirectiveIndices[1] - formatDirectiveIndices[0]) == 4 {
			thousandStr = string(formatDirectiveChars[formatDirectiveIndices[0]])
			formatDirectiveIndices = formatDirectiveIndices[1:]
		}
	}

	if len(formatDirectiveIndices) == 1 {
		decimalStr = string(formatDirectiveChars[formatDirectiveIndices[0]])
		precision = len(formatDirectiveChars) - formatDirectiveIndices[0] - 1
	}

	return
}

func generateSignPart(n float64, positiveStr, negativeStr string) (string, float64) {
	if n >= 0.000000001 {
		return positiveStr, n
	}
	if n <= -0.000000001 {
		return negativeStr, -n
	}
	return "", 0.0
}

func addThousandSeparator(intStr, thousandStr string) string {
	for i := len(intStr); i > 3; {
		i -= 3
		intStr = intStr[:i] + thousandStr + intStr[i:]
	}
	return intStr
}

// Request.RemoteAddress contains port, which we want to remove i.e.:
// "[::1]:58292" => "[::1]"
func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func acceptsHTML(hdr http.Header) bool {
	actual := header.ParseAccept(hdr, "Accept")

	for _, s := range actual {
		if s.Value == "text/html" {
			return true
		}
	}

	return false
}

func formatSize(size int64) string {
	if size <= 0 {
		return "0 B"
	}

	sizeFloat := float64(size)
	base := math.Log(sizeFloat) / math.Log(1024)

	sizeOn := math.Pow(1024, base-math.Floor(base))

	var round float64
	pow := math.Pow(10, float64(2))
	digit := pow * sizeOn
	round = math.Floor(digit)

	newVal := round / pow

	var suffixes [5]string
	suffixes[0] = "B"
	suffixes[1] = "KB"
	suffixes[2] = "MB"
	suffixes[3] = "GB"
	suffixes[4] = "TB"

	idx := int(math.Floor(base))
	if idx < 0 {
		idx = 0
	} else if idx >= len(suffixes) {
		idx = len(suffixes) - 1
	}

	getSuffix := suffixes[idx]
	return fmt.Sprintf("%s %s", strconv.FormatFloat(newVal, 'f', -1, 64), getSuffix)
}

func formatDurationDays(durationDays time.Duration) string {
	days := int(durationDays.Hours() / 24)
	if days == 1 {
		return fmt.Sprintf("%d day", days)
	}
	return fmt.Sprintf("%d days", days)
}
