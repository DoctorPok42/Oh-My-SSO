package notify

import "strings"

// describeUserAgent turns a User-Agent header into something a person
// recognises ("Firefox on Windows"). It is a rough guess for an e-mail, not
// a security decision: the header is chosen by the client and can lie.
// Order matters: Edge and Opera also say "Chrome", Chrome also says "Safari".
func describeUserAgent(ua string) string {
	if ua == "" {
		return ""
	}
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"), strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	case strings.HasPrefix(ua, "curl/"):
		browser = "curl"
	}

	os := ""
	switch {
	case strings.Contains(ua, "iPhone"):
		os = "iPhone"
	case strings.Contains(ua, "iPad"):
		os = "iPad"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "CrOS"):
		os = "ChromeOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return os
	default:
		if r := []rune(ua); len(r) > 60 {
			ua = string(r[:60]) + "…"
		}
		return ua
	}
}

func DescribeUserAgent(ua string) string { return describeUserAgent(ua) }
