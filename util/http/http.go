package http

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// max number of chunks a cookie can be broken into. To be compatible with
// widest range of browsers, we shouldn't create more than 30 cookies per domain
<<<<<<< HEAD
const maxCookieNumber = 5
const maxCookieLength = 4093
=======
const maxNumber = 5
const maxLength = 4093
>>>>>>> efe7ebb3 (fix: support longer cookie)

// MakeCookieMetadata generates a string representing a Web cookie.  Yum!
func MakeCookieMetadata(key, value string, flags ...string) ([]string, error) {
	attributes := strings.Join(flags, "; ")

<<<<<<< HEAD
	// cookie: name=value; attributes and key: key-(i) e.g. argocd.token-1
	maxValueLength := maxCookieValueLength(key, attributes)
	numberOfCookies := int(math.Ceil(float64(len(value)) / float64(maxValueLength)))
	if numberOfCookies > maxCookieNumber {
		return nil, fmt.Errorf("invalid cookie value, at %d long it is longer than the max length of %d", len(value), maxValueLength*maxCookieNumber)
=======
	// cookie: name=value; attributes and key: key-(i) e.g. argocd.token-0
	maxValueLength := maxValueLength(key, attributes)
	numberOfCookies := int(math.Ceil(float64(len(value)) / float64(maxValueLength)))
	if numberOfCookies > maxNumber {
		return nil, fmt.Errorf("invalid cookie value, at %d long it is longer than the max length of %d", len(value), maxValueLength*maxNumber)
>>>>>>> efe7ebb3 (fix: support longer cookie)
	}

	return splitCookie(key, value, attributes), nil
}

// browser has limit on size of cookie, currently 4kb. In order to
// support cookies longer than 4kb, we split cookie into multiple 4kb chunks.
<<<<<<< HEAD
// first chunk will be of format argocd.token=<numberOfChunks>:token; attributes
func splitCookie(key, value, attributes string) []string {
	var cookies []string
	valueLength := len(value)
	// cookie: name=value; attributes and key: key-(i) e.g. argocd.token-1
	maxValueLength := maxCookieValueLength(key, attributes)
	numberOfChunks := int(math.Ceil(float64(valueLength) / float64(maxValueLength)))

=======
func splitCookie(key, value, attributes string) []string {
	var cookies []string
	valueLength := len(value)

	// cookie: name=value; attributes and key: key-(i) e.g. argocd.token-0
	maxValueLength := maxValueLength(key, attributes)
>>>>>>> efe7ebb3 (fix: support longer cookie)
	var end int
	for i, j := 0, 0; i < valueLength; i, j = i+maxValueLength, j+1 {
		end = i + maxValueLength
		if end > valueLength {
			end = valueLength
		}
<<<<<<< HEAD

		var cookie string
		if j == 0 && numberOfChunks == 1 {
			cookie = fmt.Sprintf("%s=%s", key, value[i:end])
		} else if j == 0 {
			cookie = fmt.Sprintf("%s=%d:%s", key, numberOfChunks, value[i:end])
		} else {
			cookie = fmt.Sprintf("%s-%d=%s", key, j, value[i:end])
		}
		if attributes != "" {
			cookie = fmt.Sprintf("%s; %s", cookie, attributes)
		}
		cookies = append(cookies, cookie)
=======
		if attributes == "" {
			cookies = append(cookies, fmt.Sprintf("%s-%d=%s", key, j, value[i:end]))
		} else {
			cookies = append(cookies, fmt.Sprintf("%s-%d=%s; %s", key, j, value[i:end], attributes))
		}
>>>>>>> efe7ebb3 (fix: support longer cookie)
	}
	return cookies
}

<<<<<<< HEAD
// JoinCookies combines chunks of cookie based on key as prefix. It returns cookie
// value as string. cookieString is of format key1=value1; key2=value2; key3=value3
// first chunk will be of format argocd.token=<numberOfChunks>:token; attributes
func JoinCookies(key string, cookieList []*http.Cookie) (string, error) {
	cookies := make(map[string]string)
	for _, cookie := range cookieList {
		if !strings.HasPrefix(cookie.Name, key) {
			continue
		}
		cookies[cookie.Name] = cookie.Value
	}

	var sb strings.Builder
	var numOfChunks int
	var err error
	var token string
	var ok bool

	if token, ok = cookies[key]; !ok {
		return "", fmt.Errorf("failed to retrieve cookie %s", key)
	}
	parts := strings.Split(token, ":")

	if len(parts) == 2 {
		if numOfChunks, err = strconv.Atoi(parts[0]); err != nil {
			return "", err
		}
		sb.WriteString(parts[1])
	} else if len(parts) == 1 {
		numOfChunks = 1
		sb.WriteString(parts[0])
	} else {
		return "", fmt.Errorf("invalid cookie for key %s", key)
	}

	for i := 1; i < numOfChunks; i++ {
		sb.WriteString(cookies[fmt.Sprintf("%s-%d", key, i)])
	}
	return sb.String(), nil
}

func maxCookieValueLength(key, attributes string) int {
	if len(attributes) > 0 {
		return maxCookieLength - (len(key) + 3) - (len(attributes) + 2)
	}
	return maxCookieLength - (len(key) + 3)
=======
// JoinCookies combines chunks of cookie based on key as prefix.
// It returns cookie value as string. cookieString is of format
// key1=value1; key2=value2; key3=value3
func JoinCookies(key string, cookieString string) string {
	cookies := make(map[string]string)
	for _, cookie := range strings.Split(cookieString, ";") {
		parts := strings.Split(cookie, "=")
		cookies[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	var sb strings.Builder
	for i := 0; i < len(cookies); i++ {
		splitKey := fmt.Sprintf("%s-%d", key, i)
		sb.WriteString(cookies[splitKey])
	}
	return sb.String()
}

func maxValueLength(key, attributes string) int {
	if len(attributes) > 0 {
		return maxLength - (len(key) + 3) - (len(attributes) + 2)
	}
	return maxLength - (len(key) + 3)
>>>>>>> efe7ebb3 (fix: support longer cookie)
}

// DebugTransport is a HTTP Client Transport to enable debugging
type DebugTransport struct {
	T http.RoundTripper
}

func (d DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.T.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}
