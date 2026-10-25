// Package webdav implements the storage-webdav transport class from
// docs/RELAY_DISCOVERY.md: tunnel frames carried as small files through a
// whitelisted cloud storage (Yandex Disk, Nextcloud, any RFC 4918 server).
//
//	device ──HTTPS──► white cloud ◄──HTTPS── relay
//	           (mailboxes: session/up, session/down)
//
// The client PUTs its encrypted stream chunk by chunk into <mailbox>/up;
// the relay picks sessions up by listing <mailbox>, reads the frames and
// PUTs the answer stream into <mailbox>/down. Both sides speak ordinary
// HTTPS to the cloud, so no direct address of the relay is ever visible
// and no VPS is needed on the client path. Latency is seconds (poll
// interval) — the transport targets browsing, RSS and mail, not calls.
//
// The WebDAV client below is deliberately minimal and stdlib-only:
// MKCOL/PUT/GET/DELETE plus a Depth-1 PROPFIND whose multistatus is
// parsed with encoding/xml.
package webdav

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound marks a missing object or collection.
var ErrNotFound = errors.New("webdav: not found")

// Client is a minimal WebDAV client bound to one server endpoint.
type Client struct {
	base *url.URL
	user string
	pass string
	http *http.Client
}

// New parses the endpoint (e.g. "https://webdav.yandex.ru") and returns a
// client with sane timeouts. user may be empty for anonymous servers.
func New(endpoint, user, pass string) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("webdav: bad endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("webdav: endpoint must be http(s): %q", endpoint)
	}
	return &Client{
		base: u,
		user: user,
		pass: pass,
		http: &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// url joins the endpoint with a slash-separated relative path.
func (c *Client) url(path string) string {
	return c.base.String() + "/" + strings.TrimPrefix(path, "/")
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, expect ...int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	if method == "PROPFIND" {
		req.Header.Set("Depth", "1")
		req.Header.Set("Content-Type", "application/xml")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	ok := false
	for _, code := range expect {
		if resp.StatusCode == code {
			ok = true
			break
		}
	}
	if !ok {
		resp.Body.Close()
		return resp, fmt.Errorf("webdav: %s %s: http %d", method, path, resp.StatusCode)
	}
	return resp, nil
}

// Put uploads a file, creating intermediate collections as needed.
func (c *Client) Put(ctx context.Context, path string, data []byte) error {
	resp, err := c.do(ctx, "PUT", path, strings.NewReader(string(data)), 200, 201, 204)
	if err != nil && resp != nil && resp.StatusCode == http.StatusConflict {
		// Some servers refuse PUT into a missing collection.
		resp.Body.Close()
		if merr := c.MkdirAll(ctx, parentDir(path)); merr == nil {
			resp, err = c.do(ctx, "PUT", path, strings.NewReader(string(data)), 200, 201, 204)
		}
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// Get downloads a file. ErrNotFound is returned for missing objects.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	resp, err := c.do(ctx, "GET", path, nil, 200)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

// Delete removes a file or collection; a missing object is not an error.
func (c *Client) Delete(ctx context.Context, path string) error {
	resp, err := c.do(ctx, "DELETE", path, nil, 200, 202, 204)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// Mkcol creates one collection. An existing collection counts as success.
func (c *Client) Mkcol(ctx context.Context, path string) error {
	resp, err := c.do(ctx, "MKCOL", path, nil, 201, 405)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// MkdirAll creates every collection along the path (like os.MkdirAll).
func (c *Client) MkdirAll(ctx context.Context, path string) error {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	cur := ""
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		cur += "/" + seg
		if err := c.Mkcol(ctx, cur); err != nil {
			return err
		}
	}
	return nil
}

type multistatus struct {
	Responses []struct {
		Href string `xml:"href"`
	} `xml:"response"`
}

// List returns the file names directly inside dir (Depth-1 PROPFIND).
// Collection names keep their trailing slash so callers can skip them.
func (c *Client) List(ctx context.Context, dir string) ([]string, error) {
	resp, err := c.do(ctx, "PROPFIND", strings.TrimSuffix(dir, "/")+"/", strings.NewReader(profindBody), 207)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var ms multistatus
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("webdav: bad multistatus: %w", err)
	}
	prefix := strings.TrimSuffix(c.base.Path+"/"+strings.Trim(dir, "/"), "/")
	var out []string
	seen := map[string]bool{}
	for _, r := range ms.Responses {
		href, uerr := url.PathUnescape(r.Href)
		if uerr != nil {
			continue
		}
		// Narrow the server path down to the child name. Servers return
		// absolute paths (/box/up/0001.chunk), sometimes fully qualified
		// URLs — strip the scheme+host part first in that case.
		if i := strings.Index(href, "://"); i >= 0 {
			if j := strings.Index(href[i+3:], "/"); j >= 0 {
				href = href[i+3+j:]
			}
		}
		if !strings.HasPrefix(href, prefix) {
			continue
		}
		name := strings.TrimPrefix(href[len(prefix):], "/")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

const profindBody = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>`

// parentDir returns the collection part of a slash-separated path.
func parentDir(path string) string {
	i := strings.LastIndexByte(strings.TrimSuffix(path, "/"), '/')
	if i < 0 {
		return ""
	}
	return path[:i]
}
