// Package qa contains repeatable end-to-end / API regression tests that run
// against a LIVE glkvm-cloud deployment (not unit tests). They are gated by the
// QA_TARGET env var, so a normal `go test ./...` skips them.
//
// Run (example, against the CN box):
//
//	QA_TARGET=https://106.55.158.199 \
//	QA_USER=admin QA_PASS='<password>' \
//	QA_DEV_ADDR=106.55.158.199:5912 QA_DEV_TOKEN='<rtty token>' \
//	QA_REAL_DEVID=zh71fb1 QA_REAL_MAC=9483c4b71fb1 \
//	go test ./internal/qa -run TestE2E -v
//
// Assertions are invariant-based (don't depend on exact fixture counts), so the
// suite can be re-run against any environment. L2 device-protocol tests register
// their own throwaway devices (ddns prefix "qae2e") and clean them up via the API.
package qa

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------- config from env ----------

type config struct {
	target   string // user API base, e.g. https://106.55.158.199
	user     string
	pass     string
	devAddr  string // device port host:port (TLS), e.g. 106.55.158.199:5912
	devToken string // rtty registration token
	realID   string // an already-online real device id (optional)
	realMAC  string // its colon-less MAC (optional)
}

func loadConfig(t *testing.T) config {
	c := config{
		target:   os.Getenv("QA_TARGET"),
		user:     os.Getenv("QA_USER"),
		pass:     os.Getenv("QA_PASS"),
		devAddr:  os.Getenv("QA_DEV_ADDR"),
		devToken: os.Getenv("QA_DEV_TOKEN"),
		realID:   os.Getenv("QA_REAL_DEVID"),
		realMAC:  os.Getenv("QA_REAL_MAC"),
	}
	if c.target == "" {
		t.Skip("QA_TARGET not set; skipping live e2e suite")
	}
	if c.user == "" {
		c.user = "admin"
	}
	return c
}

// ---------- HTTP client ----------

type client struct {
	cfg   config
	http  *http.Client
	token string
}

func newClient(cfg config) *client {
	return &client{
		cfg: cfg,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

type apiEnvelope struct {
	OK      bool            `json:"ok"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func (c *client) do(method, path string, body any, auth bool) (int, apiEnvelope, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.cfg.target+path, rdr)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var env apiEnvelope
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env, nil
}

func (c *client) login(t *testing.T) {
	t.Helper()
	_, env, err := c.do("POST", "/api/login", map[string]string{
		"username": c.cfg.user, "password": c.cfg.pass,
	}, false)
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	if !env.OK {
		t.Fatalf("login failed: code=%s msg=%s", env.Code, env.Message)
	}
	var d struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Data, &d); err != nil || d.Token == "" {
		t.Fatalf("login returned no token: %s", string(env.Data))
	}
	c.token = d.Token
}

// ---------- device-list helpers ----------

type devItem struct {
	ID              int64  `json:"id"`
	Ddns            string `json:"ddns"`
	Mac             string `json:"mac"`
	IP              string `json:"ip"`
	Description     string `json:"description"`
	Status          string `json:"status"`
	ConnectedTime   int64  `json:"connectedTime"`
	DeviceGroupID   *int64 `json:"deviceGroupId"`
	DeviceGroupName string `json:"deviceGroupName"`
}

type devList struct {
	Items    []devItem `json:"items"`
	Page     int       `json:"page"`
	PageSize int       `json:"pageSize"`
	Total    int       `json:"total"`
}

func (c *client) listDevices(t *testing.T, query string) devList {
	t.Helper()
	path := "/api/devices"
	if query != "" {
		path += "?" + query
	}
	st, env, err := c.do("GET", path, nil, true)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if !env.OK {
		t.Fatalf("list devices not ok: http=%d code=%s", st, env.Code)
	}
	var d devList
	if err := json.Unmarshal(env.Data, &d); err != nil {
		t.Fatalf("decode device list: %v", err)
	}
	return d
}

// ---------- rtty register helper (device protocol over TLS :5912) ----------

const (
	regAttrDevid = 1
	regAttrDesc  = 2 // MAC carried here
	regAttrToken = 3
)

func tlv(typ byte, v []byte) []byte {
	b := []byte{typ, 0, 0}
	binary.BigEndian.PutUint16(b[1:], uint16(len(v)))
	return append(b, v...)
}
func frame(typ byte, payload []byte) []byte {
	b := []byte{typ, 0, 0}
	binary.BigEndian.PutUint16(b[1:], uint16(len(payload)))
	return append(b, payload...)
}

// registerDevice opens a TLS connection to the device port and performs an rtty
// registration. Returns the live connection (caller must Close) and the server's
// register response code (0 = accepted, non-zero = rejected).
func registerDevice(addr, devid, mac, token string) (net.Conn, byte, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, 0, err
	}
	payload := []byte{5} // proto 5 (TLV)
	payload = append(payload, tlv(regAttrDevid, []byte(devid))...)
	payload = append(payload, tlv(regAttrDesc, []byte(mac))...)
	if token != "" {
		payload = append(payload, tlv(regAttrToken, []byte(token))...)
	}
	if _, err := conn.Write(frame(0 /*register*/, payload)); err != nil {
		conn.Close()
		return nil, 0, err
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	head := make([]byte, 3)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, 0, err
	}
	blen := binary.BigEndian.Uint16(head[1:])
	body := make([]byte, blen)
	io.ReadFull(conn, body)
	conn.SetReadDeadline(time.Time{})
	var code byte
	if len(body) > 0 {
		code = body[0]
	}
	return conn, code, nil
}

// cleanupQADevices deletes every device whose ddns starts with the qa prefix.
func (c *client) cleanupQADevices(t *testing.T) {
	t.Helper()
	list := c.listDevices(t, "q=qae2e&pageSize=500")
	for _, it := range list.Items {
		if strings.HasPrefix(it.Ddns, "qae2e") {
			c.do("DELETE", fmt.Sprintf("/api/devices/%d", it.ID), nil, true)
		}
	}
}

// ---------- the suite ----------

func TestE2E(t *testing.T) {
	cfg := loadConfig(t)
	c := newClient(cfg)

	// ===== A. Auth =====
	t.Run("A_auth", func(t *testing.T) {
		// A5 public auth-config
		st, env, err := c.do("GET", "/auth-config", nil, false)
		if err != nil || !env.OK {
			t.Fatalf("A5 auth-config not ok: http=%d err=%v", st, err)
		}
		// A3 unauthenticated device list rejected
		c.token = ""
		_, env, _ = c.do("GET", "/api/devices?pageSize=1", nil, true)
		if env.OK {
			t.Errorf("A3 expected auth required without token, got ok")
		}
		// A2 wrong password rejected
		_, env, _ = c.do("POST", "/api/login", map[string]string{"username": cfg.user, "password": "definitely-wrong-xyz"}, false)
		if env.OK {
			t.Errorf("A2 expected login failure with wrong password")
		}
	})

	if cfg.pass == "" {
		t.Skip("QA_PASS not set; skipping authenticated tests")
	}
	c.login(t)

	// ===== B. Pagination (invariants) =====
	t.Run("B_pagination", func(t *testing.T) {
		p1 := c.listDevices(t, "page=1&pageSize=10")
		if len(p1.Items) > 10 {
			t.Errorf("B1 page items %d > pageSize 10", len(p1.Items))
		}
		if p1.Total < len(p1.Items) {
			t.Errorf("B1 total %d < page items %d", p1.Total, len(p1.Items))
		}
		if p1.Total <= 10 {
			t.Skip("fewer than 11 devices; pagination cross-page checks skipped")
		}
		p2 := c.listDevices(t, "page=2&pageSize=10")
		if len(p2.Items) > 0 && len(p1.Items) > 0 && p2.Items[0].ID == p1.Items[0].ID {
			t.Errorf("B2 page2 first item equals page1 first item")
		}
		// B3 last page size = remainder
		size := 10
		pages := (p1.Total + size - 1) / size
		last := c.listDevices(t, fmt.Sprintf("page=%d&pageSize=%d", pages, size))
		wantLast := p1.Total - (pages-1)*size
		if last.Total == p1.Total && len(last.Items) != wantLast {
			t.Errorf("B3 last page items=%d want=%d (total=%d)", len(last.Items), wantLast, p1.Total)
		}
		// B4 out-of-range page → empty, total unchanged
		oob := c.listDevices(t, fmt.Sprintf("page=%d&pageSize=%d", pages+50, size))
		if len(oob.Items) != 0 {
			t.Errorf("B4 out-of-range page returned %d items", len(oob.Items))
		}
		if oob.Total != p1.Total {
			t.Errorf("B4 total changed on oob page: %d vs %d", oob.Total, p1.Total)
		}
	})

	// ===== C. Search (invariants) =====
	t.Run("C_search", func(t *testing.T) {
		// C5 no-match → 0
		none := c.listDevices(t, "q=zzz_no_such_device_zzz")
		if none.Total != 0 || len(none.Items) != 0 {
			t.Errorf("C5 non-matching search returned total=%d", none.Total)
		}
		// pick a real device to search for
		base := c.listDevices(t, "page=1&pageSize=1")
		if len(base.Items) == 0 {
			t.Skip("no devices to exercise search")
		}
		d := base.Items[0]
		// C1 search by ddns substring → contains it
		got := c.listDevices(t, "q="+d.Ddns)
		if !containsDdns(got.Items, d.Ddns) {
			t.Errorf("C1 search by ddns %q did not return it", d.Ddns)
		}
		// C2 search by MAC with colons → still matches (colon-strip logic)
		if d.Mac != "" {
			withColons := insertColons(d.Mac)
			gotMac := c.listDevices(t, "q="+withColons)
			if !containsDdns(gotMac.Items, d.Ddns) {
				t.Errorf("C2 search by colon-MAC %q did not return device %q", withColons, d.Ddns)
			}
		}
		// C4 case-insensitive
		gotUpper := c.listDevices(t, "q="+strings.ToUpper(d.Ddns))
		if !containsDdns(gotUpper.Items, d.Ddns) {
			t.Errorf("C4 uppercase search did not match")
		}
	})

	// ===== D. Sort (invariants) =====
	t.Run("D_sort", func(t *testing.T) {
		for _, field := range []string{"ddns", "mac", "ip"} {
			asc := c.listDevices(t, "sortBy="+field+"&order=asc&pageSize=50")
			// online-first must always hold
			if !onlineFirst(asc.Items) {
				t.Errorf("D7 online-first violated when sorting by %s", field)
			}
			// within the same online-bucket, the field is ordered
			if !fieldOrderedWithinBucket(asc.Items, field, true) {
				t.Errorf("D sort by %s asc not ordered within status bucket", field)
			}
			desc := c.listDevices(t, "sortBy="+field+"&order=desc&pageSize=50")
			if !fieldOrderedWithinBucket(desc.Items, field, false) {
				t.Errorf("D sort by %s desc not ordered within status bucket", field)
			}
		}
	})

	// ===== E. Status filter (new feature) =====
	t.Run("E_status_filter", func(t *testing.T) {
		on := c.listDevices(t, "status=online&pageSize=50")
		for _, it := range on.Items {
			if it.Status != "online" {
				t.Errorf("E1 status=online returned a %s device (%s)", it.Status, it.Ddns)
			}
		}
		off := c.listDevices(t, "status=offline&pageSize=50")
		for _, it := range off.Items {
			if it.Status != "offline" {
				t.Errorf("E2 status=offline returned a %s device (%s)", it.Status, it.Ddns)
			}
		}
		all := c.listDevices(t, "pageSize=1")
		// E4 invalid status ignored → behaves like all
		bad := c.listDevices(t, "status=foobar&pageSize=1")
		if bad.Total != all.Total {
			t.Errorf("E4 invalid status changed total: %d vs %d", bad.Total, all.Total)
		}
		// E6 online+offline totals reconcile with all (allowing live drift)
		if on.Total+off.Total > all.Total {
			t.Errorf("E6 online(%d)+offline(%d) > all(%d)", on.Total, off.Total, all.Total)
		}
	})

	// ===== G. Device protocol (L2) =====
	if cfg.devAddr != "" {
		t.Run("G_device_protocol", func(t *testing.T) {
			c.cleanupQADevices(t)
			defer c.cleanupQADevices(t)

			devid := "qae2e_ok"
			mac := "02ffqae20001"
			// G2 empty MAC → rejected
			if conn, code, err := registerDevice(cfg.devAddr, "qae2e_nomac", "", cfg.devToken); err == nil {
				conn.Close()
				if code == 0 {
					t.Errorf("G2 empty-MAC registration was accepted (code 0)")
				}
			}
			// G3 bad token → rejected (only meaningful if server enforces a token)
			if cfg.devToken != "" {
				if conn, code, err := registerDevice(cfg.devAddr, "qae2e_badtok", "02ffqae29999", "wrong-token-xyz"); err == nil {
					conn.Close()
					if code == 0 {
						t.Errorf("G3 bad-token registration was accepted (code 0)")
					}
				}
			}
			// G1 valid registration → device appears online with correct MAC
			conn, code, err := registerDevice(cfg.devAddr, devid, mac, cfg.devToken)
			if err != nil {
				t.Fatalf("G1 register failed: %v", err)
			}
			defer conn.Close()
			if code != 0 {
				t.Fatalf("G1 valid registration rejected, code=%d", code)
			}
			time.Sleep(1500 * time.Millisecond)
			got := c.listDevices(t, "q="+devid)
			var found *devItem
			for i := range got.Items {
				if got.Items[i].Ddns == devid {
					found = &got.Items[i]
				}
			}
			if found == nil {
				t.Fatalf("G1 registered device %q not in list", devid)
			}
			if found.Status != "online" {
				t.Errorf("G1 device status=%q want online", found.Status)
			}
			if found.Mac != mac {
				t.Errorf("G1 device mac=%q want %q", found.Mac, mac)
			}
		})
	}

	// ===== L. Real device E2E (L3) =====
	if cfg.realID != "" {
		t.Run("L_real_device", func(t *testing.T) {
			got := c.listDevices(t, "q="+cfg.realID)
			var found *devItem
			for i := range got.Items {
				if got.Items[i].Ddns == cfg.realID {
					found = &got.Items[i]
				}
			}
			if found == nil {
				t.Fatalf("L1 real device %q not found in list", cfg.realID)
			}
			if found.Status != "online" {
				t.Errorf("L1 real device %q status=%q want online (is the KVM connected?)", cfg.realID, found.Status)
			}
			if cfg.realMAC != "" && found.Mac != cfg.realMAC {
				t.Errorf("L1 real device mac=%q want %q", found.Mac, cfg.realMAC)
			}
		})
	}
}

// ---------- assertion helpers ----------

func containsDdns(items []devItem, ddns string) bool {
	for _, it := range items {
		if it.Ddns == ddns {
			return true
		}
	}
	return false
}

func insertColons(mac string) string {
	if len(mac) != 12 {
		return mac
	}
	var p []string
	for i := 0; i < 12; i += 2 {
		p = append(p, mac[i:i+2])
	}
	return strings.Join(p, ":")
}

func onlineFirst(items []devItem) bool {
	seenOffline := false
	for _, it := range items {
		if it.Status == "online" && seenOffline {
			return false
		}
		if it.Status != "online" {
			seenOffline = true
		}
	}
	return true
}

func fieldVal(it devItem, field string) string {
	switch field {
	case "ddns":
		return it.Ddns
	case "mac":
		return it.Mac
	case "ip":
		return it.IP
	case "description":
		return it.Description
	}
	return ""
}

// fieldOrderedWithinBucket checks the field is sorted within each status bucket
// (online block, then offline block), matching the server's online-first rule.
func fieldOrderedWithinBucket(items []devItem, field string, asc bool) bool {
	buckets := map[string][]string{}
	order := []string{}
	for _, it := range items {
		if _, ok := buckets[it.Status]; !ok {
			order = append(order, it.Status)
		}
		buckets[it.Status] = append(buckets[it.Status], fieldVal(it, field))
	}
	for _, st := range order {
		vals := buckets[st]
		sorted := make([]string, len(vals))
		copy(sorted, vals)
		sort.Slice(sorted, func(i, j int) bool {
			if asc {
				return sorted[i] < sorted[j]
			}
			return sorted[i] > sorted[j]
		})
		for i := range vals {
			if vals[i] != sorted[i] {
				return false
			}
		}
	}
	return true
}

// ============================================================================
// F / H / I  — groups & RBAC, event logs, CRUD. Modular, self-contained tests.
// ============================================================================

type evtItem struct {
	DeviceMac string `json:"deviceMac"`
	EventType string `json:"eventType"`
	CreatedAt int64  `json:"createdAt"`
}

// ---- generic request helpers ----

func (c *client) post(t *testing.T, path string, body any) apiEnvelope {
	t.Helper()
	_, env, err := c.do("POST", path, body, true)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return env
}
func (c *client) put(t *testing.T, path string, body any) apiEnvelope {
	t.Helper()
	_, env, err := c.do("PUT", path, body, true)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	return env
}
func (c *client) del(t *testing.T, path string) {
	t.Helper()
	c.do("DELETE", path, nil, true)
}

func loginClient(t *testing.T, cfg config, user, pass string) *client {
	c := newClient(cfg)
	c.cfg.user, c.cfg.pass = user, pass
	_, env, err := c.do("POST", "/api/login", map[string]string{"username": user, "password": pass}, false)
	if err != nil || !env.OK {
		return nil
	}
	var d struct {
		Token string `json:"token"`
	}
	json.Unmarshal(env.Data, &d)
	if d.Token == "" {
		return nil
	}
	c.token = d.Token
	return c
}

// ---- fixture helpers ----

func (c *client) createDeviceGroup(t *testing.T, name string) int64 {
	t.Helper()
	env := c.post(t, "/api/device-groups", map[string]any{"name": name})
	if !env.OK {
		t.Fatalf("create device-group %q: %s", name, env.Code)
	}
	var d struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(env.Data, &d)
	if d.ID == 0 {
		t.Fatalf("create device-group returned no id")
	}
	return d.ID
}
func (c *client) createUserGroup(t *testing.T, name string) int64 {
	t.Helper()
	env := c.post(t, "/api/user-groups", map[string]any{"name": name})
	if !env.OK {
		t.Fatalf("create user-group %q: %s", name, env.Code)
	}
	var d struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(env.Data, &d)
	return d.ID
}
func (c *client) linkUGtoDG(t *testing.T, ugID int64, dgIDs []int64) {
	t.Helper()
	env := c.put(t, fmt.Sprintf("/api/user-groups/%d/device-groups", ugID), map[string]any{"deviceGroupIds": dgIDs})
	if !env.OK {
		t.Fatalf("link ug %d -> dg: %s", ugID, env.Code)
	}
}
func (c *client) createNormalUser(t *testing.T, username, pass string, ugIDs []int64) {
	t.Helper()
	env := c.post(t, "/api/users", map[string]any{
		"role": "user", "username": username, "password": pass, "repassword": pass, "userGroupIds": ugIDs,
	})
	if !env.OK {
		t.Fatalf("create user %q: %s", username, env.Code)
	}
}
func (c *client) findUserID(t *testing.T, username string) int64 {
	t.Helper()
	_, env, _ := c.do("GET", "/api/users", nil, true)
	var d struct {
		Items []struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
		} `json:"items"`
	}
	json.Unmarshal(env.Data, &d)
	for _, u := range d.Items {
		if u.Username == username {
			return u.ID
		}
	}
	return 0
}
func (c *client) assignDevicesToGroup(t *testing.T, dgID int64, devIDs []int64) {
	t.Helper()
	env := c.put(t, fmt.Sprintf("/api/device-groups/%d/devices", dgID), map[string]any{"deviceIds": devIDs})
	if !env.OK {
		t.Fatalf("assign devices to dg %d: %s", dgID, env.Code)
	}
}
func (c *client) me(t *testing.T) []string {
	t.Helper()
	_, env, _ := c.do("GET", "/api/me", nil, true)
	var d struct {
		Permissions []string `json:"permissions"`
	}
	json.Unmarshal(env.Data, &d)
	return d.Permissions
}
func (c *client) listEventLogs(t *testing.T, mac, types string) []evtItem {
	t.Helper()
	_, env, _ := c.do("GET", fmt.Sprintf("/api/device-event-logs?mac=%s&types=%s&pageSize=50", mac, types), nil, true)
	var d struct {
		Items []evtItem `json:"items"`
	}
	json.Unmarshal(env.Data, &d)
	return d.Items
}

// registerQAOnline registers a qa device and returns the live conn + its DB id.
func (c *client) registerQAOnline(t *testing.T, devid, mac string) (net.Conn, int64) {
	t.Helper()
	conn, code, err := registerDevice(c.cfg.devAddr, devid, mac, c.cfg.devToken)
	if err != nil {
		t.Fatalf("register %s: %v", devid, err)
	}
	if code != 0 {
		conn.Close()
		t.Fatalf("register %s rejected, code=%d", devid, code)
	}
	time.Sleep(1500 * time.Millisecond)
	got := c.listDevices(t, "q="+devid)
	for _, it := range got.Items {
		if it.Ddns == devid {
			return conn, it.ID
		}
	}
	conn.Close()
	t.Fatalf("registered device %s not found in list", devid)
	return nil, 0
}

func findItem(items []devItem, ddns string) *devItem {
	for i := range items {
		if items[i].Ddns == ddns {
			return &items[i]
		}
	}
	return nil
}
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func anyEvent(items []evtItem, mac, typ string) bool {
	for _, e := range items {
		if e.DeviceMac == mac && e.EventType == typ {
			return true
		}
	}
	return false
}

// ===== F. Group filter + RBAC visibility =====
func TestE2E_GroupsRBAC(t *testing.T) {
	cfg := loadConfig(t)
	if cfg.pass == "" {
		t.Skip("QA_PASS required")
	}
	c := newClient(cfg)
	c.login(t)

	t.Run("F2_unassigned", func(t *testing.T) {
		un := c.listDevices(t, "unassigned=true&pageSize=50")
		for _, it := range un.Items {
			if it.DeviceGroupID != nil {
				t.Errorf("F2 unassigned=true returned grouped device %s", it.Ddns)
			}
		}
	})

	if cfg.devAddr == "" {
		t.Skip("QA_DEV_ADDR required for RBAC fixture")
	}
	t.Run("F3_visibility_and_perm_enforcement", func(t *testing.T) {
		c.cleanupQADevices(t)
		defer c.cleanupQADevices(t)
		dgID := c.createDeviceGroup(t, "qae2e_dg")
		ugID := c.createUserGroup(t, "qae2e_ug")
		c.linkUGtoDG(t, ugID, []int64{dgID})
		uname, upass := "qae2e_user", "Qae2ePass123!"
		c.createNormalUser(t, uname, upass, []int64{ugID})
		defer func() {
			if uid := c.findUserID(t, uname); uid > 0 {
				c.del(t, fmt.Sprintf("/api/users/%d", uid))
			}
			c.del(t, fmt.Sprintf("/api/user-groups/%d", ugID))
			c.del(t, fmt.Sprintf("/api/device-groups/%d", dgID))
		}()

		conn, devID := c.registerQAOnline(t, "qae2e_vis", "02ffqaevis01")
		defer conn.Close()
		c.assignDevicesToGroup(t, dgID, []int64{devID})

		nu := loginClient(t, cfg, uname, upass)
		if nu == nil {
			t.Fatal("normal user login failed")
		}
		vl := nu.listDevices(t, "pageSize=100")
		// F3: the user sees their group device, and ONLY devices in their group.
		if findItem(vl.Items, "qae2e_vis") == nil {
			t.Errorf("F3 normal user cannot see their own group's device")
		}
		for _, it := range vl.Items {
			if it.DeviceGroupID == nil || *it.DeviceGroupID != dgID {
				t.Errorf("F3 normal user saw out-of-scope device %s (group=%v)", it.Ddns, it.DeviceGroupID)
			}
		}
		// Permission enforcement must be consistent with declared permissions.
		perms := nu.me(t)
		hasWrite := contains(perms, "device.write")
		_, env, _ := nu.do("DELETE", fmt.Sprintf("/api/devices/%d", devID), nil, true)
		denied := !env.OK
		if hasWrite && denied {
			t.Errorf("RBAC inconsistent: user HAS device.write but delete was denied")
		}
		if !hasWrite && !denied {
			t.Errorf("RBAC inconsistent: user LACKS device.write but delete succeeded")
		}
		t.Logf("normal user perms=%v device.write=%v deleteDenied=%v", perms, hasWrite, denied)
	})
}

// ===== H. Event logs =====
func TestE2E_EventLogs(t *testing.T) {
	cfg := loadConfig(t)
	if cfg.pass == "" || cfg.devAddr == "" {
		t.Skip("QA_PASS + QA_DEV_ADDR required")
	}
	c := newClient(cfg)
	c.login(t)
	c.cleanupQADevices(t)
	defer c.cleanupQADevices(t)

	devid, mac := "qae2e_evt", "02ffqaeevt01"
	conn, _ := c.registerQAOnline(t, devid, mac)

	t.Run("H1_online_event", func(t *testing.T) {
		// poll a few seconds for the online event
		for i := 0; i < 6; i++ {
			if anyEvent(c.listEventLogs(t, mac, "device_online"), mac, "device_online") {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("H1 no device_online event recorded for %s (mac %s)", devid, mac)
	})

	t.Run("H2_offline_event", func(t *testing.T) {
		conn.Close() // clean disconnect -> server should mark offline + log
		for i := 0; i < 12; i++ {
			if anyEvent(c.listEventLogs(t, mac, "device_offline"), mac, "device_offline") {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("H2 no device_offline event within 12s after disconnect")
	})
}

// ===== I. Device CRUD (admin) =====
func TestE2E_CRUD(t *testing.T) {
	cfg := loadConfig(t)
	if cfg.pass == "" || cfg.devAddr == "" {
		t.Skip("QA_PASS + QA_DEV_ADDR required")
	}
	c := newClient(cfg)
	c.login(t)
	c.cleanupQADevices(t)
	defer c.cleanupQADevices(t)

	dgID := c.createDeviceGroup(t, "qae2e_crud_dg")
	defer c.del(t, fmt.Sprintf("/api/device-groups/%d", dgID))

	conn, devID := c.registerQAOnline(t, "qae2e_crud", "02ffqaecrud1")

	t.Run("I1_update_description", func(t *testing.T) {
		env := c.put(t, fmt.Sprintf("/api/devices/%d", devID), map[string]string{"description": "qa-updated-desc"})
		if !env.OK {
			t.Fatalf("I1 update failed: %s", env.Code)
		}
		d := findItem(c.listDevices(t, "q=qae2e_crud").Items, "qae2e_crud")
		if d == nil || d.Description != "qa-updated-desc" {
			t.Errorf("I1 description not updated, got %+v", d)
		}
	})

	t.Run("I3_move_to_group", func(t *testing.T) {
		env := c.post(t, "/api/devices/move-to-device-group", map[string]any{"groupId": dgID, "deviceIds": []int64{devID}})
		if !env.OK {
			t.Fatalf("I3 move failed: %s", env.Code)
		}
		d := findItem(c.listDevices(t, "q=qae2e_crud").Items, "qae2e_crud")
		if d == nil || d.DeviceGroupID == nil || *d.DeviceGroupID != dgID {
			t.Errorf("I3 device not in group %d, got %+v", dgID, d)
		}
	})

	t.Run("I2_delete", func(t *testing.T) {
		conn.Close()
		c.del(t, fmt.Sprintf("/api/devices/%d", devID))
		if findItem(c.listDevices(t, "q=qae2e_crud").Items, "qae2e_crud") != nil {
			t.Errorf("I2 device still present after delete")
		}
	})
}
