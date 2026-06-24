package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"rttys/internal/domain/device"
)

// Mirrors the OLD in-memory ordering logic from the device list handler, used
// as the oracle to prove the SQL ListPaged produces identical ordering.
func oracleOrder(items []device.Device, groupName map[int64]string, sortBy, order string) []string {
	asc := !strings.EqualFold(order, "desc")
	idx := make([]int, len(items))
	for i := range idx {
		idx[i] = i
	}
	// items are assumed pre-ordered by id ASC (as the repo loaded them)
	sort.SliceStable(idx, func(a, b int) bool {
		i, j := items[idx[a]], items[idx[b]]
		oi := i.Status == device.StatusOnline
		oj := j.Status == device.StatusOnline
		if oi != oj {
			return oi
		}
		var cmp int
		switch sortBy {
		case "id":
			switch {
			case i.ID < j.ID:
				cmp = -1
			case i.ID > j.ID:
				cmp = 1
			}
		case "ip":
			cmp = strings.Compare(i.IP, j.IP)
		case "mac":
			cmp = strings.Compare(i.Mac, j.Mac)
		case "connectedTime":
			var ti, tj int64
			if i.LastSeenAt != nil {
				ti = *i.LastSeenAt
			}
			if j.LastSeenAt != nil {
				tj = *j.LastSeenAt
			}
			switch {
			case ti < tj:
				cmp = -1
			case ti > tj:
				cmp = 1
			}
		case "description":
			cmp = strings.Compare(i.Description, j.Description)
		case "ddns":
			cmp = strings.Compare(i.Ddns, j.Ddns)
		case "deviceGroupName":
			var gi, gj string
			if i.DeviceGroupID != nil {
				gi = groupName[*i.DeviceGroupID]
			}
			if j.DeviceGroupID != nil {
				gj = groupName[*j.DeviceGroupID]
			}
			cmp = strings.Compare(gi, gj)
		default:
			cmp = strings.Compare(i.Ddns, j.Ddns)
		}
		if cmp == 0 {
			return false
		}
		if asc {
			return cmp < 0
		}
		return cmp > 0
	})
	out := make([]string, len(idx))
	for k, ix := range idx {
		out[k] = items[ix].Ddns
	}
	return out
}

func TestListPagedMatchesLegacyOrdering(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "lp.db")
	db, err := Open(context.Background(), Options{DSN: dsn, MaxOpenConns: 4, MaxIdleConns: 4})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	g := db.Gorm()

	// minimal tables (only what ListPaged reads)
	g.Exec(`CREATE TABLE device_groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`)
	g.Exec(`CREATE TABLE devices (
		id INTEGER PRIMARY KEY, ddns TEXT, mac TEXT, name TEXT DEFAULT '', description TEXT DEFAULT '',
		ip TEXT DEFAULT '', client TEXT DEFAULT '', device_group_id INTEGER, status TEXT, last_seen_at INTEGER)`)
	g.Exec(`INSERT INTO device_groups(id,name) VALUES (1,'Beta'),(2,'alpha'),(3,'Zeta')`)

	// Fixtures: mixed status, null/non-null group, null/value last_seen, ties,
	// case differences, ungrouped devices.
	rows := []struct {
		id      int64
		ddns    string
		mac     string
		ip      string
		desc    string
		group   interface{}
		status  string
		lastSee interface{}
	}{
		{1, "bbb001", "aa11", "10.0.0.5", "Camera", 1, "online", 1000},
		{2, "aaa002", "bb22", "10.0.0.2", "router", nil, "offline", nil},
		{3, "ccc003", "cc33", "10.0.0.9", "camera", 2, "online", 2000},
		{4, "aaa001", "dd44", "10.0.0.2", "router", 3, "online", 1000}, // ties ip & lastseen with others
		{5, "ddd005", "ee55", "10.0.0.1", "", nil, "offline", 500},
		{6, "eee006", "ff66", "10.0.0.7", "Zebra", 1, "online", nil},
		{7, "fff007", "0011", "10.0.0.3", "alpha", 2, "offline", 3000},
		{8, "ggg008", "1122", "10.0.0.8", "Beta", nil, "online", 2000}, // ungrouped, online, ties lastseen
	}
	for _, r := range rows {
		g.Exec(`INSERT INTO devices(id,ddns,mac,ip,description,device_group_id,status,last_seen_at)
			VALUES (?,?,?,?,?,?,?,?)`, r.id, r.ddns, r.mac, r.ip, r.desc, r.group, r.status, r.lastSee)
	}

	// Build the oracle input: all devices ordered by id ASC, plus group names.
	groupName := map[int64]string{1: "Beta", 2: "alpha", 3: "Zeta"}
	var legacyItems []device.Device
	for _, r := range rows {
		var gid *int64
		if r.group != nil {
			v := int64(r.group.(int))
			gid = &v
		}
		var ls *int64
		if r.lastSee != nil {
			v := int64(r.lastSee.(int))
			ls = &v
		}
		legacyItems = append(legacyItems, device.Device{
			ID: r.id, Ddns: r.ddns, Mac: r.mac, IP: r.ip, Description: r.desc,
			DeviceGroupID: gid, Status: device.Status(r.status), LastSeenAt: ls,
		})
	}

	repo := NewDeviceRepo(g)
	fields := []string{"", "id", "ip", "mac", "ddns", "description", "connectedTime", "deviceGroupName"}
	orders := []string{"asc", "desc"}
	for _, f := range fields {
		for _, o := range orders {
			want := oracleOrder(legacyItems, groupName, f, o)
			got, total, err := repo.ListPaged(context.Background(), device.ListQuery{SortBy: f, Order: o})
			if err != nil {
				t.Fatalf("ListPaged(%q,%q): %v", f, o, err)
			}
			if total != int64(len(rows)) {
				t.Errorf("sortBy=%q order=%q: total=%d want=%d", f, o, total, len(rows))
			}
			var gotDdns []string
			for _, it := range got {
				gotDdns = append(gotDdns, it.Ddns)
			}
			if fmt.Sprint(gotDdns) != fmt.Sprint(want) {
				t.Errorf("sortBy=%q order=%q ordering mismatch:\n SQL    = %v\n legacy = %v", f, o, gotDdns, want)
			}
		}
	}

	// group-name join correctness
	got, _, _ := repo.ListPaged(context.Background(), device.ListQuery{SortBy: "id", Order: "asc"})
	for _, it := range got {
		var wantName string
		if it.DeviceGroupID != nil {
			wantName = groupName[*it.DeviceGroupID]
		}
		if it.GroupName != wantName {
			t.Errorf("device %s group name=%q want=%q", it.Ddns, it.GroupName, wantName)
		}
	}
}

func TestListPagedSearchUnassignedPagination(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "lp2.db")
	db, _ := Open(context.Background(), Options{DSN: dsn, MaxOpenConns: 4, MaxIdleConns: 4})
	defer db.Close()
	g := db.Gorm()
	g.Exec(`CREATE TABLE device_groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`)
	g.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY, ddns TEXT, mac TEXT, name TEXT DEFAULT '', description TEXT DEFAULT '',
		ip TEXT DEFAULT '', client TEXT DEFAULT '', device_group_id INTEGER, status TEXT, last_seen_at INTEGER)`)
	g.Exec(`INSERT INTO device_groups(id,name) VALUES (1,'G1')`)
	g.Exec(`INSERT INTO devices(id,ddns,mac,ip,description,device_group_id,status) VALUES
		(1,'zh71fb1','9483c4b71fb1','10.0.0.1','lab',1,'online'),
		(2,'pubacff','9483c4bbacff','10.0.0.2','',NULL,'offline'),
		(3,'aq71029','9483c4a71029','192.168.1.9','Office',NULL,'online'),
		(4,'xy00001','001122334455','10.0.0.4','SEARCHME',1,'offline')`)
	repo := NewDeviceRepo(g)
	ctx := context.Background()

	// search by ddns fragment
	got, total, _ := repo.ListPaged(ctx, device.ListQuery{Search: "zh71"})
	if total != 1 || len(got) != 1 || got[0].Ddns != "zh71fb1" {
		t.Errorf("search zh71: got %d rows total=%d", len(got), total)
	}
	// search by MAC fragment (colon-less, as handler passes it)
	got, total, _ = repo.ListPaged(ctx, device.ListQuery{Search: "9483c4"})
	if total != 3 {
		t.Errorf("search 9483c4: total=%d want 3", total)
	}
	// case-insensitive description search
	got, total, _ = repo.ListPaged(ctx, device.ListQuery{Search: "searchme"})
	if total != 1 || got[0].Ddns != "xy00001" {
		t.Errorf("search searchme: total=%d", total)
	}
	// unassigned only
	got, total, _ = repo.ListPaged(ctx, device.ListQuery{Unassigned: true})
	if total != 2 {
		t.Errorf("unassigned: total=%d want 2", total)
	}
	for _, it := range got {
		if it.DeviceGroupID != nil {
			t.Errorf("unassigned returned grouped device %s", it.Ddns)
		}
	}
	// pagination: pageSize 2 over 4 rows, sorted by id asc (online-first)
	p1, total, _ := repo.ListPaged(ctx, device.ListQuery{SortBy: "id", Order: "asc", Page: 1, PageSize: 2})
	p2, _, _ := repo.ListPaged(ctx, device.ListQuery{SortBy: "id", Order: "asc", Page: 2, PageSize: 2})
	if total != 4 || len(p1) != 2 || len(p2) != 2 {
		t.Fatalf("pagination sizes: total=%d p1=%d p2=%d", total, len(p1), len(p2))
	}
	// online-first: page1 should be the two online devices (ids 1,3)
	if p1[0].Status != device.StatusOnline || p1[1].Status != device.StatusOnline {
		t.Errorf("online-first violated: p1=%v %v", p1[0].Status, p1[1].Status)
	}
}
