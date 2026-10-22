package xdpconn

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSysfs builds a /sys/class/net replica with the given active queue
// entries for one interface and points the package at it for the test.
func fakeSysfs(t *testing.T, ifname string, entries ...string) {
	t.Helper()
	root := t.TempDir()
	if ifname != "" {
		dir := filepath.Join(root, ifname, "queues")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Mkdir(filepath.Join(dir, e), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	old := sysClassNet
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = old })
}

// TestActiveQueuesCountsTheActivePairs checks that the queue count is the
// number of receive and transmit queues the kernel lists as active, the
// smaller of the two, which is what an AF_XDP socket may bind to.
func TestActiveQueuesCountsTheActivePairs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		want    int
	}{
		{"two pairs", []string{"rx-0", "rx-1", "tx-0", "tx-1"}, 2},
		{"more receive than transmit", []string{"rx-0", "rx-1", "rx-2", "rx-3", "tx-0"}, 1},
		{"more transmit than receive", []string{"rx-0", "tx-0", "tx-1", "tx-2"}, 1},
		{"other entries ignored", []string{"rx-0", "tx-0", "power", "uevent"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeSysfs(t, "gotest0", tc.entries...)
			n, err := activeQueues("gotest0")
			if err != nil {
				t.Fatal(err)
			}
			if n != tc.want {
				t.Fatalf("activeQueues = %d, want %d", n, tc.want)
			}
		})
	}
}

// TestActiveQueuesWithoutAnyFails checks that an interface listing no
// active queue in one direction, or absent from sysfs, is an error rather
// than zero.
func TestActiveQueuesWithoutAnyFails(t *testing.T) {
	fakeSysfs(t, "gotest0", "rx-0", "rx-1")
	if n, err := activeQueues("gotest0"); err == nil {
		t.Fatalf("activeQueues with no transmit queue = %d, nil; want an error", n)
	}
	if n, err := activeQueues("gotest-missing"); err == nil {
		t.Fatalf("activeQueues of an interface absent from sysfs = %d, nil; want an error", n)
	}
}

// TestGetInterfaceQueuesNumberPrefersActiveQueues checks that the count
// the relay binds its sockets by is the active one from sysfs, so netlink,
// which reports the allocated queues, is not consulted when sysfs lists
// them: the interface here has no netlink link at all.
func TestGetInterfaceQueuesNumberPrefersActiveQueues(t *testing.T) {
	fakeSysfs(t, "gotest-nolink", "rx-0", "rx-1", "rx-2", "tx-0", "tx-1", "tx-2")
	n, err := getInterfaceQueuesNumber("gotest-nolink")
	if err != nil {
		t.Fatalf("getInterfaceQueuesNumber: %v", err)
	}
	if n != 3 {
		t.Fatalf("getInterfaceQueuesNumber = %d, want the 3 active pairs", n)
	}
}

// TestGetInterfaceQueuesNumberUnknownInterface checks that an interface
// known to neither sysfs nor netlink is an error.
func TestGetInterfaceQueuesNumberUnknownInterface(t *testing.T) {
	fakeSysfs(t, "")
	if n, err := getInterfaceQueuesNumber("gotest-nolink"); err == nil {
		t.Fatalf("getInterfaceQueuesNumber of an unknown interface = %d, nil; want an error", n)
	}
}
