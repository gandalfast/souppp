package xdpconn

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// sysClassNet is where the kernel lists each interface's active queues.
var sysClassNet = "/sys/class/net"

// getInterfaceQueuesNumber returns the number of queue pairs the relay
// binds a socket to: the active receive and transmit queues, whichever are
// fewer. The kernel lists the active queues in sysfs. Netlink's
// IFLA_NUM_RX_QUEUES and IFLA_NUM_TX_QUEUES are the queues allocated to
// the device, which may be more than the active ones, and binding an
// AF_XDP socket to a queue beyond the active ones fails with EINVAL; the
// receive count is also only reported by kernels built with RPS. Netlink
// is the fallback when sysfs is not available.
func getInterfaceQueuesNumber(interfaceName string) (int, error) {
	if n, err := activeQueues(interfaceName); err == nil {
		return n, nil
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return 0, err
	}
	queues := min(link.Attrs().NumRxQueues, link.Attrs().NumTxQueues)
	if queues < 1 {
		return 0, errors.New("no queues found")
	}
	return queues, nil
}

// activeQueues counts the rx-N and tx-N entries the kernel lists under
// /sys/class/net/<name>/queues, the device's active queues, and returns the
// smaller count.
func activeQueues(interfaceName string) (int, error) {
	entries, err := os.ReadDir(filepath.Join(sysClassNet, interfaceName, "queues"))
	if err != nil {
		return 0, err
	}
	rx, tx := 0, 0
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Name(), "rx-"):
			rx++
		case strings.HasPrefix(e.Name(), "tx-"):
			tx++
		}
	}
	n := min(rx, tx)
	if n < 1 {
		return 0, fmt.Errorf("no active queues listed for %s (rx %d, tx %d)", interfaceName, rx, tx)
	}
	return n, nil
}
