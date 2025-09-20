package xdpconn

import (
	"errors"
	"github.com/vishvananda/netlink"
)

func getInterfaceQueuesNumber(interfaceName string) (int, error) {
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
