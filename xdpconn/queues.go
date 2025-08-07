package xdpconn

import "github.com/safchain/ethtool"

// getInterfaceQueuesNumber uses ethtool to get number of combined queue of the interface, return 1 if failed to get the info
func getInterfaceQueuesNumber(interfaceName string) (int, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return 0, err
	}
	defer ethHandle.Close()

	chans, err := ethHandle.GetChannels(interfaceName)
	if err != nil {
		// Fallback to 1 queue if we are unable to obtain the count
		return 1, nil
	}

	result := int(chans.CombinedCount)
	if result <= 0 {
		result = 1
	}
	return result, nil
}
