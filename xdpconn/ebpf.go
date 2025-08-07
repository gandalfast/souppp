package xdpconn

import (
	"bytes"
	_ "embed"
	"fmt"
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"io"
)

//go:embed xdpethfilter_kern.o
var builtXDPProgBinary []byte

func loadBuiltinEBPFProg() (*xdp.Program, *ebpf.Map, error) {
	return loadEBPFProgViaReader(
		bytes.NewReader(builtXDPProgBinary),
		"xdp_redirect_func",
		"qidconf_map",
		"xsks_map",
		"etype_list",
	)
}

func loadEBPFProgViaReader(r io.ReaderAt, funcname, qidmapname, xskmapname, ethertypemap string) (*xdp.Program, *ebpf.Map, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, nil, err
	}

	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, err
	}

	prog := new(xdp.Program)
	var ok bool
	if prog.Program, ok = col.Programs[funcname]; !ok {
		return nil, nil, fmt.Errorf("can't find a function named %v", funcname)
	}
	if prog.Queues, ok = col.Maps[qidmapname]; !ok {
		return nil, nil, fmt.Errorf("can't find a queue map named %v", qidmapname)
	}
	if prog.Sockets, ok = col.Maps[xskmapname]; !ok {
		return nil, nil, fmt.Errorf("can't find a socket map named %v", xskmapname)
	}

	var elist *ebpf.Map
	if elist, ok = col.Maps[ethertypemap]; !ok {
		return nil, nil, fmt.Errorf("can't find a ether list map named %v", ethertypemap)
	}

	return prog, elist, nil
}
