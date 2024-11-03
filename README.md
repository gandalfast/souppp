# souppp
[![Go Reference](https://pkg.go.dev/badge/github.com/gandalfast/souppp.svg)](https://pkg.go.dev/github.com/gandalfast/souppp)

souppp is a library that fully implements PPPoE (and related protocols) in Go:

 * souppp/pppoe: PPPoE RFC2516
 * souppp/ppp: PPP & LCP RFC1661; IPCP RFC1332; IPv6CP RFC5072
 * souppp/auth/pap: PAP RFC1334
 * souppp/auth/chap: CHAP RFC1994
 * souppp/datapath: Linux TUN/TAP interface
 * souppp/client: PPPoE Client (& DHCPv6 over PPP)

> souppp can help you to start a PPPoE client, and currently there isn't any logic to start your own PPPoE/PPP server, you can open a Pull Request if you want to implement this feature

## PPPoE Client

### Features
- Fast Ethernet network communication via eBPF/XDP, which allows the client to bypass the Linux network stack and improve performance
- Option to specify a custom MAC address (reading response frames thanks to network card promiscous mode)
- Option to run multiple PPPoE sessions concurrently, with functions to handle and replace them
- Support IPv4, IPv6 (DHCPv6 over PPP, IA_NA and/or IA_PD) and dual stack
- Option to create corresponding PPP TUN interface in OS, to allow other processes the usage of the established PPP connection
