package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const (
	blockScore        = uint64(10)
	firewallGroupName = "nwall"
	firewallIPv6Set   = "nwall6"
)

func ApplyFirewall(results []IPResult, whitelist map[netip.Addr]struct{}) error {
	ipv4Addresses := make([]netip.Addr, 0, len(results))
	ipv6Addresses := make([]netip.Addr, 0)

	for _, result := range results {
		if !ShouldBlock(result, whitelist) {
			continue
		}

		if result.Addr.Is4() {
			ipv4Addresses = append(ipv4Addresses, result.Addr)
		} else {
			ipv6Addresses = append(ipv6Addresses, result.Addr)
		}
	}

	err := replaceIPSet(firewallGroupName, "inet", ipv4Addresses)
	if err != nil {
		return err
	}

	err = replaceIPSet(firewallIPv6Set, "inet6", ipv6Addresses)
	if err != nil {
		return err
	}

	err = configureIPTables("iptables", firewallGroupName)
	if err != nil {
		return err
	}

	err = configureIPTables("ip6tables", firewallIPv6Set)
	if err != nil {
		return err
	}

	return nil
}

func ShouldBlock(result IPResult, whitelist map[netip.Addr]struct{}) bool {
	if result.Score < blockScore {
		return false
	}

	_, whitelisted := whitelist[result.Addr.Unmap()]

	return !whitelisted
}

func replaceIPSet(setName, family string, addresses []netip.Addr) error {
	stagingName := setName + "-new"

	err := runCommand(nil, "ipset", "create", setName, "hash:ip", "family", family, "-exist")
	if err != nil {
		return err
	}

	err = runCommand(nil, "ipset", "create", stagingName, "hash:ip", "family", family, "-exist")
	if err != nil {
		return err
	}

	err = runCommand(nil, "ipset", "flush", stagingName)
	if err != nil {
		return err
	}

	if len(addresses) > 0 {
		var input strings.Builder

		for _, addr := range addresses {
			fmt.Fprintf(&input, "add %s %s\n", stagingName, addr)
		}

		err = runCommand(strings.NewReader(input.String()), "ipset", "restore")
		if err != nil {
			return err
		}
	}

	// Swap makes the replacement atomic: nwall never contains a partially populated list and the old contents move into the staging set.
	err = runCommand(nil, "ipset", "swap", setName, stagingName)
	if err != nil {
		return err
	}

	err = runCommand(nil, "ipset", "destroy", stagingName)
	if err != nil {
		return err
	}

	return nil
}

func configureIPTables(binary, setName string) error {
	exists, err := commandSucceeds(binary, "-w", "-S", firewallGroupName)
	if err != nil {
		return err
	}

	if !exists {
		err = runCommand(nil, binary, "-w", "-N", firewallGroupName)
		if err != nil {
			return err
		}
	}

	err = runCommand(nil, binary, "-w", "-F", firewallGroupName)
	if err != nil {
		return err
	}

	err = runCommand(nil, binary, "-w", "-A", firewallGroupName, "-p", "tcp", "-m", "set", "--match-set", setName, "src", "-m", "multiport", "--dports", "80,443", "-j", "DROP")
	if err != nil {
		return err
	}

	err = runCommand(nil, binary, "-w", "-A", firewallGroupName, "-p", "udp", "-m", "set", "--match-set", setName, "src", "-m", "multiport", "--dports", "80,443", "-j", "DROP")
	if err != nil {
		return err
	}

	// Remove duplicate jumps left by previous executions before inserting one clean INPUT entry.
	for {
		exists, err := commandSucceeds(binary, "-w", "-C", "INPUT", "-j", firewallGroupName)
		if err != nil {
			return err
		}

		if !exists {
			break
		}

		err = runCommand(nil, binary, "-w", "-D", "INPUT", "-j", firewallGroupName)
		if err != nil {
			return err
		}
	}

	err = runCommand(nil, binary, "-w", "-I", "INPUT", "1", "-j", firewallGroupName)
	if err != nil {
		return err
	}

	return nil
}

func removeFirewall() error {
	var returnErr error

	err := removeIPTables("iptables")
	if err != nil {
		returnErr = errors.Join(returnErr, err)
	}

	err = removeIPTables("ip6tables")
	if err != nil {
		returnErr = errors.Join(returnErr, err)
	}

	setNames := []string{
		firewallGroupName + "-new",
		firewallIPv6Set + "-new",
		firewallGroupName,
		firewallIPv6Set,
	}

	for _, setName := range setNames {
		err = removeIPSet(setName)
		if err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}

	if returnErr != nil {
		return returnErr
	}

	fmt.Println("Removed all nwall firewall rules and sets.")

	return nil
}

func removeIPTables(binary string) error {
	for {
		exists, err := commandSucceeds(binary, "-w", "-C", "INPUT", "-j", firewallGroupName)
		if err != nil {
			return err
		}

		if !exists {
			break
		}

		err = runCommand(nil, binary, "-w", "-D", "INPUT", "-j", firewallGroupName)
		if err != nil {
			return err
		}
	}

	exists, err := commandSucceeds(binary, "-w", "-S", firewallGroupName)
	if err != nil {
		return err
	}

	if !exists {
		return nil
	}

	err = runCommand(nil, binary, "-w", "-F", firewallGroupName)
	if err != nil {
		return err
	}

	err = runCommand(nil, binary, "-w", "-X", firewallGroupName)
	if err != nil {
		return err
	}

	return nil
}

func removeIPSet(setName string) error {
	output, err := runCommandOutput(nil, "ipset", "list", "-name")
	if err != nil {
		return err
	}

	if !slices.Contains(strings.Fields(string(output)), setName) {
		return nil
	}

	err = runCommand(nil, "ipset", "destroy", setName)
	if err != nil {
		return err
	}

	return nil
}
