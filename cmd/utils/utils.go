// Package utils provides some common utility functions
package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/vultr/vultr-cli/v3/pkg/cli"
)

const (
	PerPageDefault int    = 100
	FloatPrecision int    = 2
	FloatBitDepth  int    = 32
	CIDRRegex      string = `^[0-2]{0,1}[0-9]{0,2}\.[0-2]{0,1}[0-9]{0,2}\.[0-2]{0,1}[0-9]{0,2}\.[0-2]{0,1}[0-9]{0,2}\/[0-3]{0,1}[0-9]$` //nolint:lll
)

// SetOptions initializes values used in all CLI commands
func SetOptions(b *cli.Base, cmd *cobra.Command, args []string) {
	b.Args = args
	b.Printer.Output = viper.GetString("output")
}

// GetFirewallSource parses the source and if empty, returns 'anywhere'
func GetFirewallSource(source string) string {
	if source == "" {
		return "anywhere"
	}
	return source
}

// FormatFirewallNetwork returns the subnet and size of a network in CIDR
// notation
func FormatFirewallNetwork(subnet string, size int) string {
	return fmt.Sprintf("%s/%d", subnet, size)
}

func IsCIDRFormatted(addr string) (bool, error) {
	match, err := regexp.MatchString(CIDRRegex, addr)
	if err != nil {
		return false, err
	}

	return match, nil
}

func SplitCIDRFormat(cidr string) (address *string, mask *int, err error) {
	if ok, err := IsCIDRFormatted(cidr); ok {
		return nil, nil, fmt.Errorf("%q is not an understandable cidr format : %v", cidr, err)
	}

	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("could not parse cidr %q format", cidr)
	}

	subnetMask, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse cidr %q mask", cidr)
	}

	return &parts[0], &subnetMask, nil
}
