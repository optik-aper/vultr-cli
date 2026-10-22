package vpn

import (
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/vultr/govultr/v3"

	"github.com/vultr/vultr-cli/v3/cmd/printer"
	"github.com/vultr/vultr-cli/v3/cmd/utils"
)

// ======================================

// VPNsPrinter ...
type VPNsPrinter struct {
	VPNs []govultr.VPN `json:"vpns"`
	Meta *govultr.Meta `json:"meta"`
}

// JSON ...
func (v *VPNsPrinter) JSON() []byte {
	return printer.MarshalObject(v, "json")
}

// YAML ...
func (v *VPNsPrinter) YAML() []byte {
	return printer.MarshalObject(v, "yaml")
}

// Columns ...
func (v *VPNsPrinter) Columns() [][]string {
	return [][]string{0: {
		"ID",
		"LABEL",
		"PROTOCOL",
		"STATUS",
		"DATE CREATED",
	}}
}

// Data ...
func (v *VPNsPrinter) Data() [][]string {
	if len(v.VPNs) == 0 {
		return [][]string{0: {"---", "---", "---", "---", "---", "---", "---"}}
	}

	var data [][]string
	for i := range v.VPNs {
		data = append(data, []string{
			v.VPNs[i].ID,
			v.VPNs[i].Label,
			v.VPNs[i].Protocol,
			v.VPNs[i].Status,
			v.VPNs[i].DateCreated,
		})
	}

	return data
}

// Paging ...
func (v *VPNsPrinter) Paging() [][]string {
	return printer.NewPagingFromMeta(v.Meta).Compose()
}

// ======================================

// VPNPrinter ...
type VPNPrinter struct {
	VPN *govultr.VPN `json:"vpn"`
}

// JSON ...
func (v *VPNPrinter) JSON() []byte {
	return printer.MarshalObject(v, "json")
}

// YAML ...
func (v *VPNPrinter) YAML() []byte {
	return printer.MarshalObject(v, "yaml")
}

// Columns ...
func (v *VPNPrinter) Columns() [][]string {
	return nil
}

// Data ...
func (v *VPNPrinter) Data() [][]string {
	data := [][]string{
		[]string{"ID", v.VPN.ID},
		[]string{"VPC ID", v.VPN.VPCID},
		[]string{"NAT GATEWAY ID", v.VPN.NATGatewayID},
		[]string{"LABEL", v.VPN.Label},
		[]string{"STATUS", v.VPN.Status},
		[]string{"PROTOCOL", v.VPN.Protocol},
	}

	if len(v.VPN.Subnet) > 0 {
		data = append(data, []string{"SUBNET", fmt.Sprintf("%s/%s", v.VPN.Subnet, strconv.Itoa(v.VPN.SubnetPrefix))})
	} else {
		data = append(data, []string{"SUBNET", "NONE"})
	}

	if len(v.VPN.PublicKey) > 0 {
		data = append(data, []string{"PUBLIC KEY", v.VPN.PublicKey})
	} else {
		data = append(data, []string{"PUBLIC KEY", "NONE"})
	}

	data = append(data,
		[]string{"CURRENT CHARGES",
			strconv.FormatFloat(float64(v.VPN.Billing.Charges), 'f', utils.FloatPrecision, utils.FloatBitDepth),
		},
		[]string{"MONTHLY CHARGES",
			strconv.FormatFloat(float64(v.VPN.Billing.Monthly), 'f', utils.FloatPrecision, utils.FloatBitDepth),
		},
		[]string{"DATE CREATED", v.VPN.DateCreated},
	)

	return data
}

// Paging ...
func (v *VPNPrinter) Paging() [][]string {
	return nil
}

// ======================================

// VPNEndpointsPrinter ...
type VPNEndpointsPrinter struct {
	Endpoints []govultr.VPNEndpoint `json:"endpoints"`
	Meta      *govultr.Meta         `json:"meta"`
}

// JSON ...
func (v *VPNEndpointsPrinter) JSON() []byte {
	return printer.MarshalObject(v, "json")
}

// YAML ...
func (v *VPNEndpointsPrinter) YAML() []byte {
	return printer.MarshalObject(v, "yaml")
}

// Columns ...
func (v *VPNEndpointsPrinter) Columns() [][]string {
	return [][]string{0: {
		"ID",
		"LABEL",
		"DATE CREATED",
		"DATE UPDATED",
	}}
}

// Data ...
func (v *VPNEndpointsPrinter) Data() [][]string {
	if len(v.Endpoints) == 0 {
		return [][]string{0: {"---", "---", "---", "---"}}
	}

	var data [][]string
	for i := range v.Endpoints {
		data = append(data, []string{
			v.Endpoints[i].ID,
			v.Endpoints[i].Label,
			v.Endpoints[i].DateCreated,
			v.Endpoints[i].DateUpdated,
		})
	}

	return data
}

// Paging ...
func (v *VPNEndpointsPrinter) Paging() [][]string {
	return printer.NewPagingFromMeta(v.Meta).Compose()
}

// ======================================

// VPNEndpointPrinter ...
type VPNEndpointPrinter struct {
	Endpoint *govultr.VPNEndpoint `json:"endpoint"`
}

// JSON ...
func (v *VPNEndpointPrinter) JSON() []byte {
	return printer.MarshalObject(v, "json")
}

// YAML ...
func (v *VPNEndpointPrinter) YAML() []byte {
	return printer.MarshalObject(v, "yaml")
}

// Columns ...
func (v *VPNEndpointPrinter) Columns() [][]string {
	return nil
}

// Data ...
func (v *VPNEndpointPrinter) Data() [][]string {
	data := [][]string{
		[]string{"ID", v.Endpoint.ID},
		[]string{"LABEL", v.Endpoint.Label},
		[]string{"IP ADDRESS", v.Endpoint.Config.IPAddress},
	}

	psk, err := base64.StdEncoding.DecodeString(v.Endpoint.Config.PreSharedKey)
	if err != nil {
		printer.Error(fmt.Errorf("error decoding base64 vpn endpoint pre shared key : %v", err))
	}

	data = append(data,
		[]string{"PRE SHARED KEY", string(psk)},
		[]string{"REMOTE IDENTIFIER", v.Endpoint.Config.RemoteIdentifier},
		[]string{" "},
		[]string{"REMOTE SUBNETS"},
	)

	for i := range v.Endpoint.RemoteSubnets {
		data = append(data,
			[]string{fmt.Sprintf("%s/%s",
				v.Endpoint.RemoteSubnets[i].Subnet,
				strconv.Itoa(v.Endpoint.RemoteSubnets[i].Prefix)),
			},
		)
	}

	data = append(data,
		[]string{" "},
		[]string{"DATE CREATED", v.Endpoint.DateCreated},
		[]string{"DATE UPDATED", v.Endpoint.DateUpdated},
	)

	return data
}

// Paging ...
func (v *VPNEndpointPrinter) Paging() [][]string {
	return nil
}

// ======================================

// VPNEndpointConfigPrinter ...
type VPNEndpointConfigPrinter struct {
	Config string `json:"config"`
}

// JSON ...
func (v *VPNEndpointConfigPrinter) JSON() []byte {
	return printer.MarshalObject(v, "json")
}

// YAML ...
func (v *VPNEndpointConfigPrinter) YAML() []byte {
	return printer.MarshalObject(v, "yaml")
}

// Columns ...
func (v *VPNEndpointConfigPrinter) Columns() [][]string {
	return [][]string{0: {"CONFIG"}}
}

// Data ...
func (v *VPNEndpointConfigPrinter) Data() [][]string {
	config, err := base64.StdEncoding.DecodeString(v.Config)
	if err != nil {
		printer.Error(fmt.Errorf("error decoding base64 vpn endpoint config : %v", err))
	}

	return [][]string{0: {string(config)}}
}

// Paging ...
func (v *VPNEndpointConfigPrinter) Paging() [][]string {
	return nil
}
