// Package vpn providers functionality for the CLI to control VPNs
package vpn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vultr/govultr/v3"
	"github.com/vultr/vultr-cli/v3/cmd/printer"
	"github.com/vultr/vultr-cli/v3/cmd/utils"
	"github.com/vultr/vultr-cli/v3/pkg/cli"
)

var (
	long    = ``
	example = ``

	listLong    = ``
	listExample = ``

	getLong    = ``
	getExample = ``

	createLong    = ``
	createExample = ``

	updateLong    = ``
	updateExample = ``

	deleteLong    = ``
	deleteExample = ``

	endpointLong    = ``
	endpointExample = ``

	listEndpointsLong    = ``
	listEndpointsExample = ``

	getEndpointLong    = ``
	getEndpointExample = ``

	createEndpointLong    = ``
	createEndpointExample = ``

	updateEndpointLong    = ``
	updateEndpointExample = ``

	deleteEndpointLong    = ``
	deleteEndpointExample = ``

	configEndpointLong    = ``
	configEndpointExample = ``
)

// NewCmdVPN provides the CLI command for VPN functions
func NewCmdVPN(base *cli.Base) *cobra.Command { //nolint:gocyclo,funlen
	o := &options{Base: base}

	cmd := &cobra.Command{
		Use:     "vpn",
		Short:   "Commands to manage VPNs",
		Long:    long,
		Example: example,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			utils.SetOptions(o.Base, cmd, args)
			if !o.Base.HasAuth() {
				return errors.New(utils.APIKeyError)
			}
			return nil
		},
	}

	// List
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"l"},
		Short:   "List all VPNs",
		Long:    listLong,
		Example: listExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Base.Options = utils.GetPaging(cmd)

			vpns, meta, err := o.list()
			if err != nil {
				return fmt.Errorf("error retrieving vpn list : %v", err)
			}

			data := &VPNsPrinter{VPNs: vpns, Meta: meta}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	list.Flags().StringP("cursor", "c", "", "(optional) Cursor for paging.")
	list.Flags().IntP(
		"per-page",
		"p",
		utils.PerPageDefault,
		fmt.Sprintf(
			"(optional) Number of items requested per page. Default is %d and Max is 500.",
			utils.PerPageDefault,
		),
	)

	// Get
	get := &cobra.Command{
		Use:     "get <VPN ID>",
		Aliases: []string{"g"},
		Short:   "Get a VPN",
		Long:    getLong,
		Example: getExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide a VPN ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			vpn, err := o.get()
			if err != nil {
				return fmt.Errorf("error retrieving vpn : %v", err)
			}

			data := &VPNPrinter{VPN: vpn}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	// Create
	create := &cobra.Command{
		Use:     "create",
		Aliases: []string{"c"},
		Short:   "Create a VPN",
		Long:    createLong,
		Example: createExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			label, err := cmd.Flags().GetString("label")
			if err != nil {
				return fmt.Errorf("error parsing flag 'label' for vpn create : %v", err)
			}

			protocol, err := cmd.Flags().GetString("protocol")
			if err != nil {
				return fmt.Errorf("error parsing flag 'protocol' for vpn create : %v", err)
			}

			vpcID, err := cmd.Flags().GetString("vpc-id")
			if err != nil {
				return fmt.Errorf("error parsing flag 'vpc_id' for vpn create : %v", err)
			}

			subnet, err := cmd.Flags().GetString("subnet")
			if err != nil {
				return fmt.Errorf("error parsing flag 'subnet' for vpn create : %v", err)
			}

			o.CreateReq = &govultr.VPNCreateReq{
				Label:    label,
				Protocol: protocol,
				VPCID:    vpcID,
			}

			if cmd.Flags().Changed("subnet") {
				addr, mask, err := utils.SplitCIDRFormat(subnet)
				if err != nil {
					return err
				}

				o.CreateReq.Subnet = *addr
				o.CreateReq.SubnetPrefix = *mask
			}

			vpn, err := o.create()
			if err != nil {
				return fmt.Errorf("error creating vpn : %v", err)
			}

			data := &VPNPrinter{VPN: vpn}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	create.Flags().StringP("label", "l", "", "The label to apply to the VPN")
	if err := create.MarkFlagRequired("label"); err != nil {
		fmt.Printf("error marking vpn create 'label' flag required: %v", err)
		os.Exit(1)
	}

	create.Flags().StringP("protocol", "p", "",
		"The protocol to use for the VPN. One of `wireguard`, `openvpn`, or `ipsec`",
	)
	if err := create.MarkFlagRequired("protocol"); err != nil {
		fmt.Printf("error marking vpn create 'protocol' flag required: %v", err)
		os.Exit(1)
	}

	create.Flags().StringP("vpc-id", "v", "",
		"The ID of the VPC on which to add the VPN. Must be NAT gateway enabled",
	)
	if err := create.MarkFlagRequired("vpc-id"); err != nil {
		fmt.Printf("error marking vpn create 'vpc-id' flag required: %v", err)
		os.Exit(1)
	}

	create.Flags().StringP("subnet", "s", "",
		"(optional) The IPv4 network for the VPN. Must not overlap with other subnets on the VPC",
	)

	create.Flags().IntP("size", "z", 0, "(optional) The number of bits for the subnet mask. Min 16; Max 28")

	// Update
	update := &cobra.Command{
		Use:     "update <VPN ID>",
		Aliases: []string{"u"},
		Short:   "Update a VPN",
		Long:    updateLong,
		Example: updateExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provid a VPN ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			label, err := cmd.Flags().GetString("label")
			if err != nil {
				return fmt.Errorf("error parsing flag 'label' for vpn update : %v", err)
			}

			if cmd.Flags().Changed("label") {
				o.UpdateReq = &govultr.VPNUpdateReq{
					Label: label,
				}
			}

			vpn, err := o.update()
			if err != nil {
				return fmt.Errorf("error updating vpc : %v", err)
			}

			data := &VPNPrinter{VPN: vpn}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	update.Flags().StringP("label", "l", "", "The label of the VPN")
	if err := update.MarkFlagRequired("label"); err != nil {
		fmt.Printf("error marking vpn update 'label' flag required: %v", err)
		os.Exit(1)
	}

	// Delete
	del := &cobra.Command{
		Use:     "delete <VPN ID>",
		Aliases: []string{"destroy", "d"},
		Short:   "Delete a VPN",
		Long:    deleteLong,
		Example: deleteExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide a VPN ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.del(); err != nil {
				return fmt.Errorf("error deleting vpn : %v", err)
			}

			o.Base.Printer.Display(printer.Info("vpn has been deleted"), nil)

			return nil
		},
	}

	// Endpoint
	endpoint := &cobra.Command{
		Use:     "endpoint",
		Short:   "Commands to manage VPN endpoints",
		Long:    endpointLong,
		Example: endpointExample,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			utils.SetOptions(o.Base, cmd, args)
			if !o.Base.HasAuth() {
				return errors.New(utils.APIKeyError)
			}
			return nil
		},
	}

	// List Endpoints
	listEndpoints := &cobra.Command{
		Use:     "list <VPN ID>",
		Aliases: []string{""},
		Short:   "List all VPN endpoints",
		Long:    listEndpointsLong,
		Example: listEndpointsExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provid a VPN ID")
			}

			o.Base.Options = utils.GetPaging(cmd)

			ends, meta, err := o.listEndpoints()
			if err != nil {
				return fmt.Errorf("error retrieving vpn endpoint list : %v", err)
			}

			data := &VPNEndpointsPrinter{Endpoints: ends, Meta: meta}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	listEndpoints.Flags().StringP("cursor", "c", "", "(optional) Cursor for paging.")
	listEndpoints.Flags().IntP(
		"per-page",
		"p",
		utils.PerPageDefault,
		fmt.Sprintf(
			"(optional) Number of items requested per page. Default is %d and Max is 500.",
			utils.PerPageDefault,
		),
	)

	// Get Endpoint
	getEndpoint := &cobra.Command{
		Use:     "get <VPN ID> <endpoint ID>",
		Aliases: []string{""},
		Short:   "Get a VPN endpoint",
		Long:    getEndpointLong,
		Example: getEndpointExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("please provide a VPN ID and an endpoint ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			end, err := o.getEndpoint()
			if err != nil {
				return fmt.Errorf("error retrieving vpn endpoint : %v", err)
			}

			data := &VPNEndpointPrinter{Endpoint: end}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	// Create Endpoint
	createEndpoint := &cobra.Command{
		Use:     "create <VPN ID>",
		Aliases: []string{""},
		Short:   "Create a VPN endpoint",
		Long:    createEndpointLong,
		Example: createEndpointExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide a VPN ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			label, err := cmd.Flags().GetString("label")
			if err != nil {
				return fmt.Errorf("error parsing flag 'label' for vpn endpoint create : %v", err)
			}

			ipAddress, err := cmd.Flags().GetString("ip-address")
			if err != nil {
				return fmt.Errorf("error parsing flag 'ip-address' for vpn endpoint create : %v", err)
			}

			psk, err := cmd.Flags().GetString("pre-shared-key")
			if err != nil {
				return fmt.Errorf("error parsing flag 'pre-shared-key' for vpn endpoint create : %v", err)
			}

			pskB64, err := cmd.Flags().GetString("pre-shared-key-b64")
			if err != nil {
				return fmt.Errorf("error parsing flag 'pre-shared-key-b64' for vpn endpoint create : %v", err)
			}

			var preSharedKey string
			if len(psk) > 0 {
				preSharedKey = base64.StdEncoding.EncodeToString([]byte(psk))
			}

			if len(pskB64) > 0 {
				preSharedKey = pskB64
			}

			o.EndpointReq = &govultr.VPNEndpointReq{
				Label:        label,
				IPAddress:    ipAddress,
				PreSharedKey: preSharedKey,
			}

			subnets, err := cmd.Flags().GetStringArray("remote-subnet")
			if err != nil {
				return fmt.Errorf("error parsing flag 'remote-subnet' for vpn endpoint create : %v", err)
			}

			if len(subnets) > 0 {
				subs, errSubs := formatRemoteSubnets(subnets)
				if errSubs != nil {
					return fmt.Errorf("error formatting vpn endpoint remote-subnets : %v", errSubs)
				}

				o.EndpointReq.RemoteSubnets = subs
			}

			end, err := o.createEndpoint()
			if err != nil {
				return fmt.Errorf("error creating vpn endpoint : %v", err)
			}

			data := &VPNEndpointPrinter{Endpoint: end}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	createEndpoint.Flags().String("label", "", "The label to apply to the endpoint")
	if err := create.MarkFlagRequired("label"); err != nil {
		fmt.Printf("error marking vpn endpoint create 'label' flag required: %v", err)
		os.Exit(1)
	}

	createEndpoint.Flags().String("ip-address", "",
		"(optional, required if protocol is 'ipsec') The IPv4 address of the endpoint",
	)

	createEndpoint.Flags().String("pre-shared-key", "", "(optional) The 32byte key with which to create the endpoint")
	createEndpoint.Flags().String("pre-shared-key-b64", "", "(optional) The 32byte base64 encoded key with which to create the endpoint")
	createEndpoint.MarkFlagsMutuallyExclusive("pre-shared-key", "pre-shared-key-b64")

	createEndpoint.Flags().StringArray("remote-subnet", nil,
		`(only required when protocol is 'ipsec') The remote subnet(s) to deploy on the endpoint. 
One subnet per flag using CIDR formatting (eg.  172.16.0.0/16).`,
	)

	// Update Endpoint
	updateEndpoint := &cobra.Command{
		Use:     "update <VPN ID> <endpoint ID>",
		Aliases: []string{""},
		Short:   "Update a VPN endpoint",
		Long:    updateEndpointLong,
		Example: updateEndpointExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("please provide a VPN ID and an endpoint ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			label, err := cmd.Flags().GetString("label")
			if err != nil {
				return fmt.Errorf("error parsing flag 'label' for vpn endpoint update : %v", err)
			}

			ipAddress, err := cmd.Flags().GetString("ip-address")
			if err != nil {
				return fmt.Errorf("error parsing flag 'ip-address' for vpn endpoint update : %v", err)
			}

			psk, err := cmd.Flags().GetString("pre-shared-key")
			if err != nil {
				return fmt.Errorf("error parsing flag 'pre-shared-key' for vpn endpoint update : %v", err)
			}

			pskB64, err := cmd.Flags().GetString("pre-shared-key-b64")
			if err != nil {
				return fmt.Errorf("error parsing flag 'pre-shared-key-b64' for vpn endpoint update : %v", err)
			}

			o.EndpointReq = &govultr.VPNEndpointReq{}

			if cmd.Flags().Changed("label") {
				o.EndpointReq.Label = label
			}

			if cmd.Flags().Changed("ip-address") {
				o.EndpointReq.IPAddress = ipAddress
			}

			if cmd.Flags().Changed("pre-shared-key") {
				o.EndpointReq.PreSharedKey = base64.StdEncoding.EncodeToString([]byte(psk))
			}

			if cmd.Flags().Changed("pre-shared-key-b64") {
				o.EndpointReq.PreSharedKey = pskB64
			}

			if cmd.Flags().Changed("remote-subnet") {
				subnets, err := cmd.Flags().GetStringArray("remote-subnet")
				if err != nil {
					return fmt.Errorf("error parsing flag 'remote-subnet' for vpn endpoint update : %v", err)
				}

				if len(subnets) > 0 {
					subs, errSubs := formatRemoteSubnets(subnets)
					if errSubs != nil {
						return fmt.Errorf("error formatting vpn endpoint remote-subnets : %v", errSubs)
					}

					o.EndpointReq.RemoteSubnets = subs
				}
			}

			end, err := o.updateEndpoint()
			if err != nil {
				return fmt.Errorf("error updating vpn endpoint : %v", err)
			}

			data := &VPNEndpointPrinter{Endpoint: end}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	updateEndpoint.Flags().String("label", "", "The label to apply to the endpoint")
	if err := update.MarkFlagRequired("label"); err != nil {
		fmt.Printf("error marking vpn endpoint update 'label' flag required: %v", err)
		os.Exit(1)
	}

	updateEndpoint.Flags().String("ip-address", "",
		"(optional, required if protocol is 'ipsec') The IPv4 address of the endpoint",
	)

	updateEndpoint.Flags().String("pre-shared-key", "", "(optional) The 32byte key with which to create the endpoint")
	updateEndpoint.Flags().String("pre-shared-key-b64", "", "(optional) The 32byte base64 encoded key with which to create the endpoint")
	updateEndpoint.MarkFlagsMutuallyExclusive("pre-shared-key", "pre-shared-key-b64")

	updateEndpoint.Flags().StringArray("remote-subnet", nil,
		`(only required when protocol is 'ipsec') The remote subnet(s) to deploy on the endpoint. 
One subnet per flag using CIDR formatting (eg.  172.16.0.0/16).`,
	)

	// Delete Endpoint
	delEndpoint := &cobra.Command{
		Use:     "delete <VPN ID> <endpoint ID>",
		Aliases: []string{"destroy", "d"},
		Short:   "Delete a VPN endpoint",
		Long:    deleteEndpointLong,
		Example: deleteEndpointExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide a VPN ID and an endpoint ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.delEndpoint(); err != nil {
				return fmt.Errorf("error deleting vpn endpoint : %v", err)
			}

			o.Base.Printer.Display(printer.Info("vpn endpoint has been deleted"), nil)

			return nil
		},
	}

	// Get Endpoint Config
	configEndpoint := &cobra.Command{
		Use:     "config <VPN ID> <endpoint ID>",
		Aliases: []string{"file", "c"},
		Short:   "Get a VPN endpoint config file",
		Long:    configEndpointLong,
		Example: configEndpointExample,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("please provide a VPN ID and an endpoint ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := o.configEndpoint()
			if err != nil {
				return fmt.Errorf("error retrieving vpn endpoint config : %v", err)
			}

			data := &VPNEndpointConfigPrinter{Config: cfg.Config}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	endpoint.AddCommand(
		listEndpoints,
		getEndpoint,
		createEndpoint,
		updateEndpoint,
		delEndpoint,
		configEndpoint,
	)

	cmd.AddCommand(
		list,
		get,
		create,
		update,
		del,
		endpoint,
	)

	return cmd
}

type options struct {
	Base        *cli.Base
	CreateReq   *govultr.VPNCreateReq
	UpdateReq   *govultr.VPNUpdateReq
	EndpointReq *govultr.VPNEndpointReq
	Description string
}

func (o *options) list() ([]govultr.VPN, *govultr.Meta, error) {
	vpns, meta, _, err := o.Base.Client.VPN.List(o.Base.Context, o.Base.Options)
	return vpns, meta, err
}

func (o *options) get() (*govultr.VPN, error) {
	vpn, _, err := o.Base.Client.VPN.Get(o.Base.Context, o.Base.Args[0])
	return vpn, err
}

func (o *options) create() (*govultr.VPN, error) {
	vpn, _, err := o.Base.Client.VPN.Create(o.Base.Context, o.CreateReq)
	return vpn, err
}

func (o *options) update() (*govultr.VPN, error) {
	vpn, _, err := o.Base.Client.VPN.Update(o.Base.Context, o.Base.Args[0], o.UpdateReq)
	return vpn, err
}

func (o *options) del() error {
	return o.Base.Client.VPN.Delete(o.Base.Context, o.Base.Args[0])
}

func (o *options) listEndpoints() ([]govultr.VPNEndpoint, *govultr.Meta, error) {
	ends, meta, _, err := o.Base.Client.VPN.ListEndpoints(o.Base.Context, o.Base.Args[0], o.Base.Options)
	return ends, meta, err
}

func (o *options) getEndpoint() (*govultr.VPNEndpoint, error) {
	end, _, err := o.Base.Client.VPN.GetEndpoint(o.Base.Context, o.Base.Args[0], o.Base.Args[1])
	return end, err
}

func (o *options) createEndpoint() (*govultr.VPNEndpoint, error) {
	end, _, err := o.Base.Client.VPN.CreateEndpoint(o.Base.Context, o.Base.Args[0], o.EndpointReq)
	return end, err
}

func (o *options) updateEndpoint() (*govultr.VPNEndpoint, error) {
	end, _, err := o.Base.Client.VPN.UpdateEndpoint(o.Base.Context, o.Base.Args[0], o.Base.Args[1], o.EndpointReq)
	return end, err
}

func (o *options) delEndpoint() error {
	return o.Base.Client.VPN.DeleteEndpoint(o.Base.Context, o.Base.Args[0], o.Base.Args[1])
}

func (o *options) configEndpoint() (*govultr.VPNEndpointConfigFile, error) {
	cfg, _, err := o.Base.Client.VPN.GetEndpointConfigFile(o.Base.Context, o.Base.Args[0], o.Base.Args[1])
	return cfg, err
}

func formatRemoteSubnets(subnets []string) ([]govultr.VPNEndpointRemoteSubnet, error) {
	var subList []govultr.VPNEndpointRemoteSubnet

	for i := range subnets {
		addr, mask, err := utils.SplitCIDRFormat(subnets[i])
		if err != nil {
			return nil, err
		}

		subList = append(subList, govultr.VPNEndpointRemoteSubnet{
			Subnet: *addr,
			Prefix: *mask,
		})
	}

	return subList, nil
}
