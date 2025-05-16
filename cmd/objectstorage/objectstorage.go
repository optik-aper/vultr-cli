// Package objectstorage provides the object storage commands for the CLI
package objectstorage

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vultr/govultr/v3"
	"github.com/vultr/vultr-cli/v3/cmd/printer"
	"github.com/vultr/vultr-cli/v3/cmd/utils"
	"github.com/vultr/vultr-cli/v3/pkg/cli"
)

// NewCmdObjectStorage provides the CLI command for object storage functions
func NewCmdObjectStorage(base *cli.Base) *cobra.Command { //nolint:gocyclo
	o := &options{Base: base}

	cmd := &cobra.Command{
		Use:   "object-storage",
		Short: "Commands to manage object storage",
		Long:  `object-storage is used to interact with object storages`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			utils.SetOptions(o.Base, cmd, args)
			if !o.Base.HasAuth {
				return errors.New(utils.APIKeyError)
			}
			return nil
		},
	}

	// List
	list := &cobra.Command{
		Use:   "list",
		Short: "Retrieve all active object storages",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Base.Options = utils.GetPaging(cmd)

			oss, meta, err := o.list()
			if err != nil {
				return fmt.Errorf("error retrieving object storage list : %v", err)
			}

			data := &ObjectStoragesPrinter{ObjectStorages: oss, Meta: meta}
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
		Use:   "get <Object Storage ID>",
		Short: "Retrieve a given object storage",
		Long:  ``,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide an object storage ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			os, err := o.get()
			if err != nil {
				return fmt.Errorf("error getting object storage info : %v", err)
			}

			data := &ObjectStoragePrinter{ObjectStorage: os}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	// Create
	create := &cobra.Command{
		Use:   "create",
		Short: "Create a new object storage",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, errCl := cmd.Flags().GetInt("cluster-id")
			if errCl != nil {
				return fmt.Errorf("error parsing flag 'cluster-id' for object storage create : %v", errCl)
			}

			label, errLa := cmd.Flags().GetString("label")
			if errLa != nil {
				return fmt.Errorf("error parsing flag 'label' for object storage create : %v", errLa)
			}

			o.ObjectStorageReq = &govultr.ObjectStorageReq{
				ClusterID: clusterID,
				Label:     label,
			}

			os, err := o.create()
			if err != nil {
				return fmt.Errorf("error creating object storage : %v", err)
			}

			data := &ObjectStoragePrinter{ObjectStorage: os}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	create.Flags().StringP("label", "l", "", "label you want your object storage to have")
	create.Flags().IntP("cluster-id", "i", 0, "ID of the cluster in which to create the object storage")
	if err := create.MarkFlagRequired("cluster-id"); err != nil {
		printer.Error(fmt.Errorf("error marking object storage create 'cluster-id' flag required : %v", err))
		os.Exit(1)
	}

	// Label
	label := &cobra.Command{
		Use:   "label <Object Storage ID>",
		Short: "Change the label for object storage",
		Long:  ``,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide an object storage ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			label, errLa := cmd.Flags().GetString("label")
			if errLa != nil {
				return fmt.Errorf("error parsing flag 'label' for object storage label : %v", errLa)
			}

			o.ObjectStorageReq = &govultr.ObjectStorageReq{
				Label: label,
			}
			if err := o.update(); err != nil {
				return fmt.Errorf("error updating object storage label : %v", err)
			}

			o.Base.Printer.Display(printer.Info("object storage label has been set"), nil)
			return nil
		},
	}

	label.Flags().StringP("label", "l", "", "label you want your object storage to have")
	if err := label.MarkFlagRequired("label"); err != nil {
		printer.Error(fmt.Errorf("error marking object storage update 'label' flag required: %v", err))
		os.Exit(1)
	}

	// Delete
	del := &cobra.Command{
		Use:     "delete <Object Storage ID>",
		Short:   "Delete an object storage",
		Aliases: []string{"destroy"},
		Long:    ``,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide an object storage ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.del(); err != nil {
				return fmt.Errorf("unable to delete object storage : %v", err)
			}

			o.Base.Printer.Display(printer.Info("object storage has been deleted"), nil)
			return nil
		},
	}

	// Regenerate Keys
	regenerateKeys := &cobra.Command{
		Use:   "regenerate-keys <Object Storage ID>",
		Short: "Regenerate the S3 API keys for an object storage",
		Long:  ``,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("please provide an object storage ID")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := o.regenerateKeys()
			if err != nil {
				return fmt.Errorf("unable to regenerate keys for object storage : %v", err)
			}

			data := &ObjectStorageKeysPrinter{Keys: key}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	// Cluster
	cluster := &cobra.Command{
		Use:   "cluster",
		Short: "Commands to retrieve object storage cluster information",
	}

	// List Clusters
	clusterList := &cobra.Command{
		Use:   "list",
		Short: "Retrieve a list of all available object storage clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Base.Options = utils.GetPaging(cmd)

			clusters, meta, err := o.listClusters()
			if err != nil {
				return fmt.Errorf("error retrieving object storage cluster list : %v", err)
			}

			data := &ObjectStorageClustersPrinter{Clusters: clusters, Meta: meta}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	// List Cluster Tiers
	clusterTierList := &cobra.Command{
		Use:   "tiers",
		Short: "Retrieve a list of tiers for a given object storage cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			clusterID, err := cmd.Flags().GetInt("cluster-id")
			if err != nil {
				return fmt.Errorf("error parsing flag 'cluster-id' for object storage cluster tier list : %v", err)
			}

			o.ClusterID = clusterID

			clusterTiers, err := o.listClusterTiers()
			if err != nil {
				return fmt.Errorf("error retrieving object storage cluster tier list : %v", err)
			}

			data := &ObjectStorageTiersPrinter{Tiers: clusterTiers}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	clusterTierList.Flags().IntP(
		"cluster-id",
		"i",
		0,
		"ID of the object storage cluster for which to retrieve the tier information",
	)
	if err := clusterTierList.MarkFlagRequired("cluster-id"); err != nil {
		printer.Error(fmt.Errorf("error marking object storage cluster tier list 'cluster-id' flag required : %v", err))
		os.Exit(1)
	}

	cluster.AddCommand(
		clusterList,
		clusterTierList,
	)

	// Tier
	tier := &cobra.Command{
		Use:   "tier",
		Short: "Commands for object storage tiers",
	}

	// List Tiers
	tierList := &cobra.Command{
		Use:   "list",
		Short: "Retrieve a list of all object storage tiers",
		RunE: func(cmd *cobra.Command, args []string) error {
			tiers, err := o.listTiers()
			if err != nil {
				return fmt.Errorf("error retrieving object storage tier list : %v", err)
			}

			data := &ObjectStorageTiersPrinter{Tiers: tiers}
			o.Base.Printer.Display(data, nil)

			return nil
		},
	}

	tier.AddCommand(
		tierList,
	)

	cmd.AddCommand(
		list,
		get,
		create,
		label,
		del,
		regenerateKeys,
		cluster,
		tier,
	)

	return cmd
}

type options struct {
	Base             *cli.Base
	ObjectStorageReq *govultr.ObjectStorageReq
	ClusterID        int
}

func (o *options) list() ([]govultr.ObjectStorage, *govultr.Meta, error) {
	oss, meta, _, err := o.Base.Client.ObjectStorage.List(o.Base.Context, o.Base.Options)
	return oss, meta, err
}

func (o *options) get() (*govultr.ObjectStorage, error) {
	os, _, err := o.Base.Client.ObjectStorage.Get(o.Base.Context, o.Base.Args[0])
	return os, err
}

func (o *options) create() (*govultr.ObjectStorage, error) {
	os, _, err := o.Base.Client.ObjectStorage.Create(o.Base.Context, o.ObjectStorageReq)
	return os, err
}

func (o *options) update() error {
	return o.Base.Client.ObjectStorage.Update(o.Base.Context, o.Base.Args[0], o.ObjectStorageReq)
}

func (o *options) del() error {
	return o.Base.Client.ObjectStorage.Delete(o.Base.Context, o.Base.Args[0])
}

func (o *options) listClusters() ([]govultr.ObjectStorageCluster, *govultr.Meta, error) {
	clusters, meta, _, err := o.Base.Client.ObjectStorage.ListCluster(o.Base.Context, o.Base.Options)
	return clusters, meta, err
}

func (o *options) regenerateKeys() (*govultr.S3Keys, error) {
	keys, _, err := o.Base.Client.ObjectStorage.RegenerateKeys(o.Base.Context, o.Base.Args[0])
	return keys, err
}

func (o *options) listTiers() ([]govultr.ObjectStorageTier, error) {
	tiers, _, err := o.Base.Client.ObjectStorage.ListTiers(o.Base.Context)
	return tiers, err
}

func (o *options) listClusterTiers() ([]govultr.ObjectStorageTier, error) {
	tiers, _, err := o.Base.Client.ObjectStorage.ListClusterTiers(o.Base.Context, o.ClusterID)
	return tiers, err
}
