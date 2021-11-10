package cmd

import (
	"context"

	"github.com/deislabs/ratify/config"
	"github.com/deislabs/ratify/httpserver"
	ef "github.com/deislabs/ratify/pkg/executor/core"
	pf "github.com/deislabs/ratify/pkg/policyprovider/configpolicy"
	sf "github.com/deislabs/ratify/pkg/referrerstore/factory"
	vf "github.com/deislabs/ratify/pkg/verifier/factory"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	serveUse = "serve"
)

type serveCmdOptions struct {
	configFilePath    string
	httpServerAddress string
}

func NewCmdServe(argv ...string) *cobra.Command {

	var opts serveCmdOptions

	cmd := &cobra.Command{
		Use:     serveUse,
		Short:   "Run ratify as a server",
		Example: "ratify server",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(opts)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&opts.httpServerAddress, "http", "", "HTTP Address")
	flags.StringVarP(&opts.configFilePath, "config", "c", "", "Config File Path")
	return cmd
}

func serve(opts serveCmdOptions) error {
	cf, err := config.Load(opts.configFilePath)
	if err != nil {
		return err
	}

	logrus.Info("configuration successfully loaded.")
	stores, err := sf.CreateStoresFromConfig(cf.StoresConfig, config.GetDefaultPluginPath())

	if err != nil {
		return err
	}
	logrus.Infof("stores successfully created. number of stores %d", len(stores))

	verifiers, err := vf.CreateVerifiersFromConfig(cf.VerifiersConfig, config.GetDefaultPluginPath())

	if err != nil {
		return err
	}

	logrus.Infof("verifiers successfully created. number of verifiers %d", len(verifiers))

	policyEnforcer, err := pf.CreatePolicyEnforcerFromConfig(cf.PoliciesConfig)

	if err != nil {
		return err
	}

	logrus.Infof("policies successfully created.")

	executor := ef.Executor{
		Verifiers:      verifiers,
		ReferrerStores: stores,
		PolicyEnforcer: policyEnforcer,
	}

	if opts.httpServerAddress != "" {
		server, err := httpserver.NewServer(context.Background(), opts.httpServerAddress, &executor)
		if err != nil {
			return err
		}
		logrus.Infof("starting server at" + opts.httpServerAddress)
		if err := server.Run(); err != nil {
			return err
		}
	}

	return nil
}