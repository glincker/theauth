// Package main is the entry point for the TheAuth Terraform provider.
//
// To build and install locally:
//
//	go build -o terraform-provider-theauth .
//	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/theauth/theauth/0.1.0/linux_amd64/
//	mv terraform-provider-theauth ~/.terraform.d/plugins/registry.terraform.io/theauth/theauth/0.1.0/linux_amd64/
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := &plugin.ServeOpts{
		ProviderFunc: New,
	}

	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/theauth/theauth", opts)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	plugin.Serve(opts)
}
