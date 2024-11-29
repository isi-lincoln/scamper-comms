package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	//var inputFile string
	apiKeyFile := "apikey-ipgeo"
	log.SetLevel(log.DebugLevel)

	var root = &cobra.Command{
		Use:   "mock",
		Short: "mock data",
	}

	var pathfinder = &cobra.Command{
		Use:   "pathfinder <[ip list: src, hop1, ..., dst]>",
		Short: "mock pathfinder data",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			// query
			apiKey, err := getAPIKey(apiKeyFile)
			if err != nil {
				log.Fatal(err)
			}

			// output
			out, err := Convert(apiKey, args)
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("%#v", out)
		},
	}

	root.AddCommand(pathfinder)

	// Execute the root command
	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
