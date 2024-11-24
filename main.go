package main

import (
	"fmt"
	"io/ioutil"

	"github.com/isi-lincoln/scamper-comms/pathfinder"
	"github.com/isi-lincoln/scamper-comms/scamper"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	server    string
	port      int
	format    string
	fiPath    string
	threshold int
)

func main() {

	var root = &cobra.Command{
		Use:   "connect",
		Short: "managing scamper and scamper output to pathfinder",
	}

	root.Flags().StringVarP(&server, "server", "s", "localhost", "server scamper is running on")
	root.Flags().IntVarP(&port, "port", "p", 31337, "scamper daemon port")
	root.Flags().StringVarP(&format, "format", "f", "json", "format scamper output (json, warts)")
	root.Flags().StringVarP(&fiPath, "file", "o", "", "write output to a file")

	var scamper = &cobra.Command{
		Use:   "scamper \"<cmd>\"",
		Short: "connect to a scamper socket",
		Long:  "scamper -o out.json -f json -s localhost -p 31337 \"trace -q 1 -w 1 8.8.8.8\"",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			// Create the address string
			addr := fmt.Sprintf("%s:%d", server, port)

			out, err := scamper.SendTrace(addr, args[0], fiPath, format)
			if err != nil {
				log.Fatal(err)
			}
			if fiPath == "" {
				log.Info(out)
			}
		},
	}
	root.AddCommand(scamper)

	var pathfinder = &cobra.Command{
		Use:   "pathfinder <api key> <file>",
		Short: "pathfinder -t 3 <api key> <file>",
		Long:  "send scamper output json file to pathfinder api service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			defaultEndpoint := "https://api.pathfinder.caida.org/v1/traceroutes"

			if args[0] == "" {
				log.Fatalf("pathfinder requires an api key\n")
			}

			requestData, err := ioutil.ReadFile(args[1])
			if err != nil {
				log.Fatalf("error reading file: %v", err)
			}

			migrate, err := pathfinder.SendRequest(defaultEndpoint, args[0], threshold, requestData)
			if err != nil {
				log.Fatal(err)
			}
			if migrate {
				log.Infof("Threat threhold met: migrating")
			} else {
				log.Infof("Path is safe")
			}
		},
	}
	pathfinder.Flags().IntVarP(&threshold, "threshold", "t", 5, "threshold of the threat level")
	root.AddCommand(pathfinder)

	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
