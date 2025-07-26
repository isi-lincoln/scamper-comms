package main

import (
	"fmt"
	"io/ioutil"

	"github.com/isi-lincoln/scamper-comms/pathfinder"
	"github.com/isi-lincoln/scamper-comms/scamper"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	server      string
	port        int
	format      string
	fiPath      string
	threshold   int
	ignoreCerts bool
	traceSetID  int
	logLevel    string
)

func main() {

	var root = &cobra.Command{
		Use:   "connect",
		Short: "managing scamper and scamper output to pathfinder",
	}

	root.Flags().StringVarP(&server, "server", "s", "localhost", "server scamper is running on")
	root.Flags().IntVarP(&port, "port", "p", 31337, "scamper daemon port")
	root.Flags().StringVarP(&logLevel, "loglevel", "l", "debug", "what level of debugging")

	var scamper = &cobra.Command{
		Use:   "scamper \"<cmd>\"",
		Short: "connect to a scamper socket",
		Long:  "scamper -o out.json -f json -s localhost -p 31337 \"trace -q 1 -w 1 8.8.8.8\"",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Create the address string
			addr := fmt.Sprintf("%s:%d", server, port)

			logger := logrus.New()
			logger.SetLevel(logrus.InfoLevel)
			if logLevel == "debug" {
				logger.SetLevel(logrus.DebugLevel)
			}

			out, err := scamper.RequestTrace(addr, args[0], fiPath, format, logger)
			if err != nil {
				log.Fatal(err)
			}
			if fiPath == "" {
				log.Infof("%#v", out)
			}
		},
	}
	root.AddCommand(scamper)
	scamper.Flags().StringVarP(&format, "format", "f", "json", "format scamper output (json, warts)")
	scamper.Flags().StringVarP(&fiPath, "output", "o", "", "write output to a file")

	var pfCmd = &cobra.Command{
		Use:   "pathfinder",
		Short: "do pathfinder things",
	}
	root.AddCommand(pfCmd)

	var traceroute = &cobra.Command{
		Use:   "traceroute <api key> <file>",
		Short: "traceroute -t 3 <api key> <file>",
		Long:  "send scamper output json file to pathfinder api service",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			defaultTraceRouteEndpoint := "https://api.pathfinder.caida.org/v1/traceroutes"
			withTraceSet := fmt.Sprintf("%s?traceset_id=%d", defaultTraceRouteEndpoint, traceSetID)

			if args[0] == "" {
				log.Fatalf("pathfinder requires an api key\n")
			}

			requestData, err := ioutil.ReadFile(args[1])
			if err != nil {
				log.Fatalf("error reading file: %v", err)
			}

			logger := logrus.New()
			logger.SetLevel(logrus.InfoLevel)
			if logLevel == "debug" {
				logger.SetLevel(logrus.DebugLevel)
			}

			ep := defaultTraceRouteEndpoint
			if traceSetID != 0 {
				ep = withTraceSet
			}

			ready, err := pathfinder.SendTraceRouteRequest(
				ep, args[0], requestData, logger, ignoreCerts,
			)

			if err != nil {
				log.Fatal(err)
			}

			if ready {
				log.Infof("You can query endpoint")
			} else {
				log.Infof("Endpoint hasnt finished querying")
			}
		},
	}
	traceroute.Flags().BoolVarP(&ignoreCerts, "ignore-certs", "i", false, "ignore pathfinder server certificates")
	traceroute.Flags().IntVarP(&threshold, "threshold", "t", 5, "threshold of the threat level")
	traceroute.Flags().IntVarP(&traceSetID, "traceset", "s", 0, "submit traceroute to a traceset")
	pfCmd.AddCommand(traceroute)

	var traceSet = &cobra.Command{
		Use:   "traceset <api key> <creator> <[tags,]>",
		Short: "traceset <api key> <creator> <tags...>",
		Long:  "create a traceset id from a tag",
		Args:  cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			defaultTraceSetEndpoint := "https://api.pathfinder.caida.org/v1/tracesets"

			if args[0] == "" {
				log.Fatalf("pathfinder requires an api key\n")
			}

			if args[1] == "" {
				log.Fatalf("traceset creator missing\n")
			}

			tags := args[2:]
			if args[2] == "" {
				log.Fatalf("traceset tag missing\n")
			}

			logger := logrus.New()
			logger.SetLevel(logrus.InfoLevel)
			if logLevel == "debug" {
				logger.SetLevel(logrus.DebugLevel)
			}

			traceId, err := pathfinder.SendTraceSetRequest(
				defaultTraceSetEndpoint,
				args[0],
				args[1],
				tags,
				logger,
			)
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("traceset id created: %d", traceId)
		},
	}
	pfCmd.AddCommand(traceSet)

	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
