package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/isi-lincoln/scamper-comms/pathfinder"
	"github.com/isi-lincoln/scamper-comms/scamper"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	server        string
	port          int
	format        string
	fiPath        string
	threshold     int
	ignoreCerts   bool
	srcAnnotation string
	traceSetID    int
	logLevel      string
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
			apikey := args[0]

			if apikey == "" {
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

			_, code, err := pathfinder.SubmitTraceRoute(
				ep, apikey, srcAnnotation, requestData, logger, ignoreCerts,
			)
			if err != nil {
				log.Fatal(err)
			}
			ready, resp, err := pathfinder.Query(defaultTraceRouteEndpoint, apikey, code, logger, ignoreCerts)
			if err != nil {
				log.Fatal(err)
			}
			if !ready {
				ticker := time.NewTicker(10 * time.Second)
				timeoutTimer := time.NewTimer(time.Minute)

				defer ticker.Stop()
				defer timeoutTimer.Stop()

				for {
					select {
					case <-ticker.C:
						ready, resp, err = pathfinder.Query(
							defaultTraceRouteEndpoint,
							apikey,
							code,
							logger,
							ignoreCerts,
						)
						if err != nil {
							log.Fatal(err)
						}

						if ready {
							break
						} else {
							log.Infof("query not ready yet.")
						}
					case <-timeoutTimer.C:
						log.Fatal("request timed out")
					}
				}

			}

			jsonData, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				log.Error("Failed to marshal response:", err)
			} else {
				log.Infof("Response:", string(jsonData))
			}

		},
	}
	traceroute.Flags().BoolVarP(&ignoreCerts, "ignore-certs", "i", false, "ignore pathfinder server certificates")
	traceroute.Flags().IntVarP(&threshold, "threshold", "t", 5, "threshold of the threat level")
	traceroute.Flags().IntVarP(&traceSetID, "traceset", "s", 0, "submit traceroute to a traceset")
	traceroute.Flags().StringVarP(&srcAnnotation, "annotation", "a", "", "annotate the name of the source of the traceroute")
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
				ignoreCerts,
			)
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("traceset id created: %d", traceId)
		},
	}
	traceSet.Flags().BoolVarP(&ignoreCerts, "ignore-certs", "i", false, "ignore pathfinder server certificates")
	pfCmd.AddCommand(traceSet)

	err := root.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
