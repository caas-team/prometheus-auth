package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/caas-team/prometheus-auth/pkg/agent"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	VER  = "dev" //nolint:gochecknoglobals // set by build
	HASH = "-"   //nolint:gochecknoglobals // set by build
)

const (
	readTimeout    = 5 * time.Minute
	maxConnections = 512
)

func main() {
	app := cli.NewApp()
	app.Version = fmt.Sprintf("%s(%s)", VER, HASH)
	app.Name = "prometheus-auth"
	app.Usage = "Deploying in the front of Prometheus to intercept and hijack the APIs"
	app.Description = `
        ##################################################################################
        ##                                      RBAC                                    ##
        ##################################################################################
        Resources                 Non-Resource URLs  Resource Names       Verbs
        ---------                 -----------------  --------------       -----
        namespaces                []                 []                   [list,watch,get]
        secrets,                  []                 []                   [list,watch,get]
        selfsubjectaccessreviews  []                 []                   [create]`

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "log.json",
			Usage: "[optional] Log as JSON",
		},
		cli.BoolFlag{
			Name:  "log.debug",
			Usage: "[optional] Log debug info",
		},
		cli.StringFlag{
			Name:  "listen-address",
			Usage: "[optional] Address to listening",
			Value: ":9090",
		},
		cli.StringFlag{
			Name:  "proxy-url",
			Usage: "[optional] URL to proxy",
			Value: "http://localhost:9999",
		},
		cli.DurationFlag{
			Name:  "read-timeout",
			Usage: "[optional] Maximum duration before timing out read of the request, and closing idle connections",
			Value: readTimeout,
		},
		cli.IntFlag{
			Name:  "max-connections",
			Usage: "[optional] Maximum number of simultaneous connections",
			Value: maxConnections,
		},
		cli.StringSliceFlag{
			Name:  "filter-reader-labels",
			Usage: "[optional] Filter out the configured labels when calling '/api/v1/read'",
			Value: &cli.StringSlice{},
		},
	}

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("panic: %v", r)
			os.Exit(1)
		}
	}()

	app.Before = func(context *cli.Context) error {
		if context.Bool("log.json") {
			log.SetFormatter(&log.JSONFormatter{})
		} else {
			log.SetFormatter(&log.TextFormatter{ForceColors: true, FullTimestamp: true})
		}

		if context.Bool("log.debug") {
			log.SetLevel(log.DebugLevel)
			runtime.SetBlockProfileRate(20)     //nolint:mnd // debugging purposes
			runtime.SetMutexProfileFraction(20) //nolint:mnd // debugging purposes
		}

		log.SetOutput(os.Stdout)

		return nil
	}

	app.Action = agent.Run

	if err := app.Run(os.Args); err != nil {
		log.Panic(err)
	}
}
