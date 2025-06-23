package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint: gosec // enable profiler
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caas-team/prometheus-auth/pkg/data"
	"github.com/caas-team/prometheus-auth/pkg/kube"
	"github.com/cockroachdb/cmux"
	"github.com/juju/errors"
	grpcproxy "github.com/mwitkow/grpc-proxy/proxy"
	promapi "github.com/prometheus/client_golang/api"
	promapiv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	authentication "k8s.io/api/authentication/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Run(cliContext *cli.Context) {
	// enable profiler
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &agentConfig{
		ctx:                  ctx,
		listenAddress:        cliContext.String("listen-address"),
		readTimeout:          cliContext.Duration("read-timeout"),
		maxConnections:       cliContext.Int("max-connections"),
		filterReaderLabelSet: data.NewSet(cliContext.StringSlice("filter-reader-labels")...),
	}

	proxyURLString := cliContext.String("proxy-url")
	if len(proxyURLString) == 0 {
		log.Panic("--agent.proxy-url is blank")
	}
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		log.Panic("Unable to parse agent.proxy-url")
	}
	cfg.proxyURL = proxyURL

	accessTokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // read token from file
	accessTokenBytes, err := os.ReadFile(accessTokenPath)
	if err != nil {
		log.WithError(err).Panicf("Failed to read token file %q", accessTokenPath)
	}
	accessToken := strings.TrimSpace(string(accessTokenBytes))
	if len(accessToken) == 0 {
		log.Panicf("Read empty token from file %q", accessTokenPath)
	}
	cfg.myToken = accessToken

	oidcURLString := cliContext.String("oidc-issuer")
	if len(oidcURLString) > 0 {
		oidcURL, pErr := url.Parse(oidcURLString)
		if pErr != nil {
			log.Panicf("Unable to parse OIDC issuer URL %q", oidcURLString)
		}
		cfg.oidcIssuer = oidcURL.String()
	}

	log.Println(cfg)

	reader, err := createAgent(context.TODO(), cfg)
	if err != nil {
		log.WithError(err).Panic("Failed to create agent")
	}

	if err = reader.serve(); err != nil {
		log.WithError(err).Panic("Failed to serve")
	}
}

type agentConfig struct {
	ctx                  context.Context
	myToken              string
	listenAddress        string
	proxyURL             *url.URL
	readTimeout          time.Duration
	maxConnections       int
	filterReaderLabelSet data.Set
	oidcIssuer           string
}

func (a *agentConfig) String() string {
	sb := &strings.Builder{}

	fmt.Fprint(sb, "listening on ", a.listenAddress)
	fmt.Fprint(sb, ", proxying to ", a.proxyURL.String())
	fmt.Fprintf(sb, " with ignoring 'remote reader' labels [%s]", a.filterReaderLabelSet)
	fmt.Fprintf(sb, ", only allow maximum %d connections with %v read timeout", a.maxConnections, a.readTimeout)
	sb.WriteString(" .")

	return sb.String()
}

type agent struct {
	cfg        *agentConfig
	userInfo   authentication.UserInfo
	listener   net.Listener
	namespaces kube.Namespaces
	tokens     kube.Tokens
	remoteAPI  promapiv1.API
}

func (a *agent) serve() error {
	listenerMux := cmux.New(a.listener)
	httpProxy := a.createHTTPProxy()
	grpcProxy := a.createGRPCProxy()

	errCh := make(chan error)
	go func() {
		if err := httpProxy.Serve(createHTTPListener(listenerMux)); err != nil {
			errCh <- errors.Annotate(err, "failed to start proxy http listener")
		}
	}()
	go func() {
		if err := grpcProxy.Serve(createGRPCListener(listenerMux, a.cfg.myToken)); err != nil {
			errCh <- errors.Annotate(err, "failed to start proxy grpc listener")
		}
	}()
	go func() {
		log.Infof("Start listening for connections on %s", a.cfg.listenAddress)

		if err := listenerMux.Serve(); err != nil {
			errCh <- errors.Annotatef(err, "failed to listen on %s", a.cfg.listenAddress)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-a.cfg.ctx.Done():
		grpcProxy.GracefulStop()
		err := httpProxy.Shutdown(a.cfg.ctx)
		if err != nil {
			log.Warnf("Error shuting down httproxy: %v", err)
		}
		return nil
	}
}

func createAgent(ctx context.Context, cfg *agentConfig) (*agent, error) {
	utilruntime.ReallyCrash = false
	utilruntime.PanicHandlers = []func(context.Context, interface{}){
		func(ctx context.Context, i interface{}) {
			if err, ok := i.(error); ok {
				log.Error(errors.ErrorStack(err))
			} else {
				log.Error(i)
			}
		},
	}
	utilruntime.ErrorHandlers = []utilruntime.ErrorHandler{
		func(ctx context.Context, err error, msg string, args ...interface{}) {
			log.Error(errors.ErrorStack(err))
		},
	}

	listener, err := net.Listen("tcp", cfg.listenAddress)
	if err != nil {
		return nil, errors.Annotatef(err, "unable to listen on addr %s", cfg.listenAddress)
	}
	listener = netutil.LimitListener(listener, cfg.maxConnections)

	// create Kubernetes client
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Annotate(err, "unable to create Kubernetes config by InClusterConfig()")
	}
	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, errors.Annotate(err, "unable to new Kubernetes clientSet")
	}

	// create Prometheus client
	promClient, err := promapi.NewClient(promapi.Config{
		Address: cfg.proxyURL.String(),
	})
	if err != nil {
		return nil, errors.Annotate(err, "unable to new Prometheus client")
	}

	// create tokens client and get userInfo
	tokens := kube.NewTokens(cfg.ctx, k8sClient)
	userInfo, err := tokens.Authenticate(cfg.myToken)
	if err != nil {
		return nil, errors.Annotate(err, "unable to get userInfo from agent token")
	}

	return &agent{
		cfg:        cfg,
		userInfo:   userInfo,
		listener:   listener,
		namespaces: kube.NewNamespaces(cfg.ctx, k8sClient, cfg.oidcIssuer),
		tokens:     tokens,
		remoteAPI:  promapiv1.NewAPI(promClient),
	}, nil
}

func (a *agent) createHTTPProxy() *http.Server {
	return &http.Server{
		Handler:     a.httpBackend(),
		ReadTimeout: a.cfg.readTimeout,
	}
}

func (a *agent) createGRPCProxy() *grpc.Server {
	return grpc.NewServer(
		grpc.CustomCodec(grpcproxy.Codec()),
		grpc.UnknownServiceHandler(a.grpcBackend()),
	)
}
