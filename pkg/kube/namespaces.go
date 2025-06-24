package kube

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/juju/errors"

	"github.com/caas-team/prometheus-auth/pkg/data"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	clientAuthorization "k8s.io/client-go/kubernetes/typed/authorization/v1"
	clientCache "k8s.io/client-go/tools/cache"
)

const (
	byTokenIndex               = "byToken"
	byProjectIDIndex           = "byProjectID"
	cacheTTL                   = 5 * time.Minute
	secretResyncPeriod         = 2 * time.Hour
	nsResyncPeriod             = 10 * time.Minute
	reviewResultCacheSizeBytes = 1024
)

type Namespaces interface {
	Query(token string) data.Set
}

type namespaces struct {
	subjectAccessReviewsClient clientAuthorization.SubjectAccessReviewInterface
	reviewResultTTLCache       *cache.LRUExpireCache
	secretIndexer              clientCache.Indexer
	namespaceIndexer           clientCache.Indexer
	metrics                    *metrics
}

type metrics struct {
	successfulValidations *prometheus.CounterVec
	failedValdations      *prometheus.CounterVec
	mu                    sync.Mutex
}

// NewMetrics creates a new metrics struct with initialized prometheus metrics.
func NewMetrics(reg prometheus.Registerer) *metrics {
	res := metrics{
		successfulValidations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "prometheus_auth_successful_validations_total",
				Help: "Total number of successful service account validations.",
			},
			[]string{"namespace"},
		),
		failedValdations: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "prometheus_auth_failed_validations_total",
				Help: "Total number of failed service account validations. If no label is set, the namespace couldn't be parsed.",
			},
			[]string{"namespace"},
		),
		mu: sync.Mutex{},
	}

	reg.MustRegister(res.GetCollectors()...)
	return &res
}

// IncSuccessfulRequests increments the successful requests counter for the given namespace.
func (m *metrics) IncSuccessfulRequests(namespace string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successfulValidations.WithLabelValues(namespace).Inc()
}

// IncFailedRequests increments the failed requests counter for the given namespace.
func (m *metrics) IncFailedRequests(namespace string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failedValdations.WithLabelValues(namespace).Inc()
}

// GetCollectors returns all metric collectors.
func (m *metrics) GetCollectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.successfulValidations,
		m.failedValdations,
	}
}

// Query returns the namespaces associated with the given token.
func (n *namespaces) Query(token string) data.Set {
	ret, err := n.query(token)
	if err != nil {
		log.Warnf("failed to query Namespaces: %v", err)
	}
	return ret
}

// query retrieves the namespaces associated with the given token,
// which match the project ID of the namespace the token belongs to.
func (n *namespaces) query(token string) (data.Set, error) {
	ret := data.Set{}

	tokenNamespace, err := n.validate(token)
	if err != nil {
		return ret, errors.Annotatef(err, "failed validation")
	}

	log.Debugf("searching for namespace %q in cache", tokenNamespace)
	nsObj, exist, err := n.namespaceIndexer.GetByKey(tokenNamespace)
	if err != nil {
		return ret, errors.Annotatef(err, "failed to get namespace")
	}

	if !exist {
		return ret, errors.New("unknown namespace of token " + tokenNamespace)
	}

	ns := toNamespace(nsObj)
	if ns.DeletionTimestamp != nil {
		return ret, errors.New("deleting namespace of token")
	}

	projectID, exist := getProjectID(ns)
	if !exist {
		return ret, errors.New("unknown project of token")
	}

	nsList, err := n.namespaceIndexer.ByIndex(byProjectIDIndex, projectID)
	if err != nil {
		return ret, errors.Annotatef(err, "invalid project")
	}

	for _, nsObj := range nsList {
		ns = toNamespace(nsObj)
		ret[ns.Name] = struct{}{}
	}
	return ret, nil
}

// validate checks the token and returns the namespace it is associated with,
// or an error if the token is invalid or does not have access to the namespace.
func (n *namespaces) validate(token string) (string, error) {
	var claimNamespace string
	// Get Issuer - token parsing is skipped here, because we only need the issuer
	// and we don't have the key to verify the signature.
	tokenJwt, _ := jwt.Parse(token, nil)
	claims, ok := tokenJwt.Claims.(jwt.MapClaims)
	issuer, gErr := claims.GetIssuer()
	if cmp.Or(!ok, gErr != nil) {
		return "", fmt.Errorf("failed to parse claim JWT token: %s", token)
	}

	clusterName := os.Getenv("CLUSTER_NAME")
	// investigate token type
	switch issuer {
	// bound token
	case "rke":
		claimNamespace, _ = claims["kubernetes.io"].(map[string]interface{})["namespace"].(string)
	// k3s
	case "https://kubernetes.default.svc.cluster.local":
		claimNamespace, _ = claims["kubernetes.io"].(map[string]interface{})["namespace"].(string)
	// legacy token
	case "kubernetes/serviceaccount":
		claimNamespace, _ = claims["kubernetes.io/serviceaccount/namespace"].(string)
	// caas OICD
	case fmt.Sprintf("https://oidc.caas-%s.telekom.de/", clusterName):
		claimNamespace, _ = claims["kubernetes.io"].(map[string]interface{})["namespace"].(string)
	default:
		log.Errorf("invalid claim type found: %v", claims)
		n.metrics.IncFailedRequests("")
		return "", fmt.Errorf("unknown token issuer %s", issuer)
	}

	_, exist := n.reviewResultTTLCache.Get(token)
	if exist {
		log.Debugf("token for ns %q is cached", claimNamespace)
		n.metrics.IncSuccessfulRequests(claimNamespace)
		return claimNamespace, nil
	}

	projectMonitoringServiceAccountName := "project-monitoring"
	sarUser := fmt.Sprintf("system:serviceaccount:%s:%s", claimNamespace, projectMonitoringServiceAccountName)
	sar := &authorization.SubjectAccessReview{
		Spec: authorization.SubjectAccessReviewSpec{
			ResourceAttributes: &authorization.ResourceAttributes{
				Namespace: claimNamespace,
				Verb:      "view",
				Group:     "monitoring.coreos.com",
				Resource:  "prometheus",
			},
			User: sarUser,
		},
	}

	log.Debugf("sending access review for namespace %q", claimNamespace)
	reviewResult, err := n.subjectAccessReviewsClient.Create(context.TODO(), sar, meta.CreateOptions{})
	if err != nil {
		n.metrics.IncFailedRequests(claimNamespace)
		return "", errors.Annotatef(err, "failed to review token")
	}

	if !reviewResult.Status.Allowed || reviewResult.Status.Denied {
		n.metrics.IncFailedRequests(claimNamespace)
		return "", fmt.Errorf("token is not allowed to access namespace %q", claimNamespace)
	}

	if reviewResult.Status.Allowed {
		n.reviewResultTTLCache.Add(token, struct{}{}, cacheTTL)
		log.Debugf("token is allowed to access namespace %q, accepted", claimNamespace)
		n.metrics.IncSuccessfulRequests(claimNamespace)
		return claimNamespace, nil
	}

	log.Debugf("token is not allowed to access namespace %q, denied: %s", claimNamespace, reviewResult.Status.Reason)
	n.metrics.IncFailedRequests(claimNamespace)
	return claimNamespace, nil
}

func NewNamespaces(ctx context.Context, k8sClient kubernetes.Interface, reg *prometheus.Registry) Namespaces {
	// secrets
	sec := k8sClient.CoreV1().Secrets(meta.NamespaceAll)
	secListWatch := &clientCache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options meta.ListOptions) (runtime.Object, error) {
			return sec.List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options meta.ListOptions) (watch.Interface, error) {
			return sec.Watch(ctx, options)
		},
	}
	secInformer := clientCache.NewSharedIndexInformer(secListWatch, &core.Secret{}, secretResyncPeriod, clientCache.Indexers{byTokenIndex: secretByToken})

	// namespaces
	ns := k8sClient.CoreV1().Namespaces()
	nsListWatch := &clientCache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options meta.ListOptions) (runtime.Object, error) {
			return ns.List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options meta.ListOptions) (watch.Interface, error) {
			return ns.Watch(ctx, options)
		},
	}
	nsInformer := clientCache.NewSharedIndexInformer(nsListWatch, &core.Namespace{}, nsResyncPeriod, clientCache.Indexers{byProjectIDIndex: namespaceByProjectID})

	// run
	go secInformer.Run(ctx.Done())
	go nsInformer.Run(ctx.Done())

	return &namespaces{
		subjectAccessReviewsClient: k8sClient.AuthorizationV1().SubjectAccessReviews(),
		reviewResultTTLCache:       cache.NewLRUExpireCache(reviewResultCacheSizeBytes),
		secretIndexer:              secInformer.GetIndexer(),
		namespaceIndexer:           nsInformer.GetIndexer(),
		metrics:                    NewMetrics(reg),
	}
}

func toNamespace(obj interface{}) *core.Namespace {
	ns, ok := obj.(*core.Namespace)
	if !ok {
		return &core.Namespace{}
	}

	return ns
}

func toSecret(obj interface{}) *core.Secret {
	sec, ok := obj.(*core.Secret)
	if !ok {
		return &core.Secret{}
	}

	return sec
}

func getProjectID(ns *core.Namespace) (string, bool) {
	if ns != nil && ns.Labels != nil {
		projectIdentifier, exist := ns.Labels["caas.telekom.de/multiprojectkey"]
		if exist {
			return projectIdentifier, true
		}
		projectID, exist := ns.Labels["field.cattle.io/projectId"]
		if exist {
			return projectID, true
		}
	}

	return "", false
}

func namespaceByProjectID(obj interface{}) ([]string, error) {
	projectID, exist := getProjectID(toNamespace(obj))
	if exist {
		return []string{projectID}, nil
	}

	return []string{}, nil
}

func secretByToken(obj interface{}) ([]string, error) {
	sec := toSecret(obj)
	if sec.Type == core.SecretTypeServiceAccountToken {
		secretToken := sec.Data[core.ServiceAccountTokenKey]
		if len(secretToken) != 0 {
			return []string{string(secretToken)}, nil
		}
	}

	return []string{}, nil
}
