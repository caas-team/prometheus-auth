package kube

import (
	"context"
	"fmt"
	"time"

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
	secretInformerResyncPeriod = 2 * time.Hour
	nsInformerResyncPeriod     = 10 * time.Minute
	cacheMaxSize               = 1024
)

type Namespaces interface {
	Query(ctx context.Context, token string) data.Set
}

type namespaces struct {
	subjectAccessReviewsClient clientAuthorization.SubjectAccessReviewInterface
	reviewResultTTLCache       *cache.LRUExpireCache
	secretIndexer              clientCache.Indexer
	namespaceIndexer           clientCache.Indexer
}

func (n *namespaces) Query(ctx context.Context, token string) data.Set {
	ret, err := n.query(ctx, token)
	if err != nil {
		log.Warnf("failed to query Namespaces: %v", err)
	}
	return ret
}

func (n *namespaces) query(ctx context.Context, token string) (data.Set, error) {
	ret := data.Set{}

	tokenNamespace, err := n.validate(ctx, token)
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

func (n *namespaces) validate(ctx context.Context, token string) (string, error) {
	var claimNamespace string
	// parse token
	tokenJwt, _ := jwt.Parse(token, nil)
	claims, _ := tokenJwt.Claims.(jwt.MapClaims)
	// investigate token type
	switch claims["iss"] {
	// bound token
	case "rke":
		claimNamespace, _ = claims["kubernetes.io"].(map[string]interface{})["namespace"].(string)
	// k3s
	case "https://kubernetes.default.svc.cluster.local":
		claimNamespace, _ = claims["kubernetes.io"].(map[string]interface{})["namespace"].(string)
	// legacy token
	case "kubernetes/serviceaccount":
		claimNamespace, _ = claims["kubernetes.io/serviceaccount/namespace"].(string)
	default:
		return "", errors.New("unknown token claim")
	}

	_, exist := n.reviewResultTTLCache.Get(token)
	if exist {
		log.Debugf("token for ns %q is cached", claimNamespace)
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
	reviewResult, err := n.subjectAccessReviewsClient.Create(ctx, sar, meta.CreateOptions{})
	if err != nil {
		return "", errors.Annotatef(err, "failed to review token")
	}

	if !reviewResult.Status.Allowed || reviewResult.Status.Denied {
		return "", fmt.Errorf("token is not allowed to access namespace %q", claimNamespace)
	}

	if reviewResult.Status.Allowed {
		n.reviewResultTTLCache.Add(token, struct{}{}, cacheTTL)
		return claimNamespace, nil
	}

	log.Debugf("token is not allowed to access namespace %q, denied: %s", claimNamespace, reviewResult.Status.Reason)

	return claimNamespace, nil
}

func NewNamespaces(ctx context.Context, k8sClient kubernetes.Interface) Namespaces {
	// secrets
	sec := k8sClient.CoreV1().Secrets(meta.NamespaceAll)
	secListWatch := &clientCache.ListWatch{
		ListFunc: func(options meta.ListOptions) (runtime.Object, error) {
			return sec.List(ctx, options)
		},
		WatchFunc: func(options meta.ListOptions) (watch.Interface, error) {
			return sec.Watch(ctx, options)
		},
	}
	secInformer := clientCache.NewSharedIndexInformer(secListWatch, &core.Secret{}, secretInformerResyncPeriod, clientCache.Indexers{byTokenIndex: secretByToken})

	// namespaces
	ns := k8sClient.CoreV1().Namespaces()
	nsListWatch := &clientCache.ListWatch{
		ListFunc: func(options meta.ListOptions) (runtime.Object, error) {
			return ns.List(ctx, options)
		},
		WatchFunc: func(options meta.ListOptions) (watch.Interface, error) {
			return ns.Watch(ctx, options)
		},
	}
	nsInformer := clientCache.NewSharedIndexInformer(nsListWatch, &core.Namespace{}, nsInformerResyncPeriod, clientCache.Indexers{byProjectIDIndex: namespaceByProjectID})

	// run
	go secInformer.Run(ctx.Done())
	go nsInformer.Run(ctx.Done())

	return &namespaces{
		subjectAccessReviewsClient: k8sClient.AuthorizationV1().SubjectAccessReviews(),
		reviewResultTTLCache:       cache.NewLRUExpireCache(cacheMaxSize),
		secretIndexer:              secInformer.GetIndexer(),
		namespaceIndexer:           nsInformer.GetIndexer(),
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
