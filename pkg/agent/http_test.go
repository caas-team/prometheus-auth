package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/juju/errors"
	"github.com/prometheus/prometheus/promql/promqltest"

	"github.com/caas-team/prometheus-auth/pkg/agent/test"
	"github.com/prometheus/prometheus/tsdb"

	"github.com/caas-team/prometheus-auth/pkg/data"
	"github.com/caas-team/prometheus-auth/pkg/kube"
	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	jsoniter "github.com/json-iterator/go"
	promapi "github.com/prometheus/client_golang/api"
	promapiv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
	"github.com/prometheus/prometheus/promql"
	promtsdb "github.com/prometheus/prometheus/tsdb"
	promweb "github.com/prometheus/prometheus/web"
	"github.com/stretchr/testify/require"
	authentication "k8s.io/api/authentication/v1"
)

type ScenarioType string

const (
	FederateScenario ScenarioType = "federate"
	LabelScenario    ScenarioType = "label"
	QueryScenario    ScenarioType = "query"
	ReadScenario     ScenarioType = "read"
	SeriesScenario   ScenarioType = "series"
)

type httpTestCase struct {
	Type       ScenarioType
	HTTPMethod string
	Token      string
	Scenarios  map[string]test.Scenario
}

func getTestCases(t *testing.T) []httpTestCase {
	return []httpTestCase{
		// noneNamespacesToken
		{
			Type:       FederateScenario,
			HTTPMethod: http.MethodGet,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenFederateScenarios,
		},
		{
			Type:       LabelScenario,
			HTTPMethod: http.MethodGet,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenLabelScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodGet,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenQueryScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodPost,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenQueryScenarios,
		},
		{
			Type:       ReadScenario,
			HTTPMethod: http.MethodPost,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenReadScenarios(t),
		},
		{
			Type:       SeriesScenario,
			HTTPMethod: http.MethodGet,
			Token:      "noneNamespacesToken",
			Scenarios:  test.NoneNamespacesTokenSeriesScenarios,
		},
		// someNamespacesToken
		{
			Type:       FederateScenario,
			HTTPMethod: http.MethodGet,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenFederateScenarios,
		},
		{
			Type:       LabelScenario,
			HTTPMethod: http.MethodGet,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenLabelScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodGet,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenQueryScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodPost,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenQueryScenarios,
		},
		{
			Type:       ReadScenario,
			HTTPMethod: http.MethodPost,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenReadScenarios(t),
		},
		{
			Type:       SeriesScenario,
			HTTPMethod: http.MethodGet,
			Token:      "someNamespacesToken",
			Scenarios:  test.SomeNamespacesTokenSeriesScenarios,
		},
		// myToken
		{
			Type:       FederateScenario,
			HTTPMethod: http.MethodGet,
			Token:      "myToken",
			Scenarios: map[string]test.Scenario{
				"empty": {
					Queries:  url.Values{},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"match nothing": {
					Queries: url.Values{
						"match[]": []string{"does_not_match_anything"},
					},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"invalid Params from the beginning": {
					Queries: url.Values{
						"match[]": []string{"-not-a-valid-metric-name"},
					},
					RespCode: http.StatusBadRequest,
					RespBody: `1:1: parse error: unexpected <op:->
`,
				},
				"invalid Params somewhere in the middle": {
					Queries: url.Values{
						"match[]": []string{"not-a-valid-metric-name"},
					},
					RespCode: http.StatusBadRequest,
					RespBody: `1:4: parse error: unexpected <op:->
`,
				},
				"test_metric1": {
					Queries: url.Values{
						"match[]": []string{"test_metric1"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"test_metric2": {
					Queries: url.Values{
						"match[]": []string{"test_metric2"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"test_metric_without_labels": {
					Queries: url.Values{
						"match[]": []string{"test_metric_without_labels"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"test_stale_metric": {
					Queries: url.Values{
						"match[]": []string{"test_metric_stale"},
					},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"test_old_metric": {
					Queries: url.Values{
						"match[]": []string{"test_metric_old"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
`,
				},
				"{foo='boo'}": {
					Queries: url.Values{
						"match[]": []string{"{foo='boo'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"{namespace='ns-c'}": {
					Queries: url.Values{
						"match[]": []string{"{namespace='ns-c'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"two matchers": {
					Queries: url.Values{
						"match[]": []string{"test_metric1", "test_metric2"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"everything": {
					Queries: url.Values{
						"match[]": []string{"{__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty existing label value matches everything that doesn't have that label": {
					Queries: url.Values{
						"match[]": []string{"{foo='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty none-existing label value matches everything": {
					Queries: url.Values{
						"match[]": []string{"{bar='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty `namespace` label value matches everything that doesn't have `namespace` label": {
					Queries: url.Values{
						"match[]": []string{"{namespace='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
			},
		},
		{
			Type:       LabelScenario,
			HTTPMethod: http.MethodGet,
			Token:      "myToken",
			Scenarios:  test.MyTokenLabelScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodGet,
			Token:      "myToken",
			Scenarios:  test.MyTokenQueryScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodPost,
			Token:      "myToken",
			Scenarios:  test.MyTokenQueryScenarios,
		},
		{
			Type:       ReadScenario,
			HTTPMethod: http.MethodPost,
			Token:      "myToken",
			Scenarios:  test.MyTokenReadScenarios(t),
		},
		{
			Type:       SeriesScenario,
			HTTPMethod: http.MethodGet,
			Token:      "myToken",
			Scenarios:  test.MyTokenSeriesScenarios,
		},
		// unauthenticated
		{
			Type:       FederateScenario,
			HTTPMethod: http.MethodGet,
			Token:      "unauthenticated",
			Scenarios: map[string]test.Scenario{
				"empty": {
					Queries:  url.Values{},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"match nothing": {
					Queries: url.Values{
						"match[]": []string{"does_not_match_anything"},
					},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"invalid Params from the beginning": {
					Queries: url.Values{
						"match[]": []string{"-not-a-valid-metric-name"},
					},
					RespCode: http.StatusBadRequest,
					RespBody: `1:1: parse error: unexpected <op:->
`,
				},
				"invalid Params somewhere in the middle": {
					Queries: url.Values{
						"match[]": []string{"not-a-valid-metric-name"},
					},
					RespCode: http.StatusBadRequest,
					RespBody: `1:4: parse error: unexpected <op:->
`,
				},
				"test_metric1": {
					Queries: url.Values{
						"match[]": []string{"test_metric1"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"test_metric2": {
					Queries: url.Values{
						"match[]": []string{"test_metric2"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"test_metric_without_labels": {
					Queries: url.Values{
						"match[]": []string{"test_metric_without_labels"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"test_stale_metric": {
					Queries: url.Values{
						"match[]": []string{"test_metric_stale"},
					},
					RespCode: http.StatusOK,
					RespBody: ``,
				},
				"test_old_metric": {
					Queries: url.Values{
						"match[]": []string{"test_metric_old"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
`,
				},
				"{foo='boo'}": {
					Queries: url.Values{
						"match[]": []string{"{foo='boo'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"{namespace='ns-c'}": {
					Queries: url.Values{
						"match[]": []string{"{namespace='ns-c'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"two matchers": {
					Queries: url.Values{
						"match[]": []string{"test_metric1", "test_metric2"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
`,
				},
				"everything": {
					Queries: url.Values{
						"match[]": []string{"{__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty existing label value matches everything that doesn't have that label": {
					Queries: url.Values{
						"match[]": []string{"{foo='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty none-existing label value matches everything": {
					Queries: url.Values{
						"match[]": []string{"{bar='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_cluster_wide_metric untyped
test_cluster_wide_metric{namespace="caasglobal",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric1 untyped
test_metric1{foo="bar",namespace="ns-a",instance="",prometheus="cluster-level/test"} 10000 6000000
test_metric1{foo="boo",namespace="ns-c",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
				"empty `namespace` label value matches everything that doesn't have `namespace` label": {
					Queries: url.Values{
						"match[]": []string{"{namespace='',__name__=~'.+'}"},
					},
					RespCode: http.StatusOK,
					RespBody: `# TYPE test_metric2 untyped
test_metric2{foo="boo",instance="",prometheus="cluster-level/test"} 1 6000000
# TYPE test_metric_old untyped
test_metric_old{instance="",prometheus="cluster-level/test"} 981 5880000
# TYPE test_metric_without_labels untyped
test_metric_without_labels{instance="",prometheus="cluster-level/test"} 1001 6000000
`,
				},
			},
		},
		{
			Type:       LabelScenario,
			HTTPMethod: http.MethodGet,
			Token:      "unauthenticated",
			Scenarios:  test.MyTokenLabelScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodGet,
			Token:      "unauthenticated",
			Scenarios:  test.MyTokenQueryScenarios,
		},
		{
			Type:       QueryScenario,
			HTTPMethod: http.MethodPost,
			Token:      "unauthenticated",
			Scenarios:  test.MyTokenQueryScenarios,
		},
		{
			Type:       ReadScenario,
			HTTPMethod: http.MethodPost,
			Token:      "unauthenticated",
			Scenarios:  test.MyTokenReadScenarios(t),
		},
		{
			Type:       SeriesScenario,
			HTTPMethod: http.MethodGet,
			Token:      "unauthenticated",
			Scenarios:  test.MyTokenSeriesScenarios,
		},
	}
}

func Test_accessControl(t *testing.T) {
	// the contents of the prom TSDB
	input := `
		load 1m
			test_metric1{namespace="ns-a",foo="bar"}    	0+100x100
			test_metric1{namespace="ns-c",foo="boo"}    	1+0x100
			test_metric2{foo="boo"}    						1+0x100
			test_cluster_wide_metric{namespace="caasglobal"} 1+0x100
			test_metric_without_labels 						1+10x100
			test_metric_stale                      	 		1+10x99 stale
			test_metric_old                         		1+10x98
	`
	storage := promqltest.LoadedStorage(t, input)
	engine := promql.NewEngine(promql.EngineOpts{
		Timeout:    5 * time.Second,
		MaxSamples: 1000,
	})
	promqltest.RunTest(t, input, engine)

	dbDir, err := os.MkdirTemp("", "tsdb-ready")
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(dbDir)

	require.NoError(t, err)

	webHandler := promweb.New(slog.New(slog.NewJSONHandler(os.Stderr, nil)), &promweb.Options{
		Context:         context.Background(),
		ListenAddresses: []string{":9090"},
		ReadTimeout:     30 * time.Second,
		MaxConnections:  512,
		Storage:         storage,
		QueryEngine:     engine,
		ScrapeManager:   nil,
		RuleManager:     nil,
		Notifier:        nil,
		RoutePrefix:     "/",
		EnableAdminAPI:  true,
		ExternalURL: &url.URL{
			Scheme: "http",
			Host:   "localhost:9090",
			Path:   "/",
		},
		TSDBDir:      dbDir,
		LocalStorage: &dbAdapter{storage.DB},
		Version:      &promweb.PrometheusVersion{},
		Flags:        map[string]string{},

		// Federate
		LookbackDelta: 5 * time.Minute,

		// Remote Read
		RemoteReadSampleLimit:      1e6,
		RemoteReadConcurrencyLimit: 1,
		RemoteReadBytesInFrame:     0,
	})
	defer webHandler.Quit()

	err = webHandler.ApplyConfig(&config.Config{
		GlobalConfig: config.GlobalConfig{
			ExternalLabels: labels.Labels{{Name: "prometheus", Value: "cluster-level/test"}},
		},
	})
	if err != nil {
		t.Error(err)
	}

	// modify the `now` field
	refVal := reflect.ValueOf(webHandler).Elem()
	nowMemberVal := refVal.FieldByName("now")
	ptrToNow := unsafe.Pointer(nowMemberVal.UnsafeAddr())
	realPtrToNow := (*func() model.Time)(ptrToNow)
	*realPtrToNow = func() model.Time { return model.Time(101 * 60 * 1000) } // 101min, federation is set to have a 5 min `LookbackDelta`
	apiV1MemberVal := refVal.FieldByName("apiV1").Elem()
	nowMemberVal2 := apiV1MemberVal.FieldByName("now")
	ptrToNow2 := unsafe.Pointer(nowMemberVal2.UnsafeAddr())
	realPtrToNow2 := (*func() time.Time)(ptrToNow2)
	*realPtrToNow2 = func() time.Time { return model.Time(0).Time() }

	startPrometheusWebHandler(t, webHandler)

	agt := mockAgent(t)
	httpBackend := agt.httpBackend(nil)
	for _, tc := range getTestCases(t) {
		tcName := fmt.Sprintf("%s/%s/%s", tc.Type, tc.HTTPMethod, tc.Token)
		// Run each test case
		t.Run(tcName, func(t *testing.T) {
			for name, tokenScenario := range tc.Scenarios {
				// Run each scenario within a test case
				ScenarioValidator{
					Name:     name,
					Type:     tc.Type,
					Method:   tc.HTTPMethod,
					Token:    tc.Token,
					Scenario: &tokenScenario,
				}.Validate(t, httpBackend)
			}
		})
	}
}

func startPrometheusWebHandler(t *testing.T, webHandler *promweb.Handler) {
	l, err := webHandler.Listeners()
	if err != nil {
		panic(fmt.Sprintf("Unable to start web listener: %s", err))
	}

	go func() {
		err := webHandler.Run(context.Background(), l, "")
		if err != nil {
			panic(fmt.Sprintf("Can't start web handler:%s", err))
		}
	}()

	time.Sleep(5 * time.Second)

	resp, err := http.Get("http://localhost:9090/-/healthy")

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get("http://localhost:9090/-/ready")

	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	resp, err = http.Post("http://localhost:9090/api/v1/admin/tsdb/snapshot", "", strings.NewReader(""))

	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	resp, err = http.Post("http://localhost:9090/api/v1/admin/tsdb/delete_series", "", strings.NewReader("{}"))

	require.NoError(t, err)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// Set to ready.
	webHandler.SetReady(promweb.Ready)

	resp, err = http.Get("http://localhost:9090/-/healthy")

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Get("http://localhost:9090/-/ready")

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Post("http://localhost:9090/api/v1/admin/tsdb/snapshot", "", strings.NewReader(""))

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = http.Post("http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]=up", "", nil)

	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func mockAgent(t *testing.T) *agent {
	proxyURL, err := url.Parse("http://localhost:9090")
	if err != nil {
		t.Error(err)
	}

	agtCfg := &agentConfig{
		ctx:      context.Background(),
		myToken:  "myToken",
		proxyURL: proxyURL,
		filterReaderLabelSet: data.NewSet(
			"prometheus",
			"prometheus_replica",
		),
	}

	// create Prometheus client
	promClient, err := promapi.NewClient(promapi.Config{
		Address: proxyURL.String(),
	})
	if err != nil {
		t.Error(err)
	}

	return &agent{
		cfg: agtCfg,
		userInfo: authentication.UserInfo{
			Username: "myUser",
			UID:      "cluster-admin",
		},
		namespaces: mockOwnedNamespaces(),
		tokens:     mockTokenAuth(),
		remoteAPI:  promapiv1.NewAPI(promClient),
	}
}

type ScenarioValidator struct {
	Name     string
	Type     ScenarioType
	Method   string
	Token    string
	Scenario *test.Scenario
}

func (v ScenarioValidator) Validate(t *testing.T, handler http.Handler) {
	res := v.executeRequest(t, handler)
	if res == nil {
		return
	}

	// Validate unauthenticated user
	if v.Token == "unauthenticated" {
		// unauthenticated user
		if got := res.Code; got != http.StatusUnauthorized {
			t.Errorf("[series] [GET] token %q scenario %q: got code %d, want %d for unauthenticated users", v.Token, v.Name, got, http.StatusUnauthorized)
		}
		return
	}

	// Validate response code
	if got, want := res.Code, v.Scenario.RespCode; got != want {
		t.Errorf("[series] [GET] token %q scenario %q: got code %d, want %d", v.Token, v.Name, got, want)
	}

	// Validate response
	switch v.Type {
	case FederateScenario:
		v.validateTextBody(t, res)
	case ReadScenario:
		v.validateProtoBody(t, res)
	default:
		v.validateJSONBody(t, res)
	}
}

func (v ScenarioValidator) executeRequest(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	url := "http://localhost:9090" // base url that federator is expected to be hosted at
	headers := map[string]string{
		authorizationHeaderKey: fmt.Sprintf("Bearer %s", v.Token),
	}
	var body io.Reader

	switch v.Type {
	case FederateScenario:
		switch v.Method {
		case http.MethodGet:
			url = fmt.Sprintf("%s/federate?%s", url, v.Scenario.Queries.Encode())
		default:
			t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
			return nil
		}
	case LabelScenario:
		switch v.Method {
		case http.MethodGet:
			url = fmt.Sprintf("%s/api/v1/label/%s/values", url, v.Scenario.Params["name"])
		default:
			t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
			return nil
		}
	case QueryScenario:
		switch v.Method {
		case http.MethodGet:
			url = fmt.Sprintf("%s/api/v1%s?%s", url, v.Scenario.Endpoint, v.Scenario.Queries.Encode())
		case http.MethodPost:
			url = fmt.Sprintf("%s/api/v1%s", url, v.Scenario.Endpoint)
			body = strings.NewReader(v.Scenario.Queries.Encode())
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		default:
			t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
			return nil
		}
	case ReadScenario:
		switch v.Method {
		case http.MethodPost:
			url = fmt.Sprintf("%s/api/v1/read", url)
			// raw -> proto request
			protoReq := &prompb.ReadRequest{Queries: v.Scenario.PrompbQueries}
			protoReqData, err := proto.Marshal(protoReq)
			if err != nil {
				t.Fatal(err)
			}
			compressedProtoReqData := snappy.Encode(nil, protoReqData)
			body = bytes.NewBuffer(compressedProtoReqData)
		default:
			t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
			return nil
		}
	case SeriesScenario:
		switch v.Method {
		case http.MethodGet:
			url = fmt.Sprintf("%s/api/v1/series?%s", url, v.Scenario.Queries.Encode())
		default:
			t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
			return nil
		}
	default:
		t.Errorf("[%s] [%s] token %q scenario %q: cannot identify URL to send request", v.Type, v.Method, v.Token, v.Name)
		return nil
	}

	// Execute request
	req := httptest.NewRequest(v.Method, url, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	return res
}

func (v ScenarioValidator) validateTextBody(t *testing.T, res *httptest.ResponseRecorder) {
	if got, want := normalizeResponseBody(res.Body), v.Scenario.RespBody; got != want {
		t.Errorf("[%s] [%s] token %q scenario %q: got body\n%s\n, want\n%s\n", v.Type, v.Method, v.Token, v.Name, got, want)
	}
}

func (v ScenarioValidator) validateProtoBody(t *testing.T, res *httptest.ResponseRecorder) {
	// proto response -> raw
	compressedProtoResData, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	protoResData, err := snappy.Decode(nil, compressedProtoResData)
	if err != nil {
		t.Fatal(err)
	}
	var protoRes prompb.ReadResponse
	err = proto.Unmarshal(protoResData, &protoRes)
	if err != nil {
		t.Fatal(err)
	}

	sortReadResponse(&protoRes)

	if got, want := protoRes.Results, v.Scenario.RespBody; !reflect.DeepEqual(got, want) {
		t.Errorf("[%s] [%s] token %q scenario %q: got body\n%v\n, want\n%v\n", v.Type, v.Method, v.Token, v.Name, got, want)
	}
}

func (v ScenarioValidator) validateJSONBody(t *testing.T, res *httptest.ResponseRecorder) {
	if got, want := res.Body.String(), jsonResponseBody(v.Scenario.RespBody); got != want {
		t.Errorf("[%s] [%s] token %q scenario %q: got body\n%s\n, want\n%s\n", v.Type, v.Method, v.Token, v.Name, got, want)
	}
}

func normalizeResponseBody(body *bytes.Buffer) string {
	var (
		lines    []string
		lastHash int
	)
	for line, err := body.ReadString('\n'); err == nil; line, err = body.ReadString('\n') {
		if line[0] == '#' && len(lines) > 0 {
			sort.Strings(lines[lastHash+1:])
			lastHash = len(lines)
		}
		lines = append(lines, line)
	}
	if len(lines) > 0 {
		sort.Strings(lines[lastHash+1:])
	}
	return strings.Join(lines, "")
}

func jsonResponseBody(body interface{}) string {
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	respBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Sprintf(`{"error": "%s"}`, err.Error())
	}

	return string(respBytes)
}

type SortableTimeSeries []*prompb.TimeSeries

func (s SortableTimeSeries) Len() int {
	return len(s)
}

func (s SortableTimeSeries) Less(i, j int) bool {
	k := 0
	for k < len(s[i].Labels) && k < len(s[j].Labels) {
		// compare keys
		if s[i].Labels[k].Name != s[j].Labels[k].Name {
			return s[i].Labels[k].Name < s[j].Labels[k].Name
		}
		// compare values
		if s[i].Labels[k].Value != s[j].Labels[k].Value {
			return s[i].Labels[k].Value < s[j].Labels[k].Value
		}
		k += 1
	}
	// default to preserving order
	return true
}

func (s SortableTimeSeries) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func sortReadResponse(rr *prompb.ReadResponse) {
	for _, q := range rr.Results {
		sort.Sort(SortableTimeSeries(q.Timeseries))
	}
}

type fakeOwnedNamespaces struct {
	token2Namespaces map[string]data.Set
}

func (f *fakeOwnedNamespaces) Query(ctx context.Context, token string) data.Set {
	return f.token2Namespaces[token]
}

func mockOwnedNamespaces() kube.Namespaces {
	return &fakeOwnedNamespaces{
		token2Namespaces: map[string]data.Set{
			"noneNamespacesToken": {},
			"someNamespacesToken": data.NewSet("ns-a", "ns-b"),
		},
	}
}

type fakeTokenAuth struct {
	token2UserInfo map[string]authentication.UserInfo
}

func (f *fakeTokenAuth) Authenticate(ctx context.Context, token string) (authentication.UserInfo, error) {
	userInfo, ok := f.token2UserInfo[token]
	if !ok {
		return userInfo, errors.New("user is not authenticated")
	}
	return userInfo, nil
}

func mockTokenAuth() kube.Tokens {
	return &fakeTokenAuth{
		token2UserInfo: map[string]authentication.UserInfo{
			"myToken": {
				Username: "myUser",
				UID:      "cluster-admin",
			},
			"someNamespacesToken": {
				Username: "someNamespacesUser",
				UID:      "project-member",
			},
			"noneNamespacesToken": {
				Username: "noneNamespacesUser",
				UID:      "cluster-member",
			},
		},
	}
}

type dbAdapter struct {
	*tsdb.DB
}

func (a *dbAdapter) Stats(statsByLabelName string, limit int) (*promtsdb.Stats, error) {
	return a.Stats(statsByLabelName, limit)
}

func (a *dbAdapter) WALReplayStatus() (promtsdb.WALReplayStatus, error) {
	return promtsdb.WALReplayStatus{}, nil
}
