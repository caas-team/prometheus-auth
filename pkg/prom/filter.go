package prom

import (
	"github.com/caas-team/prometheus-auth/pkg/data"
	promlb "github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/prompb"
)

const (
	NamespaceMatchName         = "namespace"
	ExportedNamespaceMatchName = "exported_namespace"
)

// FilterMatchers updates the prometheus matchers to include the passed
// label matcher. If the passed label matches one of the predefined ones,
// the matchers' value will be updated to contain only the namespaceSet.
func FilterMatchers(namespaceSet data.Set, srcMatchers []*promlb.Matcher, label string) []*promlb.Matcher {
	for _, m := range srcMatchers {
		name := m.Name

		if name == NamespaceMatchName || name == ExportedNamespaceMatchName {
			translateMatcher(namespaceSet, m)
			return srcMatchers
		}
	}

	srcMatchers = append(srcMatchers, createMatcher(label, namespaceSet.Values()))

	return srcMatchers
}

func FilterLabelMatchers(namespaceSet data.Set, srcMatchers []*prompb.LabelMatcher) []*prompb.LabelMatcher {
	for _, m := range srcMatchers {
		name := m.Name

		if name == NamespaceMatchName {
			translateLabelMatcher(namespaceSet, m)
			return srcMatchers
		}
	}

	// append namespace match
	srcMatchers = append(srcMatchers, createLabelMatcher(NamespaceMatchName, namespaceSet.Values()))

	return srcMatchers
}
