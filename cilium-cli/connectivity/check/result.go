// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type Result struct {
	// Request is dropped
	Drop bool

	// Request is dropped at Egress
	EgressDrop bool

	// Request is dropped at Ingress
	IngressDrop bool

	// DropReasonFunc
	DropReasonFunc func(flow *flowpb.Flow) bool

	// Metrics holds the function to compare/check metrics.
	Metrics []MetricsResult

	// No flows are to be expected. Used for ingress when egress drops
	None bool

	// DNSProxy is true when DNS Proxy is to be expected, only valid for egress
	DNSProxy bool

	// L7Proxy is true when L7 proxy (e.g., Envoy) is to be expected
	L7Proxy bool

	// HTTPStatus is non-zero when a HTTP status code in response is to be expected
	HTTP HTTP

	// ExitCode is the expected shell exit code
	ExitCode ExitCode
}

// MetricsResult holds the source of metrics we want to assert and its assertion method.
type MetricsResult struct {
	Source MetricsSource
	Assert assertMetricsFunc
}

type assertMetricsFunc func(map[string]*dto.MetricFamily, map[string]*dto.MetricFamily) error

// IsEmpty returns true if MetricsResult does not have any source.
// Assuming it corresponds to its zero value.
func (m MetricsResult) IsEmpty() bool {
	return m.Source.Name == ""
}

type HTTP struct {
	Status string
	Method string
	URL    string
}

type ExitCode int16

const (
	ExitAnyError    ExitCode = -1
	ExitInvalidCode ExitCode = -2

	ExitCurlHTTPError ExitCode = 22
	ExitCurlTimeout   ExitCode = 28

	ExitCurlSSLError ExitCode = 35
)

var (
	// ResultNone expects a successful command, don't match any packets.
	ResultNone = Result{
		None: true,
	}

	// ResultCurlTimeout expects a failed command, don't match any packets.
	ResultCurlTimeout = Result{
		ExitCode: ExitCurlTimeout,
	}

	// ResultOK expects a successful command and a matching flow.
	ResultOK = Result{}

	// ResultDNSOK expects a successful command, only generating DNS traffic.
	ResultDNSOK = Result{
		DNSProxy: true,
	}

	// ResultDNSOKDropCurlTimeout expects a failed command, generating DNS traffic and a dropped flow.
	ResultDNSOKDropCurlTimeout = Result{
		DNSProxy:       true,
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlTimeout,
	}

	// ResultDNSOKDropCurlHTTPError expects a failed command, generating DNS traffic and a dropped flow.
	ResultDNSOKDropCurlHTTPError = Result{
		DNSProxy:       true,
		L7Proxy:        true,
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlHTTPError,
	}

	// ResultCurlHTTPError expects a failed command, but no dropped flow or DNS proxy.
	ResultCurlHTTPError = Result{
		L7Proxy:        true,
		Drop:           false,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlHTTPError,
	}

	// ResultCurlSSLError expects a failed command with SSL error, but no dropped flow or DNS proxy.
	ResultCurlSSLError = Result{
		L7Proxy:        true,
		Drop:           false,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlSSLError,
	}

	// ResultDrop expects a dropped flow and a failed command.
	ResultDrop = Result{
		Drop:           true,
		ExitCode:       ExitAnyError,
		DropReasonFunc: defaultDropReason,
	}

	// ResultDropAuthRequired expects a dropped flow with auth required as reason.
	ResultDropAuthRequired = Result{
		Drop:           true,
		DropReasonFunc: authRequiredDropReason,
	}

	// ResultAnyReasonEgressDrop expects a dropped flow at Egress and a failed command.
	ResultAnyReasonEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultPolicyDenyEgressDrop expects a dropped flow at Egress due to policy deny and a failed command.
	ResultPolicyDenyEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: policyDenyReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultDefaultDenyEgressDrop expects a dropped flow at Egress due to default deny and a failed command.
	ResultDefaultDenyEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: defaultDenyReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultIngressAnyReasonDrop expects a dropped flow at Ingress and a failed command.
	ResultIngressAnyReasonDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitAnyError,
	}

	// ResultPolicyDenyIngressDrop expects a dropped flow at Ingress due to policy deny reason and a failed command.
	ResultPolicyDenyIngressDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: policyDenyReason,
		ExitCode:       ExitAnyError,
	}

	// ResultDefaultDenyIngressDrop expects a dropped flow at Ingress due to default deny reason and a failed command.
	ResultDefaultDenyIngressDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: defaultDenyReason,
		ExitCode:       ExitAnyError,
	}

	ResultEgressUnencryptedDrop = Result{
		Drop:           true,
		EgressDrop:     true,
		DropReasonFunc: unencryptedDropReason,
		ExitCode:       ExitCurlTimeout,
	}

	// ResultDropCurlTimeout expects a dropped flow and a failed command.
	ResultDropCurlTimeout = Result{
		Drop:     true,
		ExitCode: ExitCurlTimeout,
	}

	// ResultDropCurlHTTPError expects a dropped flow and a failed command.
	ResultDropCurlHTTPError = Result{
		L7Proxy:  true,
		Drop:     true,
		ExitCode: ExitCurlHTTPError,
	}
)

func (e ExitCode) String() string {
	switch e {
	case ExitAnyError:
		return "any"
	case ExitInvalidCode:
		return "invalid"
	default:
		return strconv.Itoa(int(e))
	}
}

func (e ExitCode) Check(code uint8) bool {
	switch e {
	case ExitAnyError:
		return code != 0
	case ExitCode(code):
		return true
	}
	return false
}

func (r Result) String() string {
	if r.None {
		return "None"
	}
	ret := "Allow"
	if r.Drop {
		ret = "Drop"
	}
	if r.DNSProxy {
		ret += "-DNS"
	}
	if r.L7Proxy {
		ret += "-L7"
	}
	if r.HTTP.Status != "" || r.HTTP.Method != "" || r.HTTP.URL != "" {
		ret += "-HTTP"
	}
	if r.HTTP.Method != "" {
		ret += "-"
		ret += r.HTTP.Method
	}
	if r.HTTP.URL != "" {
		ret += "-"
		ret += r.HTTP.URL
	}
	if r.HTTP.Status != "" {
		ret += "-"
		ret += r.HTTP.Status
	}
	if r.Metrics != nil {
		ret += displayMetricsSources(r.Metrics)
	}
	if r.ExitCode >= 0 && r.ExitCode <= 255 {
		ret += fmt.Sprintf("-exit(%d)", r.ExitCode)
	}
	return ret
}

func displayMetricsSources(metrics []MetricsResult) string {
	var ret string
	ret += "-MetricsSources("
	sources := make([]string, 0)
	for _, m := range metrics {
		sources = append(sources, m.Source.Name)
	}
	ret += strings.Join(sources, ",")
	ret += ")"

	return ret
}

// ExpectMetricsIncrease compares metrics retrieved before any action were run and after;
// may return an error if metrics did not increase.
func (r Result) ExpectMetricsIncrease(source MetricsSource, metrics ...string) Result {
	if source.IsEmpty() {
		return r
	}

	res := MetricsResult{
		Source: source,
		Assert: assertMetricsIncrease(metrics...),
	}
	r.Metrics = append(r.Metrics, res)
	return r
}

// assertMetricsIncrease returns the function used to check the metrics increase between and after an action.
func assertMetricsIncrease(metrics ...string) assertMetricsFunc {
	return func(before, after map[string]*dto.MetricFamily) error {
		var err error
		for _, metricName := range metrics {
			// beforeValue can be absent, we will consider it as nil by default.
			beforeValue := before[metricName]

			afterValue, ok := after[metricName]
			if !ok {
				err = errors.Join(err, fmt.Errorf("metric %s has not been retrieved after action", metricName))
			}

			// Additional check needed because previously we do not return in case of error, otherwise we will panic!
			if afterValue != nil {
				errM := metricsIncrease(beforeValue, afterValue)
				if errM != nil {
					err = errors.Join(err, errM)
				}
			}
		}
		return err
	}
}
