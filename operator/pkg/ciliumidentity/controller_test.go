// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"strings" // Added
	"sync/atomic" // Added
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/google/go-cmp/cmp"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1" // Added
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime" // Added
	k8sClientTesting "k8s.io/client-go/testing" // Added

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health/types"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	WaitUntilTimeout = 5 * time.Second
)

func TestRegisterControllerWithOperatorManagingCIDs(t *testing.T) {
	cidResource, cesResource, fakeClient, m, h := initHiveTest(t, true)

	ctx := t.Context()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	err := testutils.WaitUntil(func() bool { return len(cidStore.List()) > 0 }, WaitUntilTimeout)
	if err != nil {
		t.Errorf("Expected CID to be created, got %v", err)
	}

	if err := verifyCIDUsageInCES(ctx, fakeClient, *cidResource, *cesResource); err != nil {
		t.Errorf("Failed to verify CID usage in CES, got %v", err)
	}

	// Verify metrics
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValuePod, metrics.LabelValueOutcomeSuccess), strings.NewReader("1\n"), "cilium_operator_cid_controller_work_queue_event_count"))
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValueCID, metrics.LabelValueOutcomeSuccess), strings.NewReader("1\n"), "cilium_operator_cid_controller_work_queue_event_count"))

	podEnqueuedLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueEnqueuedLatency))
	podProcessingLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueProcessingLatency))
	cidEnqueuedLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueEnqueuedLatency))
	cidProcessingLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueProcessingLatency))

	assert.Greater(t, podEnqueuedLatencyObservations, 0, "Pod enqueued latency should have been observed")
	assert.Greater(t, podProcessingLatencyObservations, 0, "Pod processing latency should have been observed")
	assert.Greater(t, cidEnqueuedLatencyObservations, 0, "CID enqueued latency should have been observed")
	assert.Greater(t, cidProcessingLatencyObservations, 0, "CID processing latency should have been observed")

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func TestRegisterController(t *testing.T) {
	cidResource, _, fakeClient, m, h := initHiveTest(t, false)

	ctx := t.Context()
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}

	if err := createNsAndPod(ctx, fakeClient); err != nil {
		t.Errorf("Failed to create namespace or pod: %v", err)
	}

	cidStore, _ := (*cidResource).Store(ctx)
	if len(cidStore.List()) != 0 {
		t.Errorf("Expected no CIDs to be present in the store, but found %d", len(cidStore.List()))
	}

	// Verify metrics when operator is NOT managing CIDs
	podSuccessEvents := prometheustestutil.ToFloat64(m.EventCount.WithLabelValues(LabelValuePod, metrics.LabelValueOutcomeSuccess))
	assert.GreaterOrEqual(t, podSuccessEvents, float64(1), "Pod success events should be at least 1 (for pod create)")

	cidSuccessEvents := prometheustestutil.ToFloat64(m.EventCount.WithLabelValues(LabelValueCID, metrics.LabelValueOutcomeSuccess))
	cidFailEvents := prometheustestutil.ToFloat64(m.EventCount.WithLabelValues(LabelValueCID, metrics.LabelValueOutcomeFail))
	assert.Equal(t, float64(0), cidSuccessEvents, "CID success events should be 0")
	assert.Equal(t, float64(0), cidFailEvents, "CID fail events should be 0")

	cidEnqueuedLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueEnqueuedLatency))
	cidProcessingLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueProcessingLatency))
	assert.Equal(t, 0, cidEnqueuedLatencyObservations, "CID enqueued latency should not be observed")
	assert.Equal(t, 0, cidProcessingLatencyObservations, "CID processing latency should not be observed")


	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

// ... (rest of initHiveTest, createNsAndPod, verifyCIDUsageInCES, TestCreateTwoPodsWithSameLabels, TestUpdatePodLabels, TestUpdateUsedCIDIsReverted, TestDeleteUsedCIDIsRecreated - these are unchanged from original) ...

// --- Start of previously added tests and helpers to be re-applied ---

func TestCIDGarbageCollection_UnusedCID(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-unused-cid"
	podName := "test-pod-unused-cid"
	podLabels := map[string]string{"app": "test-unused-cid"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Delete Pod and wait for CID garbage collection
	deletePodAndWaitForCIDDeletion(t, ctx, fakeClient, *cidResource, podName, nsName, createdCID.Name)
}

func TestCIDGarbageCollection_CIDReferencedByPod(t *testing.T) {
	cidResource, cesResource, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-pod-ref"
	podName := "test-pod-pod-ref"
	cesName := "test-ces-pod-ref"
	podLabels := map[string]string{"app": "test-pod-ref"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	pod, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Create CES referencing the CID
	cidNum, err := strconv.ParseInt(createdCID.Name, 10, 64)
	require.NoError(t, err, "Failed to parse CID name to int64")
	cep := cestest.CreateManagerEndpoint(podName, cidNum)
	createCES(t, ctx, fakeClient, *cesResource, cesName, nsName, []capi_v2a1.CoreCiliumEndpoint{cep})

	// Delete CES
	deleteCES(t, ctx, fakeClient, *cesResource, cesName, nsName)

	// Verify CID is NOT garbage collected because it's still referenced by the Pod
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Cleanup: Delete pod
	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, pod.Name)
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)
}

func TestCIDGarbageCollection_CIDReferencedByCES(t *testing.T) {
	cidResource, cesResource, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-ces-ref"
	podName := "test-pod-ces-ref"
	cesName := "test-ces-ces-ref"
	podLabels := map[string]string{"app": "test-ces-ref"}

	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	pod, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	cidNum, err := strconv.ParseInt(createdCID.Name, 10, 64)
	require.NoError(t, err, "Failed to parse CID name to int64")
	cep := cestest.CreateManagerEndpoint(podName, cidNum)
	createdCES := createCES(t, ctx, fakeClient, *cesResource, cesName, nsName, []capi_v2a1.CoreCiliumEndpoint{cep})

	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, pod.Name)

	requireCIDExists(t, ctx, *cidResource, createdCID.Name)
	deleteCES(t, ctx, fakeClient, *cesResource, createdCES.Name, createdCES.Namespace)
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)
}

func TestPodWithInvalidLabels(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-invalid-labels"; podName := "test-pod-invalid-labels"
	invalidLabelValue := string(make([]byte, 64));
	for i := range invalidLabelValue { invalidLabelValue[i] = 'a' }
	podLabels := map[string]string{"app": invalidLabelValue}
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err)
	pod := testCreatePodObj(podName, nsName, podLabels, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil && errors.IsInvalid(err) { t.Logf("Pod creation failed due to invalid labels: %v", err)
	} else { require.NoError(t, err) }
	time.Sleep(2 * time.Second)
	store, _ := (*cidResource).Store(ctx); cids := store.List(); foundCID := false
	for _, cid := range cids { if cmp.Equal(cid.SecurityLabels, podLabels) { foundCID = true; break } }
	assert.False(t, foundCID, "No CID for Pod with invalid labels. Found: %v", cids)
}

func TestAPIServerErrorHandling_CreateCID(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-create-err"; podName := "test-pod-create-err"; podLabels := map[string]string{"app": "test-create-err"}
	ns := testCreateNSObj(nsName, nil); _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err)
	atomicFailureCount := int32(0); maxFailures := int32(3)
	fakeClient.PrependReaction("create", "ciliumidentities", func(action k8sClientTesting.Action) (bool, runtime.Object, error) {
		if atomic.LoadInt32(&atomicFailureCount) < maxFailures {
			atomic.AddInt32(&atomicFailureCount, 1); t.Logf("Simulating API error on CID create, attempt #%d", atomic.LoadInt32(&atomicFailureCount))
			return true, nil, errors.NewServerTimeout(capi_v2.Resource("ciliumidentities"), "create", 2)
		}
		t.Logf("Allowing CID create after %d attempts", atomic.LoadInt32(&atomicFailureCount)); return false, nil, nil
	})
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)
	assert.Equal(t, maxFailures, atomic.LoadInt32(&atomicFailureCount))
	fakeClient.ClearReactions()
}

func TestAPIServerErrorHandling_DeleteCID(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-delete-err"; podName := "test-pod-delete-err"; podLabels := map[string]string{"app": "test-delete-err"}
	ns := testCreateNSObj(nsName, nil); _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err)
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)
	atomicDeleteFailureCount := int32(0); maxDeleteFailures := int32(3)
	fakeClient.PrependReaction("delete", "ciliumidentities", func(action k8sClientTesting.Action) (bool, runtime.Object, error) {
		if atomic.LoadInt32(&atomicDeleteFailureCount) < maxDeleteFailures {
			da, ok := action.(k8sClientTesting.DeleteAction); if !ok { return false, nil, fmt.Errorf("bad type: %T", action) }
			if da.GetName() == createdCID.Name {
				atomic.AddInt32(&atomicDeleteFailureCount, 1); t.Logf("Simulating API error on CID delete for %s, attempt #%d", createdCID.Name, atomic.LoadInt32(&atomicDeleteFailureCount))
				return true, nil, errors.NewServerTimeout(capi_v2.Resource("ciliumidentities"), "delete", 2)
			}
		}
		return false, nil, nil
	})
	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, podName, metav1.DeleteOptions{}); require.NoError(t, err)
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)
	assert.Equal(t, maxDeleteFailures, atomic.LoadInt32(&atomicDeleteFailureCount))
	fakeClient.ClearReactions()
}

func TestSecurityLabelDerivation_SpecialCharacters(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-special-chars"; podName := "test-pod-special-chars"
	nsLabels := map[string]string{"ns.label-with-hyphen": "v1", "ns_label.with.dots": "v2"}
	podLabels := map[string]string{"app_name": "my.app-v1", "k8s.io/role": "test_comp"}
	k8sNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName, Labels: nsLabels}}
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err)
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	require.NotNil(t, createdCID)
	expectedSecLabels := make(map[string]string)
	for k, v := range podLabels { expectedSecLabels["k8s:"+k] = v }
	for k, v := range nsLabels { expectedSecLabels["k8s:cilium.io/namespace.labels."+k] = v }
	expectedSecLabels["k8s:io.kubernetes.pod.namespace"] = nsName
	if diff := cmp.Diff(expectedSecLabels, createdCID.SecurityLabels); diff != "" {
		t.Logf("Expected: %#v\nActual: %#v", expectedSecLabels, createdCID.SecurityLabels)
		t.Errorf("CID.SecurityLabels mismatch (-want +got):\n%s", diff)
	}
}

func TestSecurityLabelDerivation_NamespaceLabelChanges(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-lbl-changes"; podName := "test-pod-ns-lbl-changes"
	staticPodLabels := map[string]string{"app": "my-app"}
	initialNsLabels := map[string]string{"env": "dev", "zone": "z1"}
	k8sNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName, Labels: initialNsLabels}}
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err)
	_, _ = createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, staticPodLabels)

	checkLbls := func(expNsLbls map[string]string, desc string) {
		t.Helper()
		expSecLbls := make(map[string]string)
		for k, v := range staticPodLabels { expSecLbls["k8s:"+k] = v }
		for k, v := range expNsLbls { expSecLbls["k8s:cilium.io/namespace.labels."+k] = v }
		expSecLbls["k8s:io.kubernetes.pod.namespace"] = nsName
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			store, _ := (*cidResource).Store(ctx); var curPodCID *capi_v2.CiliumIdentity
			for _, cid := range store.List() {
				match := true
				for pk, pv := range staticPodLabels { if cid.SecurityLabels["k8s:"+pk] != pv { match = false; break } }
				if cid.SecurityLabels["k8s:io.kubernetes.pod.namespace"] != nsName { match = false }
				if match { curPodCID = cid; break }
			}
			assert.NotNil(c, curPodCID, "No CID for pod %s after %s", podName, desc)
			if curPodCID != nil && !cmp.Equal(expSecLbls, curPodCID.SecurityLabels) {
				c.Errorf("CID labels mismatch for %s (-want +got):\n%s", desc, cmp.Diff(expSecLbls, curPodCID.SecurityLabels))
			}
		}, WaitUntilTimeout*2, 200*time.Millisecond, "CID labels not updated for %s", desc)
	}
	checkLbls(initialNsLabels, "initial")
	updatedNsLbls1 := map[string]string{"env": "prod", "zone": "z1"}
	k8sNs, _ = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	k8sNs.Labels = updatedNsLbls1; _, _ = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	checkLbls(updatedNsLbls1, "update env")
	updatedNsLbls2 := map[string]string{"env": "prod", "zone": "z1", "team": "backend"}
	k8sNs, _ = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	k8sNs.Labels = updatedNsLbls2; _, _ = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	checkLbls(updatedNsLbls2, "add team")
	updatedNsLbls3 := map[string]string{"env": "prod", "team": "backend"}
	k8sNs, _ = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	k8sNs.Labels = updatedNsLbls3; _, _ = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	checkLbls(updatedNsLbls3, "delete zone")
}

func TestSecurityLabelDerivation_PodLabelChangesAlongsideNamespaceLabels(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)
	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil { t.Fatalf("starting hive error: %s", err) }
	defer func() { if err := h.Stop(tlog, ctx); err != nil { t.Fatalf("stopping hive error: %v", err) } cancelCtxFunc() }()

	nsName := "test-ns-podsync"; podName := "test-pod-podsync"
	curNsLbls := map[string]string{"nskey": "nsval1", "stable": "ns"}
	curPodLbls := map[string]string{"podkey": "podval1", "app": "test"}
	k8sNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName, Labels: curNsLbls}}
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err)
	_, _ = createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, curPodLbls)

	checkCIDLbls := func(podLbls, nsLbls map[string]string, desc string) {
		t.Helper()
		expSecLbls := make(map[string]string)
		for k, v := range podLbls { expSecLbls["k8s:"+k] = v }
		for k, v := range nsLbls { expSecLbls["k8s:cilium.io/namespace.labels."+k] = v }
		expSecLbls["k8s:io.kubernetes.pod.namespace"] = nsName
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			store, _ := (*cidResource).Store(ctx); var curPodCID *capi_v2.CiliumIdentity
			cids := store.List()
			for _, cid := range cids {
				match := true
				for pk, pv := range podLbls { if cid.SecurityLabels["k8s:"+pk] != pv { match = false; break } }
				if !match { continue }
				if cid.SecurityLabels["k8s:io.kubernetes.pod.namespace"] != nsName { match = false }
				if match { curPodCID = cid; break }
			}
			assert.NotNil(c, curPodCID, "No CID for pod %s (%v) after %s. Store: %v", podName, podLbls, desc, cidsToNames(cids))
			if curPodCID != nil && !cmp.Equal(expSecLbls, curPodCID.SecurityLabels) {
				c.Errorf("CID labels mismatch for %s (-want +got):\n%s", desc, cmp.Diff(expSecLbls, curPodCID.SecurityLabels))
			}
		}, WaitUntilTimeout*3, 300*time.Millisecond, "CID labels not updated for %s", desc)
	}
	checkCIDLbls(curPodLbls, curNsLbls, "initial")
	curPodLbls = map[string]string{"podkey": "podval2", "app": "test"}
	fetchedPod, _ := fakeClient.Slim().CoreV1().Pods(nsName).Get(ctx, podName, metav1.GetOptions{})
	fetchedPod.Labels = curPodLbls; _, _ = fakeClient.Slim().CoreV1().Pods(nsName).Update(ctx, fetchedPod, metav1.UpdateOptions{})
	checkCIDLbls(curPodLbls, curNsLbls, "update podkey")
	curNsLbls = map[string]string{"nskey": "nsval2", "stable": "ns"}
	k8sNs, _ = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	k8sNs.Labels = curNsLbls; _, _ = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	checkCIDLbls(curPodLbls, curNsLbls, "update nskey")
	curPodLbls = map[string]string{"podkey": "podval3", "app": "test", "newpod": "added"}
	curNsLbls = map[string]string{"nskey": "nsval3", "stable": "ns", "newns": "added"}
	fetchedPod, _ = fakeClient.Slim().CoreV1().Pods(nsName).Get(ctx, podName, metav1.GetOptions{})
	fetchedPod.Labels = curPodLbls; _, _ = fakeClient.Slim().CoreV1().Pods(nsName).Update(ctx, fetchedPod, metav1.UpdateOptions{})
	k8sNs, _ = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	k8sNs.Labels = curNsLbls; _, _ = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	checkCIDLbls(curPodLbls, curNsLbls, "update both pod and ns")
}

// Helper functions for CID GC tests (and potentially others)
func getFirstCID(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity]) *capi_v2.CiliumIdentity {
	t.Helper()
	var cid *capi_v2.CiliumIdentity
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(ctx)
		assert.NoError(c, err, "Failed to get CID store")
		cids := store.List()
		assert.NotEmpty(c, cids, "Expected at least one CID in the store")
		if len(cids) > 0 {
			cid = cids[0]
		}
	}, WaitUntilTimeout, 100*time.Millisecond, "Failed to get first CID from store")
	return cid
}

func requireCIDExists(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], cidName string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(context.Background())
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.True(c, exists, "CID %s should exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not created or not found in store", cidName)
}

func requireCIDNotExists(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], cidName string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(context.Background())
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.False(c, exists, "CID %s should not exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not deleted or still found in store", cidName)
}

func createPodAndWaitForCID(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], podName, nsName string, labels map[string]string) (*corev1.Pod, *capi_v2.CiliumIdentity) {
	t.Helper()
	pod := testCreatePodObj(podName, nsName, labels, nil) // This creates a corev1.Pod
	_, err := fakeClient.Slim().CoreV1().Pods(nsName).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create pod %s/%s", nsName, podName)

	var createdCID *capi_v2.CiliumIdentity
	// Construct the expected security labels based *only* on pod labels and k8s ns name for matching.
	// This assumes that for a new pod, the initially visible/matched CID will be based on these,
	// even if the controller later enriches it with full namespace labels from the Namespace object.
	expectedInitialSecLabels := make(map[string]string)
	for k,v := range labels {
		expectedInitialSecLabels["k8s:" + k] = v
	}
	expectedInitialSecLabels["k8s:io.kubernetes.pod.namespace"] = nsName


	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cidResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CID store")
		if errAssert != nil {
			return
		}
		cids := store.List()
		found := false
		for _, cidInstance := range cids {
			// Check if the CID's security labels exactly match the expected initial set.
			if cmp.Equal(cidInstance.SecurityLabels, expectedInitialSecLabels) {
				createdCID = cidInstance
				found = true
				break
			}
		}
		assert.True(c, found, "CID for pod %s with labels %v not found using exact match for initial labels. Expected: %v. CIDs in store: %v", podName, labels, expectedInitialSecLabels, cidsToNames(cids))
	}, WaitUntilTimeout*2, 200*time.Millisecond, "CID for pod %s was not created or not found", podName)
	require.NotNil(t, createdCID, "Created CID should not be nil")
	return pod, createdCID
}

func deletePodAndWaitForCIDDeletion(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], podName, nsName, cidName string) {
	t.Helper()
	err := fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, podName, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, podName)
	requireCIDNotExists(t, ctx, cidResource, cidName)
}

func createCES(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice], cesName, cesNamespace string, ceps []capi_v2a1.CoreCiliumEndpoint) *capi_v2a1.CiliumEndpointSlice {
	t.Helper()
	ces := cestest.CreateStoreEndpointSlice(cesName, cesNamespace, ceps)
	_, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create CES %s", cesName)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cesResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CES store")
		_, exists, errAssert := store.GetByKey(resource.Key{Name: cesName, Namespace: cesNamespace})
		assert.NoError(c, errAssert, "Failed to get CES from store")
		assert.True(c, exists, "CES %s should exist", cesName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CES %s not found in store", cesName)
	return ces
}

func deleteCES(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice], cesName, cesNamespace string) {
	t.Helper()
	err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, cesName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		require.NoError(t, err, "Failed to delete CES %s/%s", cesNamespace, cesName)
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cesResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CES store")
		_, exists, errAssert := store.GetByKey(resource.Key{Name: cesName, Namespace: cesNamespace})
		assert.NoError(c, errAssert, "Failed to get CES from store")
		assert.False(c, exists, "CES %s should not exist", cesName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CES %s still found in store after deletion", cesName)
}

// cidsToNames is a helper to get a list of CID names for logging.
func cidsToNames(cids []*capi_v2.CiliumIdentity) []string {
	names := make([]string, len(cids))
	for i, cid := range cids {
		names[i] = cid.Name
	}
	return names
}

// buildPodSecurityLabels constructs the expected security labels for a CID
// based on pod labels and namespace name. It does not include namespace labels from the Namespace resource itself.
func buildPodSecurityLabels(podLabels map[string]string, nsName string) map[string]string {
	expected := make(map[string]string)
	if podLabels != nil {
		for k, v := range podLabels {
			expected["k8s:"+k] = v
		}
	}
	expected["k8s:io.kubernetes.pod.namespace"] = nsName
	// This helper specifically focuses on pod-derived labels + the standard Kubernetes namespace label.
	// It does not automatically add `reserved:init` or `k8s:cilium.io/namespace.labels.*`.
	// If a test requires namespace labels to be part of the security context,
	// they should be added to the map *after* calling this function.
	return expected
}

// findCIDBySecurityLabels searches the store for a CID matching the exact provided security labels.
// Returns the CID if found, otherwise nil.
func findCIDBySecurityLabels(ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], expectedSecLabels map[string]string) (*capi_v2.CiliumIdentity, error) {
	store, err := cidResource.Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CID store: %w", err)
	}
	cids := store.List()
	for _, cid := range cids {
		if cmp.Equal(expectedSecLabels, cid.SecurityLabels) {
			return cid, nil
		}
	}
	return nil, nil // Not found
}

func TestIdentityAllocationCountMatchesUniquePodLabelSets(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName1 := "ns1-alloc-count"
	ns1Obj := testCreateNSObj(nsName1, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1Obj, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName1)

	labelsA := map[string]string{"app": "appA", "env": "dev"}
	labelsB := map[string]string{"app": "appB", "env": "dev"}
	labelsC := map[string]string{"app": "appC", "env": "prod"}

	// Construct expected security labels based *only* on pod labels and namespace name
	// as per buildPodSecurityLabels definition.
	expectedSecLabelsA := buildPodSecurityLabels(labelsA, nsName1)
	expectedSecLabelsB := buildPodSecurityLabels(labelsB, nsName1)
	expectedSecLabelsC := buildPodSecurityLabels(labelsC, nsName1)

	var podA1, podA2, podB1, podC1 *corev1.Pod

	// Create pods
	podA1 = testCreatePodObj("poda1", nsName1, labelsA, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName1).Create(ctx, podA1, metav1.CreateOptions{})
	require.NoError(t, err); t.Logf("Created pod %s", podA1.Name)

	podA2 = testCreatePodObj("poda2", nsName1, labelsA, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName1).Create(ctx, podA2, metav1.CreateOptions{})
	require.NoError(t, err); t.Logf("Created pod %s", podA2.Name)

	podB1 = testCreatePodObj("podb1", nsName1, labelsB, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName1).Create(ctx, podB1, metav1.CreateOptions{})
	require.NoError(t, err); t.Logf("Created pod %s", podB1.Name)

	podC1 = testCreatePodObj("podc1", nsName1, labelsC, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName1).Create(ctx, podC1, metav1.CreateOptions{})
	require.NoError(t, err); t.Logf("Created pod %s", podC1.Name)

	var cidA, cidB, cidC *capi_v2.CiliumIdentity

	// Step 5: Verify 3 unique CIDs are created
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, sErr := (*cidResource).Store(ctx)
		assert.NoError(c, sErr)
		cidsList := store.List()
		assert.Len(c, cidsList, 3, "Should be 3 unique CIDs. Got: %v", cidsToNames(cidsList))

		var fErr error
		cidA, fErr = findCIDBySecurityLabels(ctx, *cidResource, expectedSecLabelsA)
		assert.NoError(c, fErr, "finding CID A")
		assert.NotNil(c, cidA, "CID for labelsA should exist. Labels: %v", expectedSecLabelsA)

		cidB, fErr = findCIDBySecurityLabels(ctx, *cidResource, expectedSecLabelsB)
		assert.NoError(c, fErr, "finding CID B")
		assert.NotNil(c, cidB, "CID for labelsB should exist. Labels: %v", expectedSecLabelsB)

		cidC, fErr = findCIDBySecurityLabels(ctx, *cidResource, expectedSecLabelsC)
		assert.NoError(c, fErr, "finding CID C")
		assert.NotNil(c, cidC, "CID for labelsC should exist. Labels: %v", expectedSecLabelsC)
	}, WaitUntilTimeout*3, 200*time.Millisecond, "Initial CIDs not found or count incorrect") // Increased timeout

	// Step 6-8: Delete podA2 (shares labelsA)
	t.Logf("Deleting pod %s", podA2.Name)
	err = fakeClient.Slim().CoreV1().Pods(nsName1).Delete(ctx, podA2.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, sErr := (*cidResource).Store(ctx)
		assert.NoError(c, sErr)
		assert.Len(c, store.List(), 3, "Should still be 3 CIDs after deleting one pod from a shared set")

		foundCIDA, _ := findCIDBySecurityLabels(ctx, *cidResource, expectedSecLabelsA)
		assert.NotNil(c, foundCIDA, "CID for labelsA should still exist after deleting podA2")
	}, WaitUntilTimeout, 100*time.Millisecond, "CID for labelsA did not persist or CID count changed after podA2 delete")

	// Step 9-10: Delete podB1
	cidBName := cidB.Name
	t.Logf("Deleting pod %s (CID: %s)", podB1.Name, cidBName)
	err = fakeClient.Slim().CoreV1().Pods(nsName1).Delete(ctx, podB1.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	requireCIDNotExists(t, ctx, *cidResource, cidBName)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, sErr := (*cidResource).Store(ctx)
		assert.NoError(c, sErr)
		assert.Len(c, store.List(), 2, "Should be 2 CIDs after deleting podB1. Got: %v", cidsToNames(store.List()))
	}, WaitUntilTimeout, 100*time.Millisecond, "CID count not 2 after deleting podB1")

	// Step 11-12: Delete podA1 (last pod with labelsA)
	cidAName := cidA.Name
	t.Logf("Deleting pod %s (CID: %s)", podA1.Name, cidAName)
	err = fakeClient.Slim().CoreV1().Pods(nsName1).Delete(ctx, podA1.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	requireCIDNotExists(t, ctx, *cidResource, cidAName)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, sErr := (*cidResource).Store(ctx)
		assert.NoError(c, sErr)
		assert.Len(c, store.List(), 1, "Should be 1 CID after deleting podA1. Got: %v", cidsToNames(store.List()))
	}, WaitUntilTimeout, 100*time.Millisecond, "CID count not 1 after deleting podA1")

	// Step 13-14: Delete podC1
	cidCName := cidC.Name
	t.Logf("Deleting pod %s (CID: %s)", podC1.Name, cidCName)
	err = fakeClient.Slim().CoreV1().Pods(nsName1).Delete(ctx, podC1.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	requireCIDNotExists(t, ctx, *cidResource, cidCName)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, sErr := (*cidResource).Store(ctx)
		assert.NoError(c, sErr)
		assert.Empty(c, store.List(), "Should be 0 CIDs after deleting podC1. Got: %v", cidsToNames(store.List()))
	}, WaitUntilTimeout, 100*time.Millisecond, "CID count not 0 after deleting podC1")
}

func TestCIDGarbageCollection_UnusedCID(t *testing.T) {
	cidResource, _, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-unused-cid"
	podName := "test-pod-unused-cid"
	podLabels := map[string]string{"app": "test-unused-cid"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Delete Pod and wait for CID garbage collection
	deletePodAndWaitForCIDDeletion(t, ctx, fakeClient, *cidResource, podName, nsName, createdCID.Name)
}

func TestCIDGarbageCollection_CIDReferencedByPod(t *testing.T) {
	cidResource, cesResource, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-pod-ref"
	podName := "test-pod-pod-ref"
	cesName := "test-ces-pod-ref"
	podLabels := map[string]string{"app": "test-pod-ref"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	pod, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Create CES referencing the CID
	cidNum, err := strconv.ParseInt(createdCID.Name, 10, 64)
	require.NoError(t, err, "Failed to parse CID name to int64")
	cep := cestest.CreateManagerEndpoint(podName, cidNum) // Using podName as CEP name for simplicity
	createCES(t, ctx, fakeClient, *cesResource, cesName, nsName, []capi_v2a1.CoreCiliumEndpoint{cep})

	// Delete CES
	deleteCES(t, ctx, fakeClient, *cesResource, cesName, nsName)

	// Verify CID is NOT garbage collected because it's still referenced by the Pod
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Cleanup: Delete pod
	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, pod.Name)
	// Deleting the pod should now allow the CID to be GCd if no other references exist.
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)
}

func TestCIDGarbageCollection_CIDReferencedByCES(t *testing.T) {
	cidResource, cesResource, fakeClient, _, h := initHiveTest(t, true)

	ctx, cancelCtxFunc := context.WithCancel(t.Context())
	tlog := hivetest.Logger(t)
	if err := h.Start(tlog, ctx); err != nil {
		t.Fatalf("starting hive encountered an error: %s", err)
	}
	defer func() {
		if err := h.Stop(tlog, ctx); err != nil {
			t.Fatalf("stopping hive encountered an error: %v", err)
		}
		cancelCtxFunc()
	}()

	nsName := "test-ns-ces-ref"
	podName := "test-pod-ces-ref"
	cesName := "test-ces-ces-ref"
	podLabels := map[string]string{"app": "test-ces-ref"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	pod, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Create CES referencing the CID
	cidNum, err := strconv.ParseInt(createdCID.Name, 10, 64)
	require.NoError(t, err, "Failed to parse CID name to int64")
	cep := cestest.CreateManagerEndpoint(podName, cidNum)
	createdCES := createCES(t, ctx, fakeClient, *cesResource, cesName, nsName, []capi_v2a1.CoreCiliumEndpoint{cep})

	// Delete Pod
	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, pod.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, pod.Name)

	// Verify CID is NOT garbage collected because it's still referenced by the CES
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Delete CES
	deleteCES(t, ctx, fakeClient, *cesResource, createdCES.Name, createdCES.Namespace)

	// Verify CID is NOW garbage collected
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)
}

// Helper functions for CID GC tests (and potentially others)
func getFirstCID(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity]) *capi_v2.CiliumIdentity {
	t.Helper()
	var cid *capi_v2.CiliumIdentity
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(ctx)
		assert.NoError(c, err, "Failed to get CID store")
		cids := store.List()
		assert.NotEmpty(c, cids, "Expected at least one CID in the store")
		if len(cids) > 0 {
			cid = cids[0]
		}
	}, WaitUntilTimeout, 100*time.Millisecond, "Failed to get first CID from store")
	return cid
}

func requireCIDExists(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], cidName string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(context.Background())
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.True(c, exists, "CID %s should exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not created or not found in store", cidName)
}

func requireCIDNotExists(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], cidName string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(context.Background())
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.False(c, exists, "CID %s should not exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not deleted or still found in store", cidName)
}

// buildPodSecurityLabels constructs the expected security labels for a CID based *only* on pod labels and namespace name.
// It does not include labels derived from the Namespace resource itself.
func buildPodSecurityLabels(podLabels map[string]string, nsName string) map[string]string {
	expected := make(map[string]string)
	if podLabels != nil {
		for k, v := range podLabels {
			expected["k8s:"+k] = v
		}
	}
	expected["k8s:io.kubernetes.pod.namespace"] = nsName
	return expected
}

func createPodAndWaitForCID(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], podName, nsName string, labels map[string]string) (*corev1.Pod, *capi_v2.CiliumIdentity) {
	t.Helper()
	pod := testCreatePodObj(podName, nsName, labels, nil)
	_, err := fakeClient.Slim().CoreV1().Pods(nsName).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create pod %s/%s", nsName, podName)

	var createdCID *capi_v2.CiliumIdentity
	expectedPodSecLabels := buildPodSecurityLabels(labels, nsName)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cidResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CID store")
		if errAssert != nil {
			return
		}
		cids := store.List()
		found := false
		for _, cidInstance := range cids {
			// Check if all expected pod-derived labels are present in the CID's security labels
			match := true
			for k, v := range expectedPodSecLabels {
				if val, ok := cidInstance.SecurityLabels[k]; !ok || val != v {
					match = false
					break
				}
			}
			// Additionally, ensure no other pod-specific labels are present if we want an exact match for pod-derived identity part
			// For this helper, we assume that if all expected pod labels match, and the namespace matches, it's our CID.
			// Namespace labels from the Namespace resource will be extra.
			if match {
				// If we need to ensure this CID is *only* for this pod's labels (and not a superset from another pod that shares these + more)
				// we might need a more sophisticated check or rely on the fact these test labels are unique enough.
				// For now, first match on pod labels is accepted.
				createdCID = cidInstance
				found = true
				break
			}
		}
		assert.True(c, found, "CID for pod %s with labels %v not found. Expected pod-derived security labels: %v. CIDs in store: %v", podName, labels, expectedPodSecLabels, cidsToNames(cids))
	}, WaitUntilTimeout*2, 200*time.Millisecond, "CID for pod %s was not created or not found", podName)
	require.NotNil(t, createdCID, "Created CID should not be nil")
	return pod, createdCID
}

func deletePodAndWaitForCIDDeletion(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], podName, nsName, cidName string) {
	t.Helper()
	err := fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, podName, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, podName)
	requireCIDNotExists(t, ctx, cidResource, cidName)
}

func createCES(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice], cesName, cesNamespace string, ceps []capi_v2a1.CoreCiliumEndpoint) *capi_v2a1.CiliumEndpointSlice {
	t.Helper()
	ces := cestest.CreateStoreEndpointSlice(cesName, cesNamespace, ceps)
	_, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create CES %s", cesName)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cesResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CES store")
		_, exists, errAssert := store.GetByKey(resource.Key{Name: cesName, Namespace: cesNamespace})
		assert.NoError(c, errAssert, "Failed to get CES from store")
		assert.True(c, exists, "CES %s should exist", cesName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CES %s not found in store", cesName)
	return ces
}

func deleteCES(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice], cesName, cesNamespace string) {
	t.Helper()
	err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, cesName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		require.NoError(t, err, "Failed to delete CES %s/%s", cesNamespace, cesName)
	}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cesResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CES store")
		_, exists, errAssert := store.GetByKey(resource.Key{Name: cesName, Namespace: cesNamespace})
		assert.NoError(c, errAssert, "Failed to get CES from store")
		assert.False(c, exists, "CES %s should not exist", cesName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CES %s still found in store after deletion", cesName)
}

// cidsToNames is a helper to get a list of CID names for logging.
func cidsToNames(cids []*capi_v2.CiliumIdentity) []string {
	names := make([]string, len(cids))
	for i, cid := range cids {
		names[i] = cid.Name
	}
	return names
}
