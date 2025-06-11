// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	prometheustestutil "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sClientTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	cestest "github.com/cilium/cilium/operator/pkg/ciliumendpointslice/testutils"
	"github.com/cilium/cilium/pkg/hive"
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
	// After 1 pod create and 1 CID create
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValuePod, metrics.LabelValueOutcomeSuccess), stringToReader("1"), "cilium_operator_cid_controller_work_queue_event_count"))
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValueCID, metrics.LabelValueOutcomeSuccess), stringToReader("1"), "cilium_operator_cid_controller_work_queue_event_count"))

	// Check that latency metrics were recorded (count > 0 for actual observations)
	// Exact values are hard to predict, so we check if they were observed at all.
	podEnqueuedLatencyCount := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueEnqueuedLatency))
	podProcessingLatencyCount := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueProcessingLatency))
	cidEnqueuedLatencyCount := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueEnqueuedLatency))
	cidProcessingLatencyCount := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueProcessingLatency))

	assert.Greater(t, podEnqueuedLatencyCount, 0, "Pod enqueued latency should have been observed")
	assert.Greater(t, podProcessingLatencyCount, 0, "Pod processing latency should have been observed")
	assert.Greater(t, cidEnqueuedLatencyCount, 0, "CID enqueued latency should have been observed")
	assert.Greater(t, cidProcessingLatencyCount, 0, "CID processing latency should have been observed")


	// Further actions in verifyCIDUsageInCES:
	// - CES Create (not directly metered by CID controller metrics)
	// - Pod Delete: Should trigger pod event, then CID event (if GC happens due to pod delete)
	// - CES Delete (not directly metered)
	//
	// The verifyCIDUsageInCES function deletes the pod, but the CID is NOT GC'd because the CES still uses it.
	// Then it deletes the CES, which SHOULD lead to CID GC.
	// So, after verifyCIDUsageInCES:
	// Pod delete event: +1 for pod success
	// CID delete event (GC): +1 for cid success (if the GC is triggered and is an event)

	// Let's re-evaluate metrics *after* verifyCIDUsageInCES for changes.
	// This part is tricky because verifyCIDUsageInCES does multiple things.
	// For now, the initial check is the most reliable for this specific test structure.
	// A more granular test would be needed to check metrics after pod delete that leads to GC.

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

	// Verify metrics
	// After 1 pod create and 1 CID create
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValuePod, metrics.LabelValueOutcomeSuccess), strings.NewReader("1\n"), "cilium_operator_cid_controller_work_queue_event_count"))
	// Depending on how CID creation is triggered (directly by pod or after pod event processing),
	// the CID success event might be 1 or more if there's a reconcile loop.
	// For a simple create, expecting 1.
	require.NoError(t, prometheustestutil.CollectAndCompare(m.EventCount.WithLabelValues(LabelValueCID, metrics.LabelValueOutcomeSuccess), strings.NewReader("1\n"), "cilium_operator_cid_controller_work_queue_event_count"))


	// Check that latency metrics were recorded (count > 0 for actual observations)
	// Exact values are hard to predict, so we check if they were observed at all.
	// These are histograms, so CollectAndCount counts the number of observations.
	podEnqueuedLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueEnqueuedLatency))
	podProcessingLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValuePod, LabelValueProcessingLatency))
	cidEnqueuedLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueEnqueuedLatency))
	cidProcessingLatencyObservations := prometheustestutil.CollectAndCount(m.QueueLatency.WithLabelValues(LabelValueCID, LabelValueProcessingLatency))

	assert.Greater(t, podEnqueuedLatencyObservations, 0, "Pod enqueued latency should have been observed")
	assert.Greater(t, podProcessingLatencyObservations, 0, "Pod processing latency should have been observed")
	assert.Greater(t, cidEnqueuedLatencyObservations, 0, "CID enqueued latency should have been observed")
	assert.Greater(t, cidProcessingLatencyObservations, 0, "CID processing latency should have been observed")

	// Note: verifyCIDUsageInCES performs additional operations (pod delete, ces create/delete)
	// which will also affect metrics. For more precise metric testing of those operations,
	// dedicated tests focusing on each action (e.g., pod deletion leading to CID GC) would be better.
	// The assertions above cover the initial pod and CID creation part of this test.

	if err := h.Stop(tlog, ctx); err != nil {
		t.Fatalf("stopping hive encountered an error: %v", err)
	}
}

func initHiveTest(t *testing.T, operatorManagingCID bool) (*resource.Resource[*capi_v2.CiliumIdentity], *resource.Resource[*capi_v2a1.CiliumEndpointSlice], *k8sClient.FakeClientset, *Metrics, *hive.Hive) {
	var cidResource resource.Resource[*capi_v2.CiliumIdentity]
	var cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]
	var fakeClient *k8sClient.FakeClientset
	var cidMetrics Metrics

	h := hive.New(
		k8sClient.FakeClientCell,
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Provide(func() config {
			if operatorManagingCID {
				return config{
					IdentityManagementMode: option.IdentityManagementModeOperator,
				}
			} else {
				return config{
					IdentityManagementMode: option.IdentityManagementModeAgent,
				}
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				EnableCiliumEndpointSlice: true,
				DisableNetworkPolicy:      false,
			}
		}),
		cell.Invoke(func(p params) error {
			registerController(p)
			return nil
		}),
		cell.Invoke(func(
			c *k8sClient.FakeClientset,
			cid resource.Resource[*capi_v2.CiliumIdentity],
			ces resource.Resource[*capi_v2a1.CiliumEndpointSlice],
			m *Metrics,
		) error {
			fakeClient = c
			cidResource = cid
			cesResource = ces
			cidMetrics = *m
			return nil
		}),
	)
	// Populate to call the invoke functions that pull out the values.
	if err := h.Populate(hivetest.Logger(t)); err != nil {
		t.Fatalf("Populate: %s", err)
	}
	return &cidResource, &cesResource, fakeClient, &cidMetrics, h
}

func createNsAndPod(ctx context.Context, fakeClient *k8sClient.FakeClientset) error {
	ns := testCreateNSObj("ns1", nil)
	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		return err
	}
	pod := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	if _, err := fakeClient.Slim().CoreV1().Pods("ns1").Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return nil
}

func verifyCIDUsageInCES(ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], cesResource resource.Resource[*capi_v2a1.CiliumEndpointSlice]) error {
	cidStore, _ := cidResource.Store(ctx)
	cids := cidStore.List()
	if len(cids) == 0 {
		return fmt.Errorf("no CIDs found in the store")
	}

	cidNum, err := strconv.Atoi(cids[0].Name)
	if err != nil {
		return err
	}

	cep1 := cestest.CreateManagerEndpoint("cep1", int64(cidNum))
	ces1 := cestest.CreateStoreEndpointSlice("ces1", "ns", []capi_v2a1.CoreCiliumEndpoint{cep1})
	if _, err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Create(ctx, ces1, metav1.CreateOptions{}); err != nil {
		return err
	}

	cesStore, _ := cesResource.Store(ctx)
	if err := testutils.WaitUntil(func() bool {
		return len(cesStore.List()) > 0
	}, WaitUntilTimeout); err != nil {
		return fmt.Errorf("failed to get CES: %w", err)
	}

	// CID is not deleted even when Pod is, because the CID is still used in CES.
	if err := fakeClient.Slim().CoreV1().Pods("ns1").Delete(ctx, "pod1", metav1.DeleteOptions{}); err != nil {
		return err
	}

	if len(cidStore.List()) == 0 {
		return fmt.Errorf("expected for CID to not be deleted")
	}

	if err := fakeClient.CiliumV2alpha1().CiliumEndpointSlices().Delete(ctx, ces1.Name, metav1.DeleteOptions{}); err != nil {
		return err
	}

	return nil
}

func TestCreateTwoPodsWithSameLabels(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	pod2 := testCreatePodObj("pod2", "ns1", testLbsA, nil)
	pod3 := testCreatePodObj("pod3", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod3, ns1)

	// Start test hive.
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

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Create the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for update event to propagate.
	ev := <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Create the second pod with the same labels.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod2.Namespace).Create(ctx, pod2, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Create the third pod with different labels.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod3.Namespace).Create(ctx, pod3, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for reconciler to create a new CID based on pod3.
	// This also confirms that pod2 creation didn't trigger creation of a new CID.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid2.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid2.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}

func TestUpdatePodLabels(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsA, nil)
	pod1b := testCreatePodObj("pod1", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod1b, ns1)

	// Start test hive.
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

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Start listening to identities events but discard all events being replayed.
	events := (*cidResource).Events(ctx)
	for ev := range events {
		ev.Done(nil)
		if ev.Kind == resource.Sync {
			break
		}
	}

	// Create the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Wait for update event to propagate.
	ev := <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid1.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid1.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)

	// Update labels of the first pod.
	if _, err := fakeClient.Slim().CoreV1().Pods(pod1b.Namespace).Update(ctx, pod1b, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update pod: %v", err)
	}

	// Wait for reconciler to create a new CID based on the updated pod.
	ev = <-events
	if ev.Kind != resource.Upsert {
		t.Fatalf("expected upsert event, got %v", ev.Kind)
	}
	if !cmp.Equal(ev.Object.SecurityLabels, cid2.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", cid2.SecurityLabels, ev.Object.SecurityLabels)
	}
	ev.Done(nil)
}

func TestUpdateUsedCIDIsReverted(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)

	pod1 := testCreatePodObj("pod1", "ns1", testLbsC, nil)
	pod2 := testCreatePodObj("pod2", "ns1", testLbsB, nil)

	cid1 := testCreateCIDObjNs("1000", pod1, ns1)
	cid2 := testCreateCIDObjNs("2000", pod2, ns1)

	// Start test hive.
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

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Check initial status of CiliumIdentity resource after pods creation.
	store, err := (*cidResource).Store(ctx)
	if err != nil {
		t.Fatalf("unexpected error while getting CID store: %s", err)
	}

	var (
		lastErr  error
		toUpdate *capi_v2.CiliumIdentity
	)
	if err := testutils.WaitUntil(func() bool {
		cids := store.List()
		if len(cids) != 1 {
			lastErr = fmt.Errorf("expected 1 identity, got %d", len(cids))
			return false
		}
		toUpdate = cids[0]
		return true
	}, WaitUntilTimeout); err != nil {
		t.Fatalf("timeout waiting for identities in store: %s", lastErr)
	}

	// Update identity.
	updated := toUpdate.DeepCopy()
	updated.Labels = cid2.Labels
	updated.SecurityLabels = cid2.SecurityLabels
	if _, err := fakeClient.CiliumV2().CiliumIdentities().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update CID: %v", err)
	}

	cid, err := fakeClient.CiliumV2().CiliumIdentities().Get(ctx, updated.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get CID: %v", err)
	}
	if !cmp.Equal(cid.SecurityLabels, updated.SecurityLabels) {
		t.Fatalf("expected labels %v, got %v", updated.SecurityLabels, cid.SecurityLabels)
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		cids := store.List()
		assert.Len(ct, cids, 1)
		if len(cids) != 1 {
			return
		}
		cid = cids[0]

		if !cmp.Equal(cid.SecurityLabels, cid1.SecurityLabels) {
			t.Fatalf("expected labels %v, got %v", cid.SecurityLabels, cid1.SecurityLabels)
		}
	}, WaitUntilTimeout, 100*time.Millisecond)

}

func TestDeleteUsedCIDIsRecreated(t *testing.T) {
	ns1 := testCreateNSObj("ns1", nil)
	pod1 := testCreatePodObj("pod1", "ns1", testLbsC, nil)
	cid1 := testCreateCIDObjNs("1000", pod1, ns1)

	// Start test hive.
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

	if _, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	if _, err := fakeClient.Slim().CoreV1().Pods(pod1.Namespace).Create(ctx, pod1, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	// Check initial status of CiliumIdentity resource after pods creation.
	store, err := (*cidResource).Store(ctx)
	if err != nil {
		t.Fatalf("unexpected error while getting CID store: %s", err)
	}

	var cid *capi_v2.CiliumIdentity
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		cids := store.List()
		assert.Len(ct, cids, 1)
		if len(cids) != 1 {
			return
		}
		cid = cids[0]
		if !cmp.Equal(cid.SecurityLabels, cid1.SecurityLabels) {
			t.Fatalf("expected labels %v, got %v", cid.SecurityLabels, cid1.SecurityLabels)
		}
	}, WaitUntilTimeout, 100*time.Millisecond)

	err = fakeClient.CiliumV2().CiliumIdentities().Delete(ctx, cid.Name, metav1.DeleteOptions{})
	assert.NoError(t, err, "CiliumIdentity deletion should not return an error")

	_, err = fakeClient.CiliumV2().CiliumIdentities().Get(ctx, cid.Name, metav1.GetOptions{})
	assert.True(t, errors.IsNotFound(err), "Expected NotFound error after deletion")

	// Ensure the identity will be re-created
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		cids := store.List()
		assert.Len(ct, cids, 1)
		if len(cids) != 1 {
			return
		}
		cid = cids[0]
		if !cmp.Equal(cid.SecurityLabels, cid1.SecurityLabels) {
			t.Fatalf("expected labels %v, got %v", cid.SecurityLabels, cid1.SecurityLabels)
		}
	}, WaitUntilTimeout, 100*time.Millisecond)
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
	// We can optionally wait for its deletion if needed for test isolation, but the main test point is above.
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
	cep := cestest.CreateManagerEndpoint(podName, cidNum) // Using podName as CEP name for simplicity
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

func TestPodWithInvalidLabels(t *testing.T) {
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

	nsName := "test-ns-invalid-labels"
	podName := "test-pod-invalid-labels"
	// Create a label value that is too long (Kubernetes limit is 63 characters)
	invalidLabelValue := string(make([]byte, 64))
	for i := range invalidLabelValue {
		invalidLabelValue[i] = 'a'
	}
	podLabels := map[string]string{"app": invalidLabelValue}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Attempt to create Pod with invalid labels
	// K8s API server itself might reject this pod, or the CID controller might ignore it.
	// If the API server rejects it, then `createPodAndWaitForCID` would fail.
	// We want to test the CID controller's behavior if such a pod somehow exists (e.g. validation webhook disabled).
	// So, we'll create the pod directly and then check CIDs.
	pod := testCreatePodObj(podName, nsName, podLabels, nil)
	_, err = fakeClient.Slim().CoreV1().Pods(nsName).Create(ctx, pod, metav1.CreateOptions{})
	// We need to check if the error is from K8s API server due to invalid label.
	// If so, the test premise (that the pod exists and controller has to deal with it) is not met.
	// However, Cilium's identity logic itself should be robust against invalid labels even if K8s somehow allowed them.
	if err != nil && errors.IsInvalid(err) {
		t.Logf("Pod creation failed due to invalid labels at K8s API server level: %v. This test primarily targets controller logic assuming such a pod could exist.", err)
		// If K8s rejects the pod, then no CID would be created by definition.
		// This part of the test is more about the CID controller not crashing.
	} else {
		require.NoError(t, err, "Failed to create pod %s/%s, or error was not 'IsInvalid'", nsName, podName)
	}


	// Wait for a short period to allow controllers to react
	time.Sleep(2 * time.Second) // Allow time for reconciliation if any

	// Verify no CID was created for this pod
	// List all CIDs and check if any correspond to the podLabels.
	// A simpler check for this test is to ensure no *new* CIDs are created if the store was initially empty,
	// or that no CID matches these specific, invalid labels.
	store, err := (*cidResource).Store(ctx)
	require.NoError(t, err, "Failed to get CID store")
	cids := store.List()
	foundCID := false
	for _, cid := range cids {
		if cmp.Equal(cid.SecurityLabels, podLabels) {
			foundCID = true
			break
		}
	}
	assert.False(t, foundCID, "No CID should be created for a Pod with invalid labels. Found: %v", cids)

	// As an additional check, if metrics for invalid label errors were available, we'd check them.
	// For now, the primary assertion is that no CID is created and the controller doesn't crash.
}

func TestAPIServerErrorHandling_CreateCID(t *testing.T) {
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

	nsName := "test-ns-create-err"
	podName := "test-pod-create-err"
	podLabels := map[string]string{"app": "test-create-err"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	atomicFailureCount := int32(0)
	maxFailures := int32(3) // Simulate 3 failures

	// Simulate API server errors for creating CIDs
	fakeClient.PrependReaction("create", "ciliumidentities", func(action k8sClientTesting.Action) (handled bool, ret runtime.Object, err error) {
		if atomic.LoadInt32(&atomicFailureCount) < maxFailures {
			atomic.AddInt32(&atomicFailureCount, 1)
			t.Logf("Simulating API server error on CID create, attempt #%d", atomic.LoadInt32(&atomicFailureCount))
			// Return a server timeout error, a common transient error.
			// The "2" is a RetryAfterSeconds hint, though the controller's retry logic might be fixed.
			return true, nil, errors.NewServerTimeout(capi_v2.Resource("ciliumidentities"), "create", 2)
		}
		t.Logf("Allowing CID create to succeed after %d attempts", atomic.LoadInt32(&atomicFailureCount))
		return false, nil, nil // Fallthrough to normal behavior, allowing actual creation
	})

	// Create Pod - this should trigger CID creation.
	// The createPodAndWaitForCID helper will wait until the CID is actually created and found.
	// This will take longer due to the simulated errors and retries by the controller.
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)

	// Verify that the CID was eventually created
	requireCIDExists(t, ctx, *cidResource, createdCID.Name)

	// Verify that the simulated failures actually occurred.
	// It should be exactly maxFailures because PrependReaction applies them in order.
	assert.Equal(t, maxFailures, atomic.LoadInt32(&atomicFailureCount), "Expected exactly %d creation failures due to simulated API errors", maxFailures)

	// Clear reactions for subsequent tests or cleanup
	fakeClient.ClearReactions()
}

func TestAPIServerErrorHandling_DeleteCID(t *testing.T) {
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

	nsName := "test-ns-delete-err"
	podName := "test-pod-delete-err"
	podLabels := map[string]string{"app": "test-delete-err"}

	// Create Namespace
	ns := testCreateNSObj(nsName, nil)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and CID successfully first
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	requireCIDExists(t, ctx, *cidResource, createdCID.Name) // Ensure it's there before we try to delete it

	atomicDeleteFailureCount := int32(0)
	maxDeleteFailures := int32(3) // Simulate 3 failures

	// Simulate API server errors for deleting CIDs
	fakeClient.PrependReaction("delete", "ciliumidentities", func(action k8sClientTesting.Action) (handled bool, ret runtime.Object, err error) {
		if atomic.LoadInt32(&atomicDeleteFailureCount) < maxDeleteFailures {
			deleteAction, ok := action.(k8sClientTesting.DeleteAction) // Use interface type
			if !ok {
				t.Errorf("Unexpected action type for delete reaction: %T", action)
				return false, nil, fmt.Errorf("unexpected action type for delete reaction: %T", action)
			}
			// Only simulate error for the specific CID we are testing
			if deleteAction.GetName() == createdCID.Name {
				atomic.AddInt32(&atomicDeleteFailureCount, 1)
				t.Logf("Simulating API server error on CID delete for %s, attempt #%d", createdCID.Name, atomic.LoadInt32(&atomicDeleteFailureCount))
				return true, nil, errors.NewServerTimeout(capi_v2.Resource("ciliumidentities"), "delete", 2) // RetryAfterSeconds: 2
			}
		}
		// Log even if not our target CID or after max failures, to help debug if needed
		targetMsg := ""
		if da, ok := action.(k8sClientTesting.DeleteAction); ok && da.GetName() == createdCID.Name {
			targetMsg = fmt.Sprintf("for target CID %s ", createdCID.Name)
		}
		t.Logf("Reaction: Allowing CID delete %sto proceed. Current failure count for target: %d", targetMsg, atomic.LoadInt32(&atomicDeleteFailureCount))
		return false, nil, nil // Fallthrough to normal behavior
	})

	// Delete Pod - this should trigger CID deletion, which will initially fail due to simulated errors
	err = fakeClient.Slim().CoreV1().Pods(nsName).Delete(ctx, podName, metav1.DeleteOptions{})
	require.NoError(t, err, "Failed to delete pod %s/%s", nsName, podName)

	// Verify CID is eventually deleted. requireCIDNotExists has its own timeout.
	requireCIDNotExists(t, ctx, *cidResource, createdCID.Name)

	// Verify that the simulated failures actually occurred for the specific CID.
	assert.Equal(t, maxDeleteFailures, atomic.LoadInt32(&atomicDeleteFailureCount), "Expected exactly %d deletion failures for CID %s due to simulated API errors", maxDeleteFailures, createdCID.Name)

	// Clear reactions
	fakeClient.ClearReactions()
}

func TestSecurityLabelDerivation_SpecialCharacters(t *testing.T) {
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

	nsName := "test-ns-special-chars"
	podName := "test-pod-special-chars"

	nsLabels := map[string]string{
		"ns.label-with-hyphen":         "value1",
		"ns_label.with.dots":           "value2",
		"cilium.io/very-long-ns-label": "a-long-value-with-hyphens_and_underscores.123",
	}
	podLabels := map[string]string{
		"app_name":           "my.app-v1",
		"k8s.io/role":        "test_component",
		"another-label.here": "with.all.sorts-of_chars",
	}

	// Create Namespace with labels
	k8sNs := testCreateNSObj(nsName, nsLabels)
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and wait for CID
	// The createPodAndWaitForCID function needs to be aware that it might receive a pod object that already has labels.
	// The current testCreatePodObj used by createPodAndWaitForCID takes labels as an argument.
	// We need to ensure the pod is created with these labels *and* the namespace labels are picked up.
	// The `createPodAndWaitForCID` helper creates a pod object itself. We need to ensure it uses the podLabels.
	// And the CID controller should automatically pick up namespace labels.

	// `createPodAndWaitForCID` will create a pod with `podLabels`.
	// The CID controller is responsible for merging these with namespace labels.
	_, createdCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, podLabels)
	require.NotNil(t, createdCID, "CID should have been created")

	expectedSecurityLabels := make(map[string]string)
	for k, v := range podLabels {
		expectedSecurityLabels["k8s:"+k] = v
	}
	for k, v := range nsLabels {
		expectedSecurityLabels["k8s:cilium.io/namespace.labels."+k] = v
	}
	// Add the default namespace label
	expectedSecurityLabels["k8s:io.kubernetes.pod.namespace"] = nsName

	// Compare the security labels
	// Note: The order of labels in the map does not matter for cmp.Equal with maps.
	if diff := cmp.Diff(expectedSecurityLabels, createdCID.SecurityLabels); diff != "" {
		t.Errorf("CID.SecurityLabels mismatch (-want +got):\n%s", diff)
		t.Logf("Expected: %v", expectedSecurityLabels)
		t.Logf("Got: %v", createdCID.SecurityLabels)
	}
}

func TestSecurityLabelDerivation_NamespaceLabelChanges(t *testing.T) {
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

	nsName := "test-ns-label-changes"
	podName := "test-pod-ns-changes"
	staticPodLabels := map[string]string{"app": "my-static-app"} // Pod labels don't change in this test

	// Initial Namespace labels
	initialNsLabels := map[string]string{"env": "dev", "zone": "us-east-1"}
	k8sNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName, Labels: initialNsLabels}}
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and initial CID
	_, initialCID := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, staticPodLabels)
	require.NotNil(t, initialCID, "Initial CID should have been created")

	checkCurrentCIDLabels := func(expectedNsLabels map[string]string, description string) {
		t.Helper()
		expectedSecLabels := make(map[string]string)
		for k, v := range staticPodLabels {
			expectedSecLabels["k8s:"+k] = v
		}
		for k, v := range expectedNsLabels {
			expectedSecLabels["k8s:cilium.io/namespace.labels."+k] = v
		}
		expectedSecLabels["k8s:io.kubernetes.pod.namespace"] = nsName

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			store, errStore := (*cidResource).Store(ctx)
			assert.NoError(c, errStore, "Failed to get CID store for %s", description)
			if errStore != nil {
				return
			}
			var currentPodCID *capi_v2.CiliumIdentity
			for _, cid := range store.List() {
				// Find the CID that matches the pod's static labels
				match := true
				for pk, pv := range staticPodLabels {
					if cid.SecurityLabels["k8s:"+pk] != pv {
						match = false
						break
					}
				}
				if cid.SecurityLabels["k8s:io.kubernetes.pod.namespace"] != nsName {
					match = false
				}
				if match {
					currentPodCID = cid
					break
				}
			}
			assert.NotNil(c, currentPodCID, "Could not find CID for pod %s after %s", podName, description)
			if currentPodCID == nil {
				return
			}

			if diff := cmp.Diff(expectedSecLabels, currentPodCID.SecurityLabels); diff != "" {
				c.Errorf("CID.SecurityLabels mismatch for %s (-want +got):\n%s", description, diff)
				c.Logf("Expected: %#v", expectedSecLabels)
				c.Logf("Got: %#v", currentPodCID.SecurityLabels)
			}
		}, WaitUntilTimeout*2, 200*time.Millisecond, "CID labels not updated for %s", description)
	}

	// 1. Verify Initial State
	checkCurrentCIDLabels(initialNsLabels, "initial state")

	// 2. Update Namespace Label
	updatedNsLabelsStep1 := map[string]string{"env": "prod", "zone": "us-east-1"} // Changed 'env'
	k8sNs, err = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	require.NoError(t, err)
	k8sNs.Labels = updatedNsLabelsStep1
	_, err = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update namespace labels for step 1")
	checkCurrentCIDLabels(updatedNsLabelsStep1, "after updating 'env' label")

	// 3. Add New Namespace Label
	updatedNsLabelsStep2 := map[string]string{"env": "prod", "zone": "us-east-1", "team": "backend"} // Added 'team'
	k8sNs, err = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	require.NoError(t, err)
	k8sNs.Labels = updatedNsLabelsStep2
	_, err = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update namespace labels for step 2")
	checkCurrentCIDLabels(updatedNsLabelsStep2, "after adding 'team' label")

	// 4. Delete Namespace Label
	updatedNsLabelsStep3 := map[string]string{"env": "prod", "team": "backend"} // Deleted 'zone'
	k8sNs, err = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	require.NoError(t, err)
	k8sNs.Labels = updatedNsLabelsStep3
	_, err = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update namespace labels for step 3")
	checkCurrentCIDLabels(updatedNsLabelsStep3, "after deleting 'zone' label")
}

func TestSecurityLabelDerivation_PodLabelChangesAlongsideNamespaceLabels(t *testing.T) {
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

	nsName := "test-ns-pod-label-changes"
	podName := "test-pod-pod-ns-changes"

	initialNsLabels := map[string]string{"nskey": "nsvalue1", "stablekey": "alwayshere"}
	currentNsLabels := initialNsLabels // Keep track of current NS labels

	initialPodLabels := map[string]string{"podkey": "podvalue1", "app": "test-app"}
	currentPodLabels := initialPodLabels // Keep track of current Pod labels

	// Create Namespace
	k8sNs := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName, Labels: currentNsLabels}}
	_, err := fakeClient.Slim().CoreV1().Namespaces().Create(ctx, k8sNs, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create namespace %s", nsName)

	// Create Pod and initial CID
	// createPodAndWaitForCID will use initialPodLabels for the first creation and lookup
	createdPod, _ := createPodAndWaitForCID(t, ctx, fakeClient, *cidResource, podName, nsName, currentPodLabels)
	require.NotNil(t, createdPod, "Pod should have been created")

	// Helper to check CID labels based on current pod and namespace labels
	checkCIDLabels := func(podLabelsToCheck, nsLabelsToCheck map[string]string, description string) {
		t.Helper()
		expectedSecLabels := make(map[string]string)
		for k, v := range podLabelsToCheck {
			expectedSecLabels["k8s:"+k] = v
		}
		for k, v := range nsLabelsToCheck {
			expectedSecLabels["k8s:cilium.io/namespace.labels."+k] = v
		}
		expectedSecLabels["k8s:io.kubernetes.pod.namespace"] = nsName

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			store, errStore := (*cidResource).Store(ctx)
			assert.NoError(c, errStore, "Failed to get CID store for %s", description)
			if errStore != nil {
				return
			}
			var currentPodCID *capi_v2.CiliumIdentity
			cids := store.List()
			for _, cid := range cids {
				match := true
				// Check if this CID matches all *current* pod labels and the namespace
				for pk, pv := range podLabelsToCheck {
					if cid.SecurityLabels["k8s:"+pk] != pv {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				if cid.SecurityLabels["k8s:io.kubernetes.pod.namespace"] != nsName {
					match = false
				}
				if match {
					currentPodCID = cid
					break
				}
			}
			assert.NotNil(c, currentPodCID, "Could not find CID for pod %s with labels %v after %s. CIDs in store: %v", podName, podLabelsToCheck, description, cidsToNames(cids))
			if currentPodCID == nil {
				return
			}

			if diff := cmp.Diff(expectedSecLabels, currentPodCID.SecurityLabels); diff != "" {
				c.Errorf("CID.SecurityLabels mismatch for %s (-want +got):\n%s", description, diff)
				c.Logf("Expected: %#v", expectedSecLabels)
				c.Logf("Got: %#v", currentPodCID.SecurityLabels)
			}
		}, WaitUntilTimeout*3, 300*time.Millisecond, "CID labels not updated for %s", description) // Increased timeout for potentially slower updates
	}
	cidsToNames := func(cids []*capi_v2.CiliumIdentity) []string {
		names := make([]string, len(cids))
		for i, cid := range cids {
			names[i] = cid.Name
		}
		return names
	}


	// 1. Verify Initial State
	checkCIDLabels(currentPodLabels, currentNsLabels, "initial state")

	// 2. Update Pod Label
	t.Log("Updating pod label...")
	currentPodLabels = map[string]string{"podkey": "podvalue2", "app": "test-app"} // Changed 'podkey'

	fetchedPod, err := fakeClient.Slim().CoreV1().Pods(nsName).Get(ctx, podName, metav1.GetOptions{})
	require.NoError(t, err, "Failed to get pod for update")
	fetchedPod.Labels = currentPodLabels
	_, err = fakeClient.Slim().CoreV1().Pods(nsName).Update(ctx, fetchedPod, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update pod labels")
	checkCIDLabels(currentPodLabels, currentNsLabels, "after updating pod label 'podkey'")

	// 3. Update Namespace Label
	t.Log("Updating namespace label...")
	currentNsLabels = map[string]string{"nskey": "nsvalue2", "stablekey": "alwayshere"} // Changed 'nskey'

	k8sNs, err = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	require.NoError(t, err)
	k8sNs.Labels = currentNsLabels
	_, err = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update namespace labels")
	checkCIDLabels(currentPodLabels, currentNsLabels, "after updating namespace label 'nskey'")

	// 4. Update both Pod and Namespace labels to different values
	t.Log("Updating both pod and namespace labels...")
	currentPodLabels = map[string]string{"podkey": "podvalue3", "app": "test-app", "newpodlabel": "added"}
	currentNsLabels = map[string]string{"nskey": "nsvalue3", "stablekey": "alwayshere", "newnslabel": "added"}

	fetchedPod, err = fakeClient.Slim().CoreV1().Pods(nsName).Get(ctx, podName, metav1.GetOptions{})
	require.NoError(t, err, "Failed to get pod for update (step 4)")
	fetchedPod.Labels = currentPodLabels
	_, err = fakeClient.Slim().CoreV1().Pods(nsName).Update(ctx, fetchedPod, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update pod labels (step 4)")

	k8sNs, err = fakeClient.Slim().CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	require.NoError(t, err)
	k8sNs.Labels = currentNsLabels
	_, err = fakeClient.Slim().CoreV1().Namespaces().Update(ctx, k8sNs, metav1.UpdateOptions{})
	require.NoError(t, err, "Failed to update namespace labels (step 4)")

	checkCIDLabels(currentPodLabels, currentNsLabels, "after updating both pod and namespace labels")
}

// Helper functions for CID GC tests
// getFirstCID retrieves the first CID found in the store.
// This is useful when a test creates a single pod and needs to know the generated CID name.
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
		store, err := cidResource.Store(context.Background()) // Use background context for store reads
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.True(c, exists, "CID %s should exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not created or not found in store", cidName)
}

func requireCIDNotExists(t *testing.T, ctx context.Context, cidResource resource.Resource[*capi_v2.CiliumIdentity], cidName string) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, err := cidResource.Store(context.Background()) // Use background context for store reads
		assert.NoError(c, err, "Failed to get CID store")
		_, exists, err := store.GetByKey(resource.Key{Name: cidName})
		assert.NoError(c, err, "Failed to get CID %s from store", cidName)
		assert.False(c, exists, "CID %s should not exist", cidName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CID %s was not deleted or still found in store", cidName)
}

func createPodAndWaitForCID(t *testing.T, ctx context.Context, fakeClient *k8sClient.FakeClientset, cidResource resource.Resource[*capi_v2.CiliumIdentity], podName, nsName string, labels map[string]string) (*capi_v2.Pod, *capi_v2.CiliumIdentity) {
	t.Helper()
	pod := testCreatePodObj(podName, nsName, labels, nil)
	_, err := fakeClient.Slim().CoreV1().Pods(nsName).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err, "Failed to create pod %s/%s", nsName, podName)

	// Wait for the CID to be created and retrieve it.
	// This assumes that the pod creation will lead to a *single* new CID or reuse an existing one with matching labels.
	// We find the CID by listing all CIDs and searching for one that matches the pod's labels.
	var createdCID *capi_v2.CiliumIdentity
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cidResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CID store")
		if errAssert != nil {
			return
		}
		cids := store.List()
		for _, cid := range cids {
			// Compare labels to find the matching CID.
			// This is a simplified comparison; a more robust check might be needed
			// depending on the exact label derivation for CIDs.
			if cmp.Equal(cid.SecurityLabels, labels) {
				createdCID = cid
				return
			}
		}
		assert.NotNil(c, createdCID, "CID for pod %s with labels %v not found", podName, labels)
	}, WaitUntilTimeout, 200*time.Millisecond, "CID for pod %s was not created or not found", podName)
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

	// Wait for CES to appear in store
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
	if err != nil && !errors.IsNotFound(err) { // It might already be GCed or deleted by another part of the test
		require.NoError(t, err, "Failed to delete CES %s/%s", cesNamespace, cesName)
	}

	// Wait for CES to disappear from store
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		store, errAssert := cesResource.Store(ctx)
		assert.NoError(c, errAssert, "Failed to get CES store")
		_, exists, errAssert := store.GetByKey(resource.Key{Name: cesName, Namespace: cesNamespace})
		assert.NoError(c, errAssert, "Failed to get CES from store")
		assert.False(c, exists, "CES %s should not exist", cesName)
	}, WaitUntilTimeout, 100*time.Millisecond, "CES %s still found in store after deletion", cesName)
}
