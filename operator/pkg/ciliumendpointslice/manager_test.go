// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// K8sPodWatcher is part of newCESManager signature, but not used by the handlers.
	// No need to import "github.com/cilium/cilium/pkg/k8s/watchers" for nil.
)

// Helper to create a pod for testing
func newTestPod(namespace, name string, ips []string, labels map[string]string) *core_v1.Pod {
	pod := &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
		Status: core_v1.PodStatus{
			PodIPs: []core_v1.PodIP{},
		},
	}
	for _, ip := range ips {
		pod.Status.PodIPs = append(pod.Status.PodIPs, core_v1.PodIP{IP: ip})
	}
	return pod
}

func TestPodManager(t *testing.T) {
	log := hivetest.Logger(t)
	defaultMaxPodsInCES := 2 // Max 2 "endpoints" (pods) per slice for easier testing

	t.Run("Add new pod to empty manager", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "test"})
		keys := m.handlePodAdd(pod1)

		assert.Len(t, keys, 1, "Should return one CESKey")
		cesName := CESName(keys[0].Name)

		assert.Equal(t, 1, m.mapping.getCESCount(), "Total number of CESs should be 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total number of CEPs (pods) should be 1")
		assert.Equal(t, 1, m.mapping.countCEPsInCES(cesName), "Pod count in CES should be 1")

		cepName := NewCEPName("pod1", "ns1")
		storedPodInfo, ok := m.mapping.GetPodCoreInfoInCES(cesName, cepName)
		assert.True(t, ok, "PodInfo should be found in CES")
		assert.Equal(t, "pod1", storedPodInfo.Name)
		assert.Equal(t, "ns1", storedPodInfo.Namespace)
		assert.Equal(t, []string{"1.1.1.1"}, storedPodInfo.IPs)
		assert.Equal(t, map[string]string{"app": "test"}, storedPodInfo.Labels)
	})

	t.Run("Add multiple pods to fill a CES and create a new one", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "test1"})
		pod2 := newTestPod("ns1", "pod2", []string{"1.1.1.2"}, map[string]string{"app": "test2"})
		pod3 := newTestPod("ns1", "pod3", []string{"1.1.1.3"}, map[string]string{"app": "test3"})

		keys1 := m.handlePodAdd(pod1)
		keys2 := m.handlePodAdd(pod2)
		keys3 := m.handlePodAdd(pod3)

		assert.Len(t, keys1, 1)
		assert.Len(t, keys2, 1)
		assert.Len(t, keys3, 1)

		cesName1 := CESName(keys1[0].Name)
		cesName2 := CESName(keys2[0].Name)
		cesName3 := CESName(keys3[0].Name)

		assert.Equal(t, cesName1, cesName2, "Pod1 and Pod2 should be in the same CES")
		assert.NotEqual(t, cesName1, cesName3, "Pod3 should be in a different CES")

		assert.Equal(t, 2, m.mapping.getCESCount(), "Total number of CESs should be 2")
		assert.Equal(t, 3, m.mapping.countCEPs(), "Total number of CEPs (pods) should be 3")
		assert.Equal(t, defaultMaxPodsInCES, m.mapping.countCEPsInCES(cesName1), "CES1 should be full")
		assert.Equal(t, 1, m.mapping.countCEPsInCES(cesName3), "CES2 should have one pod")
	})

	t.Run("Add pods for different namespaces", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1_ns1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, nil)
		pod1_ns2 := newTestPod("ns2", "pod1", []string{"2.2.2.2"}, nil)

		keys1 := m.handlePodAdd(pod1_ns1)
		keys2 := m.handlePodAdd(pod1_ns2)

		assert.Len(t, keys1, 1)
		assert.Len(t, keys2, 1)
		assert.NotEqual(t, CESName(keys1[0].Name), CESName(keys2[0].Name), "Pods in different namespaces should be in different CESs")
		assert.Equal(t, 2, m.mapping.getCESCount(), "Total number of CESs should be 2")
		assert.Equal(t, 2, m.mapping.countCEPs(), "Total number of CEPs (pods) should be 2")
	})

	t.Run("Add existing pod (update PodCoreInfo)", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1_v1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "v1"})
		m.handlePodAdd(pod1_v1)

		cepName := NewCEPName("pod1", "ns1")
		cesName, _ := m.mapping.getCESName(cepName)
		originalPodInfo, _ := m.mapping.GetPodCoreInfoInCES(cesName, cepName)
		assert.Equal(t, []string{"1.1.1.1"}, originalPodInfo.IPs)
		assert.Equal(t, "v1", originalPodInfo.Labels["app"])

		pod1_v2 := newTestPod("ns1", "pod1", []string{"1.1.1.1", "1.1.1.100"}, map[string]string{"app": "v2"}) // Same name/ns, different IPs/labels
		m.handlePodAdd(pod1_v2)

		assert.Equal(t, 1, m.mapping.getCESCount(), "CES count should remain 1")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Pod count should remain 1")

		updatedPodInfo, _ := m.mapping.GetPodCoreInfoInCES(cesName, cepName)
		assert.Equal(t, []string{"1.1.1.1", "1.1.1.100"}, updatedPodInfo.IPs, "Pod IPs should be updated")
		assert.Equal(t, "v2", updatedPodInfo.Labels["app"], "Pod labels should be updated")
	})

	t.Run("Update pod with IP change (same CEPName)", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		podOld := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "test"})
		m.handlePodAdd(podOld)

		cepName := NewCEPName("pod1", "ns1")
		cesName, _ := m.mapping.getCESName(cepName)

		podNew := newTestPod("ns1", "pod1", []string{"1.1.1.2"}, map[string]string{"app": "test"}) // IP changed
		m.handlePodUpdate(podOld, podNew)

		assert.Equal(t, 1, m.mapping.getCESCount(), "CES count should remain 1")
		updatedPodInfo, _ := m.mapping.GetPodCoreInfoInCES(cesName, cepName)
		assert.Equal(t, []string{"1.1.1.2"}, updatedPodInfo.IPs, "Pod IPs should be updated")
	})

	t.Run("Update pod with Label change (same CEPName)", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		podOld := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "v1"})
		m.handlePodAdd(podOld)

		cepName := NewCEPName("pod1", "ns1")
		cesName, _ := m.mapping.getCESName(cepName)

		podNew := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "v2"}) // Label changed
		m.handlePodUpdate(podOld, podNew)

		assert.Equal(t, 1, m.mapping.getCESCount(), "CES count should remain 1")
		updatedPodInfo, _ := m.mapping.GetPodCoreInfoInCES(cesName, cepName)
		assert.Equal(t, "v2", updatedPodInfo.Labels["app"], "Pod labels should be updated")
	})

	t.Run("Update pod with Name change (different CEPName)", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		podOld := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, map[string]string{"app": "test"})
		keysOld := m.handlePodAdd(podOld)
		cesNameOld := CESName(keysOld[0].Name)
		cepNameOld := NewCEPName("pod1", "ns1")

		podNew := newTestPod("ns1", "pod2", []string{"1.1.1.1"}, map[string]string{"app": "test"}) // Name changed
		keysNew := m.handlePodUpdate(podOld, podNew)
		cesNameNew := CESName(keysNew[0].Name)
		cepNameNew := NewCEPName("pod2", "ns1")

		assert.Equal(t, 1, m.mapping.getCESCount(), "CES count should remain 1 (reused or new if old became empty)")
		assert.Equal(t, 1, m.mapping.countCEPs(), "Total pod count should be 1")

		_, oldExists := m.mapping.GetPodCoreInfoInCES(cesNameOld, cepNameOld)
		assert.False(t, oldExists, "Old pod entry should be removed")

		newPodInfo, newExists := m.mapping.GetPodCoreInfoInCES(cesNameNew, cepNameNew)
		assert.True(t, newExists, "New pod entry should exist")
		assert.Equal(t, "pod2", newPodInfo.Name)
	})

	t.Run("Delete pod from CES", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, nil)
		pod2 := newTestPod("ns1", "pod2", []string{"1.1.1.2"}, nil)
		keys1 := m.handlePodAdd(pod1)
		m.handlePodAdd(pod2)
		cesName := CESName(keys1[0].Name)

		assert.Equal(t, 2, m.mapping.countCEPsInCES(cesName))
		m.handlePodDelete(pod1)

		assert.Equal(t, 1, m.mapping.countCEPs(), "Total pod count should be 1")
		assert.Equal(t, 1, m.mapping.countCEPsInCES(cesName), "Pod count in CES should be 1")
		_, exists := m.mapping.GetPodCoreInfoInCES(cesName, NewCEPName("pod1", "ns1"))
		assert.False(t, exists, "Deleted pod should not exist in CES map")
	})

	t.Run("Delete pod making CES empty (should delete CES)", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, nil)
		m.handlePodAdd(pod1)

		assert.Equal(t, 1, m.mapping.getCESCount())
		m.handlePodDelete(pod1)

		assert.Equal(t, 0, m.mapping.getCESCount(), "CES should be deleted as it's empty")
		assert.Equal(t, 0, m.mapping.countCEPs(), "Total pod count should be 0")
	})

	t.Run("Delete non-existent pod", func(t *testing.T) {
		m := newCESManager(defaultMaxPodsInCES, log, nil).(*cesManager)
		pod1 := newTestPod("ns1", "pod1", []string{"1.1.1.1"}, nil)
		// Don't add pod1

		deleteKey := m.handlePodDelete(pod1)
		assert.Empty(t, deleteKey.Name, "Returned key for non-existent pod delete should be empty")
		assert.Equal(t, 0, m.mapping.getCESCount())
		assert.Equal(t, 0, m.mapping.countCEPs())
	})
}
