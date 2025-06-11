// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"log/slog"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	core_v1 "k8s.io/api/core/v1" // Assuming this is the package for Pod type
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils" // Added for ValidIPs
	"github.com/cilium/cilium/pkg/k8s/watchers"       // Assuming this is the package for K8sPodWatcher
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// sequentialLetters contains lower case alphabets without vowels and few numbers.
	// skipped vowels and numbers [0, 1] to avoid generating controversial names.
	sequentialLetters = []rune("bcdfghjklmnpqrstvwxyz2456789")
)

// operations is an interface to all operations that a CES manager can perform.
type operations interface {
	// External APIs to handle pod events
	handlePodAdd(pod *core_v1.Pod) []CESKey
	handlePodUpdate(oldPod, newPod *core_v1.Pod) []CESKey
	handlePodDelete(pod *core_v1.Pod) CESKey

	initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName
	// initializeMappingCEPtoCES is removed as it's CoreCiliumEndpoint specific

	getCEPCountInCES(ces CESName) int
	getCEPinCES(ces CESName) []CEPName
	getCESData(ces CESName) CESData
	isCEPinCES(cep CEPName, ces CESName) bool
}

// cesManager is used to batch CEP into a CES, based on FirstComeFirstServe. If a new CEP
// is inserted, then the CEP is queued in any one of the available CES. CEPs are
// inserted into CESs without any preference or any priority.
type cesManager struct {
	logger *slog.Logger
	// mapping is used to map CESName to CESTracker[i.e. list of CEPs],
	// as well as CEPName to CESName.
	mapping *CESToCEPMapping

	// maxCEPsInCES is the maximum number of CiliumCoreEndpoint(s) packed in
	// a CiliumEndpointSlice Resource.
	maxCEPsInCES int

	// podWatcher is used to receive pod updates.
	podWatcher watchers.K8sPodWatcher // Placeholder type
}

// newCESManager creates and initializes a new FirstComeFirstServe based CES
// manager, in this mode CEPs are batched based on FirstComeFirtServe algorithm.
func newCESManager(maxCEPsInCES int, logger *slog.Logger, podWatcher watchers.K8sPodWatcher) operations {
	return &cesManager{
		logger:       logger,
		mapping:      newCESToCEPMapping(),
		maxCEPsInCES: maxCEPsInCES,
		podWatcher:   podWatcher,
	}
}

// This function create a new ces and capacity to hold maximum ceps in a CES.
// This is called in 2 different scenarios:
//  1. During runtime, when ces manager decides to create a new ces, it calls
//     with an empty name, it generates a random unique name and assign it to the CES.
//  2. During operator warm boot [after crash or software upgrade], slicing manager
//     creates a CES, by passing unique name.
func (c *cesManager) createCES(name, ns string) CESName {
	if name == "" {
		name = uniqueCESliceName(c.mapping)
	}
	cesName := CESName(name)
	c.mapping.insertCES(cesName, ns)
	c.logger.Debug("Generated CES", logfields.CESName, cesName)
	return cesName
}

// getLargestAvailableCESForNamespace returns the largest CES from cache for the
// specified namespace that has at least 1 CEP and 1 available spot (less than
// maximum CEPs). If it is not found, a nil is returned.
func (c *cesManager) getLargestAvailableCESForNamespace(ns string) CESName {
	largestCEPCount := 0
	selectedCES := CESName("")
	for _, ces := range c.mapping.getAllCESs() {
		cepCount := c.mapping.countCEPsInCES(ces)
		if cepCount < c.maxCEPsInCES && cepCount > largestCEPCount && c.mapping.getCESData(ces).ns == ns {
			selectedCES = ces
			largestCEPCount = cepCount
			if largestCEPCount == c.maxCEPsInCES-1 {
				break
			}
		}
	}
	return selectedCES
}

// handlePodAdd is called when a pod is added.
func (c *cesManager) handlePodAdd(pod *core_v1.Pod) []CESKey {
	// TODO: Implement logic to extract relevant information from the pod,
	// convert it to a CEP-like structure if necessary, and then use logic
	// similar to the old UpdateCEPMapping.
	c.logger.Debug("Pod added, to be mapped to CES", "podName", pod.Name, "namespace", pod.Namespace)

	// Placeholder: Derive a CEP name from the pod. This needs actual implementation.
	// For now, let's assume a function GetCEPNameFromPod exists, or we use a simple name.
	cepName := NewCEPName(pod.Name, pod.Namespace) // Use NewCEPName for consistency

	// Extract PodCoreInfo
	podIPs := k8sUtils.ValidIPs(pod.Status)
	// DeepCopy labels to avoid issues if the original pod object's labels map is modified elsewhere.
	podLabels := make(map[string]string)
	if pod.ObjectMeta.Labels != nil {
		for k, v := range pod.ObjectMeta.Labels {
			podLabels[k] = v
		}
	}
	podInfo := PodCoreInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		IPs:       podIPs,
		Labels:    podLabels,
	}

	// Check if this pod (as a CEP) is already mapped.
	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		// Pod is already in a CES, update its info
		c.logger.Debug("Pod (as CEP) already mapped to CES, updating info",
			"podName", pod.Name,
			"namespace", pod.Namespace,
			logfields.CESName, cesName.string(),
		)
		// The existing CES assignment is maintained. We update the stored PodCoreInfo.
		c.mapping.insertCEP(cepName, cesName, podInfo)
		return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
	}

	// Get the largest available CES or create a new one for this new pod.
	cesName = c.getLargestAvailableCESForNamespace(pod.Namespace)
	if cesName == "" {
		cesName = c.createCES("", pod.Namespace)
	}
	c.mapping.insertCEP(cepName, cesName, podInfo)
	c.logger.Debug("Pod (as CEP) mapped to CES",
		"podName", pod.Name,
		"namespace", pod.Namespace,
		"podIPs", podIPs,
		logfields.CESName, cesName.string(),
	)
	return []CESKey{NewCESKey(cesName.string(), pod.Namespace)}
}

// handlePodUpdate is called when a pod is updated.
func (c *cesManager) handlePodUpdate(oldPod, newPod *core_v1.Pod) []CESKey {
	// TODO: Implement logic to determine if the update affects CES mapping.
	// This might involve checking if relevant fields (IP, labels, etc.) have changed.
	// If the mapping needs to change, it could be a remove and then add.
	c.logger.Debug("Pod updated", "podName", newPod.Name, "namespace", newPod.Namespace)

	// This is a simplified approach. A real implementation would need to compare
	// oldPod and newPod to see if the change impacts CES assignment.
	// For example, if a pod's IP changes or labels that affect its identity for CES.
	// If identity changes, it might be a remove of old and add of new.
	// If it's just metadata, it might not affect CES.

	// For now, let's assume an update might mean re-evaluating its CES placement,
	// by removing the old instance (if identifiable and different) and adding the new one.
	// A more sophisticated approach would check if the CEPName derived from oldPod and newPod
	// are different, or if other critical properties changed.

	// Simplified: try to remove the old pod representation and then add the new one.
	// This isn't fully robust as GetCEPNameFromPod might be the same.
	// cepOldName := CEPName(oldPod.Namespace + "/" + oldPod.Name) // Simplified placeholder
	// if _, exists := c.mapping.getCESName(cepOldName); exists {
	// 	 c.handlePodDelete(oldPod) // This would log and potentially modify CES state
	// }
	// return c.handlePodAdd(newPod)

	// More direct approach for now: if newPod's representation should be in a CES,
	// handlePodAdd will ensure it is, and update if it already exists (idempotency of mapping.insertCEP).
	// This assumes that the identity (CEPName) either doesn't change or if it does,
	// the old entry corresponding to oldPod might need explicit removal if not overwritten.
	// For this subtask, we'll rely on the add logic to correctly place/update the newPod's state.
	// A true update might need to remove the oldPod first if its CEPName is different from newPod's.
	cepNewName := NewCEPName(newPod.Name, newPod.Namespace)
	cepOldName := NewCEPName(oldPod.Name, oldPod.Namespace)

	// If the effective "name" or identity for CES purposes has changed.
	if cepNewName != cepOldName {
		c.logger.Debug("Pod identity (for CES) changed during update", "oldPodName", oldPod.Name, "newPodName", newPod.Name)
		// Remove the old representation
		cesNameOld, existsOld := c.mapping.getCESName(cepOldName)
		if existsOld {
			c.logger.Debug("Removing old Pod (as CEP) representation due to update", "podName", oldPod.Name, logfields.CESName, cesNameOld.string())
			c.mapping.deleteCEP(cepOldName)
			if c.mapping.countCEPsInCES(cesNameOld) == 0 {
				c.mapping.deleteCES(cesNameOld)
			}
		}
	}
	// Add/Update the new representation
	// This reuses the add logic, which handles existing entries (updates PodCoreInfo)
	// or assigns to a new/existing CES.
	return c.handlePodAdd(newPod)
}

// handlePodDelete is called when a pod is deleted.
func (c *cesManager) handlePodDelete(pod *core_v1.Pod) CESKey {
	// TODO: Implement logic to remove the pod (as a CEP) from its CES.
	c.logger.Debug("Pod deleted, removing from CES mapping", "podName", pod.Name, "namespace", pod.Namespace)

	// Placeholder: Derive a CEP name from the pod.
	cepName := NewCEPName(pod.Name, pod.Namespace) // Use NewCEPName for consistency

	cesName, exists := c.mapping.getCESName(cepName)
	if exists {
		c.logger.Debug("Removing Pod (as CEP) from CES",
			"podName", pod.Name,
			"namespace", pod.Namespace,
			logfields.CESName, cesName.string(),
		)
		c.mapping.deleteCEP(cepName)
		if c.mapping.countCEPsInCES(cesName) == 0 {
			c.mapping.deleteCES(cesName)
		}
		return NewCESKey(cesName.string(), pod.Namespace)
	}
	c.logger.Debug("Pod (as CEP) not found in any CES mapping for deletion", "podName", pod.Name, "namespace", pod.Namespace)
	return CESKey(resource.Key{})
}

func (c *cesManager) initializeMappingForCES(ces *cilium_v2.CiliumEndpointSlice) CESName {
	return c.createCES(ces.Name, ces.Namespace)
}

// initializeMappingCEPtoCES has been removed as it's specific to CoreCiliumEndpoint
// and this manager now focuses on pods. If initialization from existing
// CiliumEndpointSlice CRDs (which might contain non-pod CEPs) is needed,
// that logic would need to be re-evaluated.

func (c *cesManager) getCEPCountInCES(ces CESName) int {
	return c.mapping.countCEPsInCES(ces)
}

func (c *cesManager) getCESData(ces CESName) CESData {
	return c.mapping.getCESData(ces)
}

func (c *cesManager) getCEPinCES(ces CESName) []CEPName {
	return c.mapping.getCEPsInCES(ces)
}

func (c *cesManager) isCEPinCES(cep CEPName, ces CESName) bool {
	mappedCES, exists := c.mapping.getCESName(cep)
	return exists && mappedCES == ces
}
