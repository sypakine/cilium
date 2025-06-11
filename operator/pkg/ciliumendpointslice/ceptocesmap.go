// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

type CEPName resource.Key
type CESKey resource.Key
type CESName string

// CESToCEPMapping is used to map Cilium Endpoints to CiliumEndpointSlices and
// retrieving all the Cilium Endpoints mapped to the given CiliumEndpointSlice.
// This map is protected by lock for consistent and concurrent access.
type CESToCEPMapping struct {
	mutex lock.RWMutex
	// cepNameToCESName is used to map CiliumEndpoint name to CiliumEndpointSlice name.
	cepNameToCESName map[CEPName]CESName
	// cesNameToPodInfoSet is used to map CiliumEndpointSlice name to the CoreInfos of Pods it contains.
	cesNameToPodInfoSet map[CESName]map[CEPName]PodCoreInfo // Changed from struct{} to PodCoreInfo
	cesData             map[CESName]CESData
}

// PodCoreInfo holds essential information derived from a Pod, similar to parts of CoreCiliumEndpoint.
type PodCoreInfo struct {
	Name       string
	Namespace  string
	IPs        []string // Simplified: In reality, this would be structured like cilium_v2.AddressPair
	Labels     map[string]string
	// Potentially IdentityID int64 etc.
}

// CESData contains all CES data except endpoints.
// CES is reconicled to have endpoints equal to CEPs mapped to it
// and other fields set from the CESData.
type CESData struct {
	ns string
}

// Creates and intializes the new CESToCEPMapping
func newCESToCEPMapping() *CESToCEPMapping {
	return &CESToCEPMapping{
		cepNameToCESName:    make(map[CEPName]CESName),
		cesNameToPodInfoSet: make(map[CESName]map[CEPName]PodCoreInfo), // Initialize the new map type
		cesData:             make(map[CESName]CESData),
	}
}

// Insert the CEP in cache, map CEP name to CES name, and store its PodCoreInfo
func (c *CESToCEPMapping) insertCEP(cepName CEPName, cesName CESName, podInfo PodCoreInfo) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cepNameToCESName[cepName] = cesName
	if c.cesNameToPodInfoSet[cesName] == nil {
		c.cesNameToPodInfoSet[cesName] = make(map[CEPName]PodCoreInfo)
	}
	c.cesNameToPodInfoSet[cesName][cepName] = podInfo
}

// Remove the CEP entry from map
func (c *CESToCEPMapping) deleteCEP(cepName CEPName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cesNameToCEPNameSet[c.cepNameToCESName[cepName]], cepName)
	delete(c.cepNameToCESName, cepName)
}

// Return CES to which the given CEP is assigned
func (c *CESToCEPMapping) getCESName(cepName CEPName) (CESName, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	name, ok := c.cepNameToCESName[cepName]
	return name, ok
}

func (c *CESToCEPMapping) hasCEP(cepName CEPName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cepNameToCESName[cepName]
	return ok
}

// Return total number of CEPs stored in cache
func (c *CESToCEPMapping) countCEPs() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cepNameToCESName)
}

// Return total number of CEPs mapped to the given CES
func (c *CESToCEPMapping) countCEPsInCES(ces CESName) int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesNameToPodInfoSet[ces])
}

// Return CEP Names mapped to the given CES
func (c *CESToCEPMapping) getCEPsInCES(ces CESName) []CEPName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	ceps := make([]CEPName, 0, len(c.cesNameToPodInfoSet[ces]))
	for cep := range c.cesNameToPodInfoSet[ces] {
		ceps = append(ceps, cep)
	}
	return ceps
}

// GetPodCoreInfoInCES returns the PodCoreInfo for a given CEPName in a specific CES.
// Returns the PodCoreInfo and true if found, otherwise zero PodCoreInfo and false.
func (c *CESToCEPMapping) GetPodCoreInfoInCES(cesName CESName, cepName CEPName) (PodCoreInfo, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if podsInCes, ok := c.cesNameToPodInfoSet[cesName]; ok {
		podInfo, found := podsInCes[cepName]
		return podInfo, found
	}
	return PodCoreInfo{}, false
}

// Initializes mapping structure for CES
func (c *CESToCEPMapping) insertCES(cesName CESName, ns string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Ensure the inner map is initialized when a new CES is inserted.
	if _, exists := c.cesNameToPodInfoSet[cesName]; !exists {
		c.cesNameToPodInfoSet[cesName] = make(map[CEPName]PodCoreInfo)
	}
	c.cesData[cesName] = CESData{
		ns: ns,
	}
}

// Remove mapping structure for CES
func (c *CESToCEPMapping) deleteCES(cesName CESName) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.cesNameToPodInfoSet, cesName)
	delete(c.cesData, cesName)
}

func (c *CESToCEPMapping) hasCESName(cesName CESName) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	_, ok := c.cesNameToPodInfoSet[cesName]
	return ok
}

// Return the total number of CESs.
func (c *CESToCEPMapping) getCESCount() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cesNameToPodInfoSet)
}

// Return names of all CESs.
func (c *CESToCEPMapping) getAllCESs() []CESName {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	cess := make([]CESName, 0, len(c.cesNameToPodInfoSet))
	for ces := range c.cesNameToPodInfoSet {
		cess = append(cess, ces)
	}
	return cess
}

// Return the CES data
func (c *CESToCEPMapping) getCESData(name CESName) CESData {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	data := c.cesData[name]
	return data
}

func (ces CESKey) key() resource.Key {
	return resource.Key(ces)
}

func (cep CEPName) key() resource.Key {
	return resource.Key(cep)
}

func (ces CESKey) string() string {
	return ces.key().String()
}

func (cep CEPName) string() string {
	return cep.key().String()
}

func (c CESName) string() string {
	return string(c)
}

// NewCESKey is used with namespace only to determine which queue CES should be in.
// CES is a cluster-scope object and it does not contain the metadata namespace field.
func NewCESKey(name string, namespace string) CESKey {
	return CESKey(resource.Key{Name: name, Namespace: namespace})
}

func NewCEPName(name, ns string) CEPName {
	return CEPName(resource.Key{Name: name, Namespace: ns})
}
