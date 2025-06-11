// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"net"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/node/addressing"
)

// +kubebuilder:validation:Format=cidr
type IPv4orIPv6CIDR string

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumidentity",path="ciliumidentities",scope="Cluster",shortName={ciliumid}
// +kubebuilder:printcolumn:JSONPath=".metadata.labels.io\\.kubernetes\\.pod\\.namespace",description="The namespace of the entity",name="Namespace",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="The age of the identity",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// CiliumIdentity is a CRD that represents an identity managed by Cilium.
// It is intended as a backing store for identity allocation, acting as the
// global coordination backend, and can be used in place of a KVStore (such as
// etcd).
// The name of the CRD is the numeric identity and the labels on the CRD object
// are the kubernetes sourced labels seen by cilium. This is currently the
// only label source possible when running under kubernetes. Non-kubernetes
// labels are filtered but all labels, from all sources, are places in the
// SecurityLabels field. These also include the source and are used to define
// the identity.
// The labels under metav1.ObjectMeta can be used when searching for
// CiliumIdentity instances that include particular labels. This can be done
// with invocations such as:
//
//	kubectl get ciliumid -l 'foo=bar'
type CiliumIdentity struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// SecurityLabels is the source-of-truth set of labels for this identity.
	SecurityLabels map[string]string `json:"security-labels"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumIdentityList is a list of CiliumIdentity objects.
type CiliumIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumIdentity
	Items []CiliumIdentity `json:"items"`
}

// +k8s:deepcopy-gen=false

// AddressPair is a pair of IPv4 and/or IPv6 address.
type AddressPair struct {
	IPV4 string `json:"ipv4,omitempty"`
	IPV6 string `json:"ipv6,omitempty"`
}

// +k8s:deepcopy-gen=false

// AddressPairList is a list of address pairs.
type AddressPairList []*AddressPair

// Sort sorts an AddressPairList by IPv4 and IPv6 address.
func (a AddressPairList) Sort() {
	sort.Slice(a, func(i, j int) bool {
		if a[i].IPV4 < a[j].IPV4 {
			return true
		} else if a[i].IPV4 == a[j].IPV4 {
			return a[i].IPV6 < a[j].IPV6
		}
		return false
	})
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumnode",path="ciliumnodes",scope="Cluster",shortName={cn,ciliumn}
// +kubebuilder:printcolumn:JSONPath=".spec.addresses[?(@.type==\"CiliumInternalIP\")].ip",description="Cilium internal IP for this node",name="CiliumInternalIP",type=string
// +kubebuilder:printcolumn:JSONPath=".spec.addresses[?(@.type==\"InternalIP\")].ip",description="IP of the node",name="InternalIP",type=string
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="Time duration since creation of Ciliumnode",name="Age",type=date
// +kubebuilder:storageversion
// +kubebuilder:subresource:status

// CiliumNode represents a node managed by Cilium. It contains a specification
// to control various node specific configuration aspects and a status section
// to represent the status of the node.
type CiliumNode struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired specification/configuration of the node.
	Spec NodeSpec `json:"spec"`

	// Status defines the realized specification/configuration and status
	// of the node.
	//
	// +kubebuilder:validation:Optional
	Status NodeStatus `json:"status,omitempty"`
}

// NodeAddress is a node address.
type NodeAddress struct {
	// Type is the type of the node address
	Type addressing.AddressType `json:"type,omitempty"`

	// IP is an IP of a node
	IP string `json:"ip,omitempty"`
}

// NodeSpec is the configuration specific to a node.
type NodeSpec struct {
	// InstanceID is the identifier of the node. This is different from the
	// node name which is typically the FQDN of the node. The InstanceID
	// typically refers to the identifier used by the cloud provider or
	// some other means of identification.
	InstanceID string `json:"instance-id,omitempty"`

	// BootID is a unique node identifier generated on boot
	//
	// +kubebuilder:validation:Optional
	BootID string `json:"bootid,omitempty"`

	// Addresses is the list of all node addresses.
	//
	// +kubebuilder:validation:Optional
	Addresses []NodeAddress `json:"addresses,omitempty"`

	// HealthAddressing is the addressing information for health connectivity
	// checking.
	//
	// +kubebuilder:validation:Optional
	HealthAddressing HealthAddressingSpec `json:"health,omitempty"`

	// IngressAddressing is the addressing information for Ingress listener.
	//
	// +kubebuilder:validation:Optional
	IngressAddressing AddressPair `json:"ingress,omitempty"`

	// Encryption is the encryption configuration of the node.
	//
	// +kubebuilder:validation:Optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	// ENI is the AWS ENI specific configuration.
	//
	// +kubebuilder:validation:Optional
	ENI eniTypes.ENISpec `json:"eni,omitempty"`

	// Azure is the Azure IPAM specific configuration.
	//
	// +kubebuilder:validation:Optional
	Azure azureTypes.AzureSpec `json:"azure,omitempty"`

	// AlibabaCloud is the AlibabaCloud IPAM specific configuration.
	//
	// +kubebuilder:validation:Optional
	AlibabaCloud alibabaCloudTypes.Spec `json:"alibaba-cloud,omitempty"`

	// IPAM is the address management specification. This section can be
	// populated by a user or it can be automatically populated by an IPAM
	// operator.
	//
	// +kubebuilder:validation:Optional
	IPAM ipamTypes.IPAMSpec `json:"ipam,omitempty"`

	// NodeIdentity is the Cilium numeric identity allocated for the node, if any.
	//
	// +kubebuilder:validation:Optional
	NodeIdentity uint64 `json:"nodeidentity,omitempty"`
}

// HealthAddressingSpec is the addressing information required to do
// connectivity health checking.
type HealthAddressingSpec struct {
	// IPv4 is the IPv4 address of the IPv4 health endpoint.
	//
	// +kubebuilder:validation:Optional
	IPv4 string `json:"ipv4,omitempty"`

	// IPv6 is the IPv6 address of the IPv4 health endpoint.
	//
	// +kubebuilder:validation:Optional
	IPv6 string `json:"ipv6,omitempty"`
}

// EncryptionSpec defines the encryption relevant configuration of a node.
type EncryptionSpec struct {
	// Key is the index to the key to use for encryption or 0 if encryption is
	// disabled.
	//
	// +kubebuilder:validation:Optional
	Key int `json:"key,omitempty"`
}

// NodeStatus is the status of a node.
type NodeStatus struct {
	// ENI is the AWS ENI specific status of the node.
	//
	// +kubebuilder:validation:Optional
	ENI eniTypes.ENIStatus `json:"eni,omitempty"`

	// Azure is the Azure specific status of the node.
	//
	// +kubebuilder:validation:Optional
	Azure azureTypes.AzureStatus `json:"azure,omitempty"`

	// IPAM is the IPAM status of the node.
	//
	// +kubebuilder:validation:Optional
	IPAM ipamTypes.IPAMStatus `json:"ipam,omitempty"`

	// AlibabaCloud is the AlibabaCloud specific status of the node.
	//
	// +kubebuilder:validation:Optional
	AlibabaCloud alibabaCloudTypes.ENIStatus `json:"alibaba-cloud,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumNodeList is a list of CiliumNode objects.
type CiliumNodeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumNode
	Items []CiliumNode `json:"items"`
}

// InstanceID returns the InstanceID of a CiliumNode.
func (n *CiliumNode) InstanceID() (instanceID string) {
	if n != nil {
		instanceID = n.Spec.InstanceID
		// OBSOLETE: This fallback can be removed in Cilium 1.9
		if instanceID == "" {
			instanceID = n.Spec.ENI.InstanceID
		}
	}
	return
}

func (n NodeAddress) ToString() string {
	return n.IP
}

func (n NodeAddress) AddrType() addressing.AddressType {
	return n.Type
}

// GetIP returns one of the CiliumNode's IP addresses available with the
// following priority:
// - NodeInternalIP
// - NodeExternalIP
// - other IP address type
// An error is returned if GetIP fails to extract an IP from the CiliumNode
// based on the provided address family.
func (n *CiliumNode) GetIP(ipv6 bool) net.IP {
	return addressing.ExtractNodeIP[NodeAddress](n.Spec.Addresses, ipv6)
}
