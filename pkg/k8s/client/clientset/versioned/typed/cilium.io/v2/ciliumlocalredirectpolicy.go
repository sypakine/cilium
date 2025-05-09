// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	context "context"

	ciliumiov2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumLocalRedirectPoliciesGetter has a method to return a CiliumLocalRedirectPolicyInterface.
// A group's client should implement this interface.
type CiliumLocalRedirectPoliciesGetter interface {
	CiliumLocalRedirectPolicies(namespace string) CiliumLocalRedirectPolicyInterface
}

// CiliumLocalRedirectPolicyInterface has methods to work with CiliumLocalRedirectPolicy resources.
type CiliumLocalRedirectPolicyInterface interface {
	Create(ctx context.Context, ciliumLocalRedirectPolicy *ciliumiov2.CiliumLocalRedirectPolicy, opts v1.CreateOptions) (*ciliumiov2.CiliumLocalRedirectPolicy, error)
	Update(ctx context.Context, ciliumLocalRedirectPolicy *ciliumiov2.CiliumLocalRedirectPolicy, opts v1.UpdateOptions) (*ciliumiov2.CiliumLocalRedirectPolicy, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, ciliumLocalRedirectPolicy *ciliumiov2.CiliumLocalRedirectPolicy, opts v1.UpdateOptions) (*ciliumiov2.CiliumLocalRedirectPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*ciliumiov2.CiliumLocalRedirectPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*ciliumiov2.CiliumLocalRedirectPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *ciliumiov2.CiliumLocalRedirectPolicy, err error)
	CiliumLocalRedirectPolicyExpansion
}

// ciliumLocalRedirectPolicies implements CiliumLocalRedirectPolicyInterface
type ciliumLocalRedirectPolicies struct {
	*gentype.ClientWithList[*ciliumiov2.CiliumLocalRedirectPolicy, *ciliumiov2.CiliumLocalRedirectPolicyList]
}

// newCiliumLocalRedirectPolicies returns a CiliumLocalRedirectPolicies
func newCiliumLocalRedirectPolicies(c *CiliumV2Client, namespace string) *ciliumLocalRedirectPolicies {
	return &ciliumLocalRedirectPolicies{
		gentype.NewClientWithList[*ciliumiov2.CiliumLocalRedirectPolicy, *ciliumiov2.CiliumLocalRedirectPolicyList](
			"ciliumlocalredirectpolicies",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *ciliumiov2.CiliumLocalRedirectPolicy { return &ciliumiov2.CiliumLocalRedirectPolicy{} },
			func() *ciliumiov2.CiliumLocalRedirectPolicyList { return &ciliumiov2.CiliumLocalRedirectPolicyList{} },
		),
	}
}
