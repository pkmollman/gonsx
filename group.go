package gonsx

import (
	"encoding/json"
	"fmt"
)

const (
	AllGroupsEndpoint = "/policy/api/v1/infra/domains/default/groups"
)

type Group struct {
	BaseNsxPolicyApiResource
	// Realization state of this group
	State *string `json:"state,omitempty"`
	// Extended Expression allows additional higher level context to be specified for grouping criteria. (e.g. user AD group) This field allow users to specified user context as the source of a firewall rule for IDFW feature. Current version only support a single IdentityGroupExpression. In the future, this might expand to support other conjunction and non-conjunction expression.  The extended expression list must follow below criteria: 1. Contains a single IdentityGroupExpression. No conjunction expression is supported. 2. No other non-conjunction expression is supported, except for IdentityGroupExpression. 3. Each expression must be a valid Expression. See the definition of the Expression type for more information. 4. Extended expression are implicitly AND with expression. 5. No nesting can be supported if this value is used. 6. If a Group is using extended expression, this group must be the only member in the source field of an communication map.
	ExtendedExpression []DynamicExpressionWrapper `json:"extended_expression,omitempty"`
	// The expression list must follow below criteria:   1. A non-empty expression list, must be of odd size. In a list, with   indices starting from 0, all non-conjunction expressions must be at   even indices, separated by a conjunction expression at odd   indices.   2. The total of ConditionExpression and NestedExpression in a list   should not exceed 5.   3. The total of IPAddressExpression, MACAddressExpression, external   IDs in an ExternalIDExpression and paths in a PathExpression must not exceed   500.   4. Each expression must be a valid Expression. See the definition of   the Expression type for more information.
	Expression []DynamicExpressionWrapper `json:"expression,omitempty"`
	// Group type can be specified during create and update of a group. Empty group type indicates a 'generic' group, ie group can include any entity from the valid GroupMemberType.
	GroupType []string `json:"group_type,omitempty"`
	// If true, indicates that this is a remote reference group. Such group will have span different from the its parent domain. Default value is false.
	Reference *bool `json:"reference,omitempty"`
}

func (g *Group) String() string {
	if g == nil {
		return "<nil>"
	}
	return fmt.Sprintf(`Group: %s`, *g.DisplayName)
}

type Expression struct {
	BaseNsxPolicyApiResource
}

func (e Expression) isDynamicExpression() {}

type DynamicExpression interface {
	isDynamicExpression()
}

type DynamicExpressionWrapper struct {
	Expression DynamicExpression `json:"-"`
}

func (e *DynamicExpressionWrapper) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Expression)
}

var DynamicExpressionMap = map[string]func() DynamicExpression{
	"Condition": func() DynamicExpression {
		return &ExpressionCondition{}
	},
	"ConjunctionOperator": func() DynamicExpression {
		return &ExpressionConjunctionOperator{}
	},
	"IPAddressExpression": func() DynamicExpression {
		return &ExpressionIPAddress{}
	},
	"PathExpression": func() DynamicExpression {
		return &ExpressionPath{}
	},
	"ExternalIDExpression": func() DynamicExpression {
		return &ExpressionExternalID{}
	},
	"MACAddressExpression": func() DynamicExpression {
		return &ExpressionMACAddress{}
	},
	"IdentityGroupExpression": func() DynamicExpression {
		return &ExpressionIdentityGroup{}
	},
}

// unmarshalJSON is a custom unmarshaler for DynamicExpressionWrapper
func (e *DynamicExpressionWrapper) UnmarshalJSON(data []byte) error {
	var baseExpression Expression
	err := json.Unmarshal(data, &baseExpression)
	if err != nil {
		return err
	}

	// typeString := *baseExpression.ResourceType

	expression, ok := DynamicExpressionMap[*baseExpression.ResourceType]
	if !ok {
		return fmt.Errorf("unknown expression type %s", *baseExpression.ResourceType)
	}

	e.Expression = expression()

	err = json.Unmarshal(data, e.Expression)
	if err != nil {
		return err
	}

	return nil
}

type ExpressionCondition struct {
	Expression
	// Operator is made non-mandatory to support Segment and SegmentPort tag based expression. To evaluate expression for other types, operator value should be provided.
	Operator *string `json:"operator,omitempty"`
	// Value
	Value *string `json:"value"`
	// Default operator when not specified explicitly would be considered as EQUALS. If value for Condition is empty, then condition will not be evaluated. For example, Condition with key as Tag and value as \"|tag\" would be evaluated for tag value not for empty scope value.
	ScopeOperator *string `json:"scope_operator,omitempty"`
	// Key
	Key *string `json:"key"`
	// Group member type
	MemberType *string `json:"member_type"`
}

// GroupConjunctionOperator Represents the operators AND or OR.
type ExpressionConjunctionOperator struct {
	Expression
	// Conjunction Operator Node
	ConjunctionOperator *string `json:"conjunction_operator"`
}

type ExpressionIPAddress struct {
	Expression
	// IP Addresses
	IpAddresses []string `json:"ip_addresses"`
}

type ExpressionMACAddress struct {
	Expression
	// MAC Addresses
	MacAddresses []string `json:"mac_addresses"`
}

type ExpressionPath struct {
	Expression
	// Path
	Paths []string `json:"paths"`
}

type ExpressionExternalID struct {
	Expression
	// External IDs
	ExternalIds []string `json:"external_ids"`
	// External ID Type
	ExternalIdType *string `json:"member_type"`
}

type ExpressionIdentityGroup struct {
	Expression
	// Identity Groups, minimum 1 element is required
	IdentityGroups []IdentityGroupInfo `json:"identity_groups"`
}

type IdentityGroupInfo struct {
	DistinguishedName string `json:"distinguished_name"`
	DomainBaseDN      string `json:"domain_base_distinquished_name"`
	Sid               string `json:"sid,omitempty"`
}

func (g *Group) GetMembers(nsxConfig *NSXClient) ([]string, error) {
	members := []string{}

	vmMembersChan := make(chan []string, 1)
	ipMembersChan := make(chan []string, 1)

	go func() {
		members, err := g.GetVmMembers(nsxConfig)
		if err != nil {
			vmMembersChan <- nil
		}
		vmMembersChan <- members
	}()

	go func() {
		members, err := g.GetIPAddressMembers(nsxConfig)
		if err != nil {
			ipMembersChan <- nil
		}
		ipMembersChan <- members
	}()

	var vmMembers []string = <-vmMembersChan
	var ipMembers []string = <-ipMembersChan

	if vmMembers == nil {
		return nil, fmt.Errorf("error getting vm members")
	}

	if ipMembers == nil {
		return nil, fmt.Errorf("error getting ip members")
	}

	members = append(members, vmMembers...)
	members = append(members, ipMembers...)

	return members, nil

}

func (g *Group) GetIPAddressMembers(nsxConfig *NSXClient) ([]string, error) {
	requestURI := fmt.Sprintf("https://%s/policy/api/v1/infra/domains/default/groups/%s/members/ip-addresses", nsxConfig.Hostname, *g.Id)
	request, err := nsxConfig.NewRequest("GET", requestURI, nil)

	if err != nil {
		return nil, err
	}

	response, err := nsxConfig.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	type ipResults struct {
		Results []string `json:"results"`
	}

	results := ipResults{}
	// unmarschal the response into the results struct
	err = json.NewDecoder(response.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	return results.Results, nil
}

func (g *Group) GetVmMembers(nsxConfig *NSXClient) ([]string, error) {
	requestURI := fmt.Sprintf("https://%s/policy/api/v1/infra/domains/default/groups/%s/members/virtual-machines", nsxConfig.Hostname, *g.Id)
	request, err := nsxConfig.NewRequest("GET", requestURI, nil)

	if err != nil {
		return nil, err
	}

	response, err := nsxConfig.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	type ipResults struct {
		Results []BaseNsxPolicyApiResource `json:"results"`
	}

	results := ipResults{}
	// unmarschal the response into the results struct
	err = json.NewDecoder(response.Body).Decode(&results)
	if err != nil {
		return nil, err
	}

	vmNames := make([]string, 0)

	for _, vm := range results.Results {
		if vm.DisplayName != nil {
			vmNames = append(vmNames, *vm.DisplayName)
		}
	}

	return vmNames, nil
}
