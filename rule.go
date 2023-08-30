package gonsx

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Rule struct {
	BaseNsxPolicyApiResource
	// Flag to disable the rule. Default is enabled.
	Disabled *bool `json:"disabled,omitempty"`
	// Define direction of traffic.
	Direction *string `json:"direction,omitempty"`
	// Type of IP packet that should be matched while enforcing the rule. The value is set to IPV4_IPV6 for Layer3 rule if not specified. For Layer2/Ether rule the value must be null.
	IpProtocol *string `json:"ip_protocol,omitempty"`
	// Text for additional notes on changes.
	Notes *string `json:"notes,omitempty"`
	// Flag to enable packet logging. Default is disabled.
	Logged *bool `json:"logged,omitempty"`
	// Holds the list of layer 7 service profile paths. These profiles accept attributes and sub-attributes of various network services (e.g. L4 AppId, encryption algorithm, domain name, etc) as key value pairs. Instead of Layer 7 service profiles you can use a L7 access profile. One of either Layer 7 service profiles or L7 Access Profile can be used in firewall rule. In case of L7 access profile only one is allowed.
	Profiles []string `json:"profiles,omitempty"`
	// This is a unique 4 byte positive number that is assigned by the system.  This rule id is passed all the way down to the data path. The first 1GB (1000 to 2^30) will be shared by GM and LM with zebra style striped number space. For E.g 1000 to (1Million -1) by LM, (1M - 2M-1) by GM and so on.
	RuleId *int64 `json:"rule_id,omitempty"`
	// A flag to indicate whether rule is a default rule.
	IsDefault *bool `json:"is_default,omitempty"`
	// User level field which will be printed in CLI and packet logs. Even though there is no limitation on length of a tag, internally tag will get truncated after 32 characters.
	Tag *string `json:"tag,omitempty"`
	// We need paths as duplicate names may exist for groups under different domains. Along with paths we support IP Address of type IPv4 and IPv6. IP Address can be in one of the format(CIDR, IP Address, Range of IP Address). In order to specify all groups, use the constant \"ANY\". This is case insensitive. If \"ANY\" is used, it should be the ONLY element in the group array. Error will be thrown if ANY is used in conjunction with other values.
	SourceGroups []string `json:"source_groups,omitempty"`
	// We need paths as duplicate names may exist for groups under different domains. Along with paths we support IP Address of type IPv4 and IPv6. IP Address can be in one of the format(CIDR, IP Address, Range of IP Address). In order to specify all groups, use the constant \"ANY\". This is case insensitive. If \"ANY\" is used, it should be the ONLY element in the group array. Error will be thrown if ANY is used in conjunction with other values.
	DestinationGroups []string `json:"destination_groups,omitempty"`
	// In order to specify all services, use the constant \"ANY\". This is case insensitive. If \"ANY\" is used, it should be the ONLY element in the services array. Error will be thrown if ANY is used in conjunction with other values.
	Services []string `json:"services,omitempty"`
	// The list of policy paths where the rule is applied LR/Edge/T0/T1/LRP etc. Note that a given rule can be applied on multiple LRs/LRPs.
	Scope []string `json:"scope,omitempty"`
	// In order to specify raw services this can be used, along with services which contains path to services. This can be empty or null.
	ServiceEntries []DynamicServiceEntryWrapper `json:"service_entries,omitempty"`
	// If set to true, the rule gets applied on all the groups that are NOT part of the destination groups. If false, the rule applies to the destination groups
	DestinationsExcluded *bool `json:"destinations_excluded,omitempty"`
	// This field is used to resolve conflicts between multiple Rules under Security or Gateway Policy for a Domain If no sequence number is specified in the payload, a value of 0 is assigned by default. If there are multiple rules with the same sequence number then their order is not deterministic. If a specific order of rules is desired, then one has to specify unique sequence numbers or use the POST request on the rule entity with a query parameter action=revise to let the framework assign a sequence number
	SequenceNumber *int32 `json:"sequence_number,omitempty"`
	// If set to true, the rule gets applied on all the groups that are NOT part of the source groups. If false, the rule applies to the source groups
	SourcesExcluded *bool `json:"sources_excluded,omitempty"`
	// The action to be applied to all the services The JUMP_TO_APPLICATION action is only supported for rules created in the Environment category. Once a match is hit then the rule processing will jump to the rules present in the Application category, skipping all further rules in the Environment category. If no rules match in the Application category then the default application rule will be hit. This is applicable only for DFW.
	Action *string `json:"action,omitempty"`
}

func (r Rule) ParentId() string {
	// split parent path by / and return the last element
	parentPath := *r.ParentPath
	parentPathSplit := strings.Split(parentPath, "/")
	return parentPathSplit[len(parentPathSplit)-1]
}

type ServiceEntry struct {
	BaseNsxPolicyApiResource
}

func (e ServiceEntry) isDynamicServiceEntry() {}

type DynamicServiceEntry interface {
	isDynamicServiceEntry()
}

type DynamicServiceEntryWrapper struct {
	ServiceEntry DynamicServiceEntry `json:"-"`
}

var DynamicServiceEntryMap = map[string]func() DynamicServiceEntry{
	"ALGTypeServiceEntry": func() DynamicServiceEntry {
		return &AlgServiceEntry{}
	},
	"EtherTypeServiceEntry": func() DynamicServiceEntry {
		return &EtherServiceEntry{}
	},
	"ICMPTypeServiceEntry": func() DynamicServiceEntry {
		return &IcmpServiceEntry{}
	},
	"IGMPTypeServiceEntry": func() DynamicServiceEntry {
		return &IgmpServiceEntry{}
	},
	"IPProtocolServiceEntry": func() DynamicServiceEntry {
		return &IpProtocolServiceEntry{}
	},
	"L4PortSetServiceEntry": func() DynamicServiceEntry {
		return &L4PortSetServiceEntry{}
	},
	"NestedServiceServiceEntry": func() DynamicServiceEntry {
		return &NestedServiceEntry{}
	},
}

// unmarshalJSON is a custom unmarshaler for DynamicServiceEntryWrapper
func (e *DynamicServiceEntryWrapper) UnmarshalJSON(data []byte) error {
	var baseServiceEntry ServiceEntry
	err := json.Unmarshal(data, &baseServiceEntry)
	if err != nil {
		return err
	}

	serviceEntry, ok := DynamicServiceEntryMap[*baseServiceEntry.ResourceType]
	if !ok {
		return fmt.Errorf("unknown service entry type %s", *baseServiceEntry.ResourceType)
	}

	e.ServiceEntry = serviceEntry()

	err = json.Unmarshal(data, e.ServiceEntry)
	if err != nil {
		return err
	}

	return nil
}

func (s *DynamicServiceEntryWrapper) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ServiceEntry)
}

type AlgServiceEntry struct {
	ServiceEntry
	Alg string `json:"alg"`
	// despite the s in the name, this is a single port
	DestinationPorts []string `json:"destination_ports"`
	SourcePorts      []string `json:"source_ports,omitempty"`
}

type EtherServiceEntry struct {
	ServiceEntry
	EtherType int `json:"ether_type,omitempty"`
}

type IcmpServiceEntry struct {
	ServiceEntry
	IcmpType *uint8 `json:"icmp_type,omitempty"`
	IcmpCode *uint8 `json:"icmp_code,omitempty"`
	Protocol string `json:"protocol"`
}

type IgmpServiceEntry struct {
	ServiceEntry
}

type IpProtocolServiceEntry struct {
	ServiceEntry
	ProtocolNumber uint8 `json:"protocol_number"`
}

type L4PortSetServiceEntry struct {
	ServiceEntry
	L4Protocol       string   `json:"l4_protocol"`
	DestinationPorts []string `json:"destination_ports"`
	SourcePorts      []string `json:"source_ports,omitempty"`
}

type NestedServiceEntry struct {
	ServiceEntry
	NestedServicePath string `json:"nested_service_path"`
}
