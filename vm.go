package gonsx

type VirtualMachine struct {
	BaseNsxPolicyApiResource
	// List of external compute ids of the virtual machine in the format 'id-type-key:value' , list of external compute ids ['uuid:xxxx-xxxx-xxxx-xxxx', 'moIdOnHost:moref-11', 'instanceUuid:xxxx-xxxx-xxxx-xxxx']
	ComputeIds []string `json:"compute_ids"`
	// Current external id of this virtual machine in the system.
	ExternalId string     `json:"external_id"`
	GuestInfo  *GuestInfo `json:"guest_info,omitempty"`
	// Id of the host in which this virtual machine exists.
	HostId     *string                   `json:"host_id,omitempty"`
	LocalId    string                    `json:"local_id_on_host"`
	PowerState string                    `json:"power_state"`
	Scope      []DiscoveredResourceScope `json:"scope,omitempty"`
	Source     *ResourceReference        `json:"source,omitempty"`
}

type GuestInfo struct {
	ComputerName *string `json:"computer_name,omitempty"`
	OsName       *string `json:"os_name,omitempty"`
}

type DiscoveredResourceScope struct {
	ScopeId   *string `json:"scope_id,omitempty"`
	ScopeType *string `json:"scope_type,omitempty"`
}

type ResourceReference struct {
	Valid             *bool   `json:"is_valid,omitempty"`
	TargetDisplayName *string `json:"target_display_name,omitempty"`
	TargetId          *string `json:"target_id,omitempty"`
	TargetType        *string `json:"target_type,omitempty"`
}
