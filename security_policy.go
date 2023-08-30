package gonsx

type SecurityPolicy struct {
	BaseNsxPolicyApiResource
	// - Distributed Firewall - Policy framework provides five pre-defined categories for classifying a security policy. They are \"Ethernet\",\"Emergency\", \"Infrastructure\" \"Environment\" and \"Application\". There is a pre-determined order in which the policy framework manages the priority of these security policies. Ethernet category is for supporting layer 2 firewall rules. The other four categories are applicable for layer 3 rules. Amongst them, the Emergency category has the highest priority followed by Infrastructure, Environment and then Application rules. Administrator can choose to categorize a security policy into the above categories or can choose to leave it empty. If empty it will have the least precedence w.r.t the above four categories. - Edge Firewall - Policy Framework for Edge Firewall provides six pre-defined categories \"Emergency\", \"SystemRules\", \"SharedPreRules\", \"LocalGatewayRules\", \"AutoServiceRules\" and \"Default\", in order of priority of rules. All categories are allowed for Gatetway Policies that belong to 'default' Domain. However, for user created domains, category is restricted to \"SharedPreRules\" or \"LocalGatewayRules\" only. Also, the users can add/modify/delete rules from only the \"SharedPreRules\" and \"LocalGatewayRules\" categories. If user doesn't specify the category then defaulted to \"Rules\". System generated category is used by NSX created rules, for example BFD rules. Autoplumbed category used by NSX verticals to autoplumb data path rules. Finally, \"Default\" category is the placeholder default rules with lowest in the order of priority.
	Category *string `json:"category,omitempty"`
	// A flag to indicate whether policy is a default policy.
	IsDefault *bool `json:"is_default,omitempty"`
	// Indicates whether a security policy should be locked. If the security policy is locked by a user, then no other user would be able to modify this security policy. Once the user releases the lock, other users can update this security policy.
	Locked *bool `json:"locked,omitempty"`
	// ID of the user who last modified the lock for the secruity policy.
	LockModifiedBy *string `json:"lock_modified_by,omitempty"`
	// SecurityPolicy locked/unlocked time in epoch milliseconds.
	LockModifiedTime *int64 `json:"lock_modified_time,omitempty"`
	// The count of rules in the policy.
	RuleCount *int32 `json:"rule_count,omitempty"`
	// Comments for security policy lock/unlock.
	Comments *string `json:"comments,omitempty"`
	// This field is to indicate the internal sequence number of a policy with respect to the policies across categories.
	InternalSequenceNumber *int32 `json:"internal_sequence_number,omitempty"`
	// Stateful or Stateless nature of security policy is enforced on all rules in this security policy. When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed. Layer3 security policies can be stateful or stateless. By default, they are stateful. Layer2 security policies can only be stateless.
	Stateful *bool `json:"stateful,omitempty"`
	// Provides a mechanism to apply the rules in this policy for a specified time duration.
	SchedulerPath *string `json:"scheduler_path,omitempty"`
	// Ensures that a 3 way TCP handshake is done before the data packets are sent. tcp_strict=true is supported only for stateful security policies. If the tcp_strict flag is not specified and the security policy is stateful, then tcp_strict will be set to true.
	TcpStrict *bool `json:"tcp_strict,omitempty"`
	// The list of group paths where the rules in this policy will get applied. This scope will take precedence over rule level scope. Supported only for security and redirection policies. In case of RedirectionPolicy, it is expected only when the policy is NS and redirecting to service chain.
	Scope []string `json:"scope,omitempty"`
	// This field is used to resolve conflicts between security policies across domains. In order to change the sequence number of a policy one can fire a POST request on the policy entity with a query parameter action=revise The sequence number field will reflect the value of the computed sequence number upon execution of the above mentioned POST request. For scenarios where the administrator is using a template to update several security policies, the only way to set the sequence number is to explicitly specify the sequence number for each security policy. If no sequence number is specified in the payload, a value of 0 is assigned by default. If there are multiple policies with the same sequence number then their order is not deterministic. If a specific order of policies is desired, then one has to specify unique sequence numbers or use the POST request on the policy entity with a query parameter action=revise to let the framework assign a sequence number. The value of sequence number must be between 0 and 999,999.
	SequenceNumber *int32 `json:"sequence_number,omitempty"`
	// This field indicates the default connectivity policy for the security policy. Based on the connectivitiy preference, a default rule for this security policy will be created. An appropriate action will be set on the rule based on the value of the connectivity preference. If NONE is selected or no connectivity preference is specified, then no default rule for the security policy gets created. The default rule that gets created will be a any-any rule and applied to entities specified in the scope of the security policy. Specifying the connectivity_preference without specifying the scope is not allowed. The scope has to be a Group and one cannot specify IPAddress directly in the group that is used as scope. This default rule is only applicable for the Layer3 security policies. ALLOWLIST - Adds a default drop rule. Administrator can then use \"allow\" rules to allow traffic between groups DENYLIST - Adds a default allow rule. Admin can then use \"drop\" rules to block traffic between groups ALLOWLIST_ENABLE_LOGGING - Allowlisting with logging enabled DENYLIST_ENABLE_LOGGING - Denylisting with logging enabled NONE - No default rule is created.
	ConnectivityPreference *string `json:"connectivity_preference,omitempty"`
	// This field indicates the application connectivity policy for the security policy.
	ApplicationConnectivityStrategy []ApplicationConnectivityStrategy `json:"application_connectivity_strategy,omitempty"`
	// Based on the value of the connectivity strategy, a default rule is created for the security policy. The rule id is internally assigned by the system for this default rule.
	DefaultRuleId *int64 `json:"default_rule_id,omitempty"`
	// Rules that are a part of this SecurityPolicy
	Rules []Rule `json:"rules,omitempty"`
	// This field indicates the default connectivity policy for the security policy. Based on the connectivity strategy, a default rule for this security policy will be created. An appropriate action will be set on the rule based on the value of the connectivity strategy. If NONE is selected or no connectivity strategy is specified, then no default rule for the security policy gets created. The default rule that gets created will be a any-any rule and applied to entities specified in the scope of the security policy. Specifying the connectivity_strategy without specifying the scope is not allowed. The scope has to be a Group and one cannot specify IPAddress directly in the group that is used as scope. This default rule is only applicable for the Layer3 security policies. This property is deprecated. Use the type connectivity_preference instead. WHITELIST - Adds a default drop rule. Administrator can then use \"allow\" rules (aka whitelist) to allow traffic between groups BLACKLIST - Adds a default allow rule. Admin can then use \"drop\" rules (aka blacklist) to block traffic between groups WHITELIST_ENABLE_LOGGING - Whitelising with logging enabled BLACKLIST_ENABLE_LOGGING - Blacklisting with logging enabled NONE - No default rule is created.
	ConnectivityStrategy *string `json:"connectivity_strategy,omitempty"`
	// This property is deprecated. Flag to enable logging for all the rules in the security policy. If the value is true then logging will be enabled for all the rules in the security policy. If the value is false, then the rule level logging value will be honored.
	LoggingEnabled *bool   `json:"logging_enabled,omitempty"`
	TargetType     *string `json:"target_type,omitempty"`
}

type ApplicationConnectivityStrategy struct {
	Strategy       string `json:"application_connectivity_strategy,omitempty"`
	RuleId         *int64 `json:"default_application_rule_id,omitempty"`
	LoggingEnabled *bool  `json:"logging_enabled,omitempty"`
}
