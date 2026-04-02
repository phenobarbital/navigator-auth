//! High-performance PEP batch filter for navigator-auth PBAC.
//!
//! Provides `filter_resources_batch` — a PyO3 function that takes serialized
//! policies, a list of resources, user context, and environment, and returns
//! which resources are allowed/denied.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use serde::Deserialize;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Data models (deserialized from JSON/Python dicts)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
struct PolicyDef {
    name: String,
    effect: String, // "allow" or "deny"
    resources: Vec<String>,
    actions: Vec<String>,
    #[serde(default)]
    subjects: SubjectSpec,
    #[serde(default)]
    conditions: ConditionSpec,
    #[serde(default)]
    priority: i32,
    #[serde(default)]
    enforcing: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct SubjectSpec {
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    exclude_groups: Vec<String>,
    #[serde(default)]
    exclude_users: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ConditionSpec {
    #[serde(default)]
    environment: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct UserContext {
    #[serde(default)]
    username: String,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct EnvironmentContext {
    #[serde(default)]
    hour: i32,
    #[serde(default)]
    dow: i32,
    #[serde(default)]
    is_business_hours: bool,
    #[serde(default)]
    is_weekend: bool,
    #[serde(default)]
    day_segment: String,
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/// Match a resource name against a pattern (supports * wildcard and ? single char).
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Use glob_match for wildcard patterns
    if pattern.contains('*') || pattern.contains('?') {
        return glob_match::glob_match(pattern, name);
    }
    pattern == name
}

/// Check if a policy covers a specific resource string "type:name".
fn policy_covers_resource(policy: &PolicyDef, resource: &str) -> bool {
    if policy.resources.is_empty() {
        return true; // No resource restriction
    }
    for pattern in &policy.resources {
        if let Some((ptype, pname)) = pattern.split_once(':') {
            if let Some((rtype, rname)) = resource.split_once(':') {
                if ptype == rtype && matches_pattern(pname, rname) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a policy covers a specific action.
fn policy_covers_action(policy: &PolicyDef, action: &str) -> bool {
    if policy.actions.is_empty() {
        return true;
    }
    policy.actions.iter().any(|a| a == action)
}

/// Check if a user matches the policy's subject specification.
fn matches_subject(policy: &PolicyDef, user: &UserContext) -> bool {
    let spec = &policy.subjects;

    // Check exclusions first
    if spec.exclude_users.contains(&user.username) {
        return false;
    }
    let user_groups: HashSet<&str> = user.groups.iter().map(|s| s.as_str()).collect();
    if spec
        .exclude_groups
        .iter()
        .any(|g| user_groups.contains(g.as_str()))
    {
        return false;
    }

    // Check inclusions
    if spec.groups.iter().any(|g| g == "*") {
        return true;
    }
    if spec.users.contains(&user.username) {
        return true;
    }
    if spec.groups.iter().any(|g| user_groups.contains(g.as_str())) {
        return true;
    }
    let user_roles: HashSet<&str> = user.roles.iter().map(|s| s.as_str()).collect();
    if spec.roles.iter().any(|r| user_roles.contains(r.as_str())) {
        return true;
    }

    // If no subjects specified at all, match everyone
    spec.groups.is_empty()
        && spec.users.is_empty()
        && spec.roles.is_empty()
}

/// Check environment conditions.
fn matches_environment(policy: &PolicyDef, env: &EnvironmentContext) -> bool {
    for (key, expected) in &policy.conditions.environment {
        match key.as_str() {
            "is_business_hours" => {
                if let Some(val) = expected.as_bool() {
                    if env.is_business_hours != val {
                        return false;
                    }
                }
            }
            "is_weekend" => {
                if let Some(val) = expected.as_bool() {
                    if env.is_weekend != val {
                        return false;
                    }
                }
            }
            "hour" => {
                if let Some(val) = expected.as_i64() {
                    if env.hour != val as i32 {
                        return false;
                    }
                }
            }
            "dow" => {
                if let Some(val) = expected.as_i64() {
                    if env.dow != val as i32 {
                        return false;
                    }
                }
            }
            "day_segment" => {
                if let Some(val) = expected.as_str() {
                    if env.day_segment != val {
                        return false;
                    }
                }
            }
            _ => {} // Unknown conditions are ignored
        }
    }
    true
}

/// Evaluate whether a single resource is allowed by the policy set.
fn evaluate_resource(
    policies: &[PolicyDef],
    resource: &str,
    action: &str,
    user: &UserContext,
    env: &EnvironmentContext,
) -> bool {
    let mut best_allow: Option<i32> = None;
    let mut best_deny: Option<i32> = None;

    for policy in policies {
        // Check enforcing policies first
        if !policy_covers_resource(policy, resource) {
            continue;
        }
        if !policy_covers_action(policy, action) {
            continue;
        }
        if !matches_subject(policy, user) {
            continue;
        }
        if !matches_environment(policy, env) {
            continue;
        }

        let is_allow = policy.effect.to_lowercase() == "allow";

        if policy.enforcing {
            return is_allow;
        }

        if is_allow {
            best_allow = Some(best_allow.map_or(policy.priority, |p: i32| p.max(policy.priority)));
        } else {
            best_deny = Some(best_deny.map_or(policy.priority, |p: i32| p.max(policy.priority)));
        }
    }

    // Deny takes precedence at equal priority
    match (best_deny, best_allow) {
        (Some(dp), Some(ap)) => ap > dp,
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (None, None) => false, // Default deny
    }
}

// ---------------------------------------------------------------------------
// PyO3 exposed function
// ---------------------------------------------------------------------------

/// Batch filter resources against policies.
///
/// Args:
///     policies_json: JSON string of policy definitions.
///     resources: List of resource strings (e.g. ["tool:jira_create", "tool:github_pr"]).
///     user_context: Dict with username, groups, roles.
///     environment: Dict with hour, dow, is_business_hours, is_weekend, day_segment.
///
/// Returns:
///     Dict with "allowed" and "denied" lists of resource strings.
#[pyfunction]
#[pyo3(signature = (policies_json, resources, user_context, environment))]
fn filter_resources_batch(
    py: Python<'_>,
    policies_json: &str,
    resources: Vec<String>,
    user_context: &Bound<'_, PyDict>,
    environment: &Bound<'_, PyDict>,
) -> PyResult<PyObject> {
    // Parse policies
    let policies: Vec<PolicyDef> = serde_json::from_str(policies_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid policies JSON: {e}")))?;

    // Parse user context
    let user = UserContext {
        username: user_context
            .get_item("username")?
            .map(|v| v.extract::<String>().unwrap_or_default())
            .unwrap_or_default(),
        groups: user_context
            .get_item("groups")?
            .map(|v| v.extract::<Vec<String>>().unwrap_or_default())
            .unwrap_or_default(),
        roles: user_context
            .get_item("roles")?
            .map(|v| v.extract::<Vec<String>>().unwrap_or_default())
            .unwrap_or_default(),
    };

    // Parse environment
    let env = EnvironmentContext {
        hour: environment
            .get_item("hour")?
            .map(|v| v.extract::<i32>().unwrap_or(0))
            .unwrap_or(0),
        dow: environment
            .get_item("dow")?
            .map(|v| v.extract::<i32>().unwrap_or(0))
            .unwrap_or(0),
        is_business_hours: environment
            .get_item("is_business_hours")?
            .map(|v| v.extract::<bool>().unwrap_or(false))
            .unwrap_or(false),
        is_weekend: environment
            .get_item("is_weekend")?
            .map(|v| v.extract::<bool>().unwrap_or(false))
            .unwrap_or(false),
        day_segment: environment
            .get_item("day_segment")?
            .map(|v| v.extract::<String>().unwrap_or_default())
            .unwrap_or_default(),
    };

    // Extract the action from resources or use default
    // Resources are expected as "type:name", action comes from context
    let action = user_context
        .get_item("action")?
        .map(|v| v.extract::<String>().unwrap_or_default())
        .unwrap_or_default();

    // Parallel batch evaluation using rayon
    let results: Vec<(String, bool)> = py.allow_threads(|| {
        resources
            .par_iter()
            .map(|resource| {
                let allowed = evaluate_resource(&policies, resource, &action, &user, &env);
                (resource.clone(), allowed)
            })
            .collect()
    });

    // Build result dict
    let result_dict = PyDict::new_bound(py);
    let mut allowed_list: Vec<String> = Vec::new();
    let mut denied_list: Vec<String> = Vec::new();

    for (resource, is_allowed) in results {
        if is_allowed {
            allowed_list.push(resource);
        } else {
            denied_list.push(resource);
        }
    }

    result_dict.set_item("allowed", allowed_list)?;
    result_dict.set_item("denied", denied_list)?;

    Ok(result_dict.into())
}

/// Navigator Auth PEP module — high-performance batch resource filtering.
#[pymodule]
fn navigator_auth_pep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(filter_resources_batch, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("jira_*", "jira_create"));
        assert!(matches_pattern("jira_*", "jira_delete"));
        assert!(!matches_pattern("jira_*", "github_pr"));
        assert!(matches_pattern("exact", "exact"));
        assert!(!matches_pattern("exact", "other"));
    }

    #[test]
    fn test_policy_covers_resource() {
        let policy = PolicyDef {
            name: "test".into(),
            effect: "allow".into(),
            resources: vec!["tool:jira_*".into(), "tool:github_*".into()],
            actions: vec![],
            subjects: SubjectSpec::default(),
            conditions: ConditionSpec::default(),
            priority: 0,
            enforcing: false,
        };
        assert!(policy_covers_resource(&policy, "tool:jira_create"));
        assert!(policy_covers_resource(&policy, "tool:github_pr"));
        assert!(!policy_covers_resource(&policy, "tool:slack_send"));
        assert!(!policy_covers_resource(&policy, "kb:docs"));
    }

    #[test]
    fn test_evaluate_resource_basic() {
        let policies = vec![PolicyDef {
            name: "allow_engineering".into(),
            effect: "allow".into(),
            resources: vec!["tool:*".into()],
            actions: vec!["tool:execute".into()],
            subjects: SubjectSpec {
                groups: vec!["engineering".into()],
                ..Default::default()
            },
            conditions: ConditionSpec::default(),
            priority: 10,
            enforcing: false,
        }];

        let user = UserContext {
            username: "testuser".into(),
            groups: vec!["engineering".into()],
            roles: vec![],
        };

        let env = EnvironmentContext {
            hour: 10,
            dow: 2,
            is_business_hours: true,
            is_weekend: false,
            day_segment: "morning".into(),
        };

        assert!(evaluate_resource(
            &policies,
            "tool:jira_create",
            "tool:execute",
            &user,
            &env
        ));
    }
}
