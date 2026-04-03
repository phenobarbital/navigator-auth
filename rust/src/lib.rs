//! High-performance PEP batch filter for navigator-auth PBAC.
//!
//! Provides `filter_resources_batch` — a PyO3 function that takes serialized
//! policies, a list of resources, user context, and environment, and returns
//! which resources are allowed/denied.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Data models (deserialized from JSON/Python dicts)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct EvaluationResult {
    allowed: bool,
    effect: String,
    matched_policy: Option<String>,
    reason: String,
}

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
    groups: HashSet<String>,
    #[serde(default)]
    users: HashSet<String>,
    #[serde(default)]
    roles: HashSet<String>,
    #[serde(default)]
    exclude_groups: HashSet<String>,
    #[serde(default)]
    exclude_users: HashSet<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct ConditionSpec {
    #[serde(default)]
    environment: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    is_manager: bool,
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

/// Check if a pattern string contains regex metacharacters.
fn is_regex_pattern(pattern: &str) -> bool {
    pattern.contains('^')
        || pattern.contains('$')
        || pattern.contains('(')
        || pattern.contains(')')
        || pattern.contains('+')
        || pattern.contains('{')
        || pattern.contains('[')
        || pattern.contains(']')
        || pattern.contains('|')
}

/// Pre-compile all regex patterns found in the policy resource definitions.
fn build_regex_cache(policies: &[PolicyDef]) -> HashMap<String, Regex> {
    let mut cache = HashMap::new();
    for policy in policies {
        for pattern in &policy.resources {
            if let Some((_, pname)) = pattern.split_once(':') {
                if is_regex_pattern(pname) && !cache.contains_key(pname) {
                    if let Ok(re) = Regex::new(pname) {
                        cache.insert(pname.to_string(), re);
                    }
                }
            }
        }
    }
    cache
}

/// Match a resource name against a pattern (supports * wildcard, ? single char, and Regex).
fn matches_pattern(pattern: &str, name: &str, regex_cache: Option<&HashMap<String, Regex>>) -> bool {
    if pattern == "*" {
        return true;
    }

    if is_regex_pattern(pattern) {
        if let Some(cache) = regex_cache {
            if let Some(re) = cache.get(pattern) {
                return re.is_match(name);
            }
        }
        // Fallback: compile on-the-fly (should be avoided by caller)
        match Regex::new(pattern) {
            Ok(re) => re.is_match(name),
            Err(_) => false, // Invalid regex = no match
        }
    } else if pattern.contains('*') || pattern.contains('?') {
        // Use glob_match for wildcard patterns
        glob_match::glob_match(pattern, name)
    } else {
        pattern == name
    }
}

/// Check if a policy covers a specific resource string "type:name".
fn policy_covers_resource(
    policy: &PolicyDef,
    resource: &str,
    regex_cache: Option<&HashMap<String, Regex>>,
) -> bool {
    if policy.resources.is_empty() {
        return true; // No resource restriction
    }
    for pattern in &policy.resources {
        if pattern == "*" || pattern == "*:*" {
            return true;
        }
        if let Some((ptype, pname)) = pattern.split_once(':') {
            if let Some((rtype, rname)) = resource.split_once(':') {
                if (ptype == "*" || ptype == rtype) && matches_pattern(pname, rname, regex_cache) {
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
    policy.actions.iter().any(|a| a == "*" || a == action)
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

fn compare_json_nums(v1: &serde_json::Value, v2: &serde_json::Value) -> bool {
    if let (Some(i1), Some(i2)) = (v1.as_i64(), v2.as_i64()) {
        return i1 == i2;
    }
    if let (Some(f1), Some(f2)) = (v1.as_f64(), v2.as_f64()) {
        return (f1 - f2).abs() < f64::EPSILON;
    }
    v1 == v2
}

/// Check environment conditions.
fn matches_environment(policy: &PolicyDef, env: &EnvironmentContext) -> bool {
    for (key, expected) in &policy.conditions.environment {
        let current_value: serde_json::Value = match key.as_str() {
            "is_business_hours" => env.is_business_hours.into(),
            "is_weekend" => env.is_weekend.into(),
            "hour" => env.hour.into(),
            "dow" => env.dow.into(),
            "day_segment" => env.day_segment.clone().into(),
            _ => continue, // Unknown conditions are ignored
        };

        if expected.is_array() {
            // List match: current_value IN expected_list
            let list = expected.as_array().unwrap();
            if !list.iter().any(|item| compare_json_nums(&current_value, item)) {
                return false;
            }
        } else if expected.is_object() {
            // Range match: min <= current_value <= max
            let obj = expected.as_object().unwrap();
            if let Some(min) = obj.get("min") {
                if let (Some(c), Some(m)) = (current_value.as_f64(), min.as_f64()) {
                    if c < m {
                        return false;
                    }
                }
            }
            if let Some(max) = obj.get("max") {
                if let (Some(c), Some(m)) = (current_value.as_f64(), max.as_f64()) {
                    if c > m {
                        return false;
                    }
                }
            }
        } else {
            // Exact match
            if !compare_json_nums(&current_value, expected) {
                return false;
            }
        }
    }
    true
}

/// Check hierarchical conditions (e.g. Manager access)
fn matches_hierarchy(policy: &PolicyDef, user: &UserContext, owner_reports_to: Option<&str>) -> bool {
    if !policy.conditions.is_manager {
        return true; // No hierarchy check required
    }
    // If is_manager is true, the current user must be the manager of the resource owner
    if let Some(reports_to) = owner_reports_to {
        return reports_to == user.username;
    }
    false
}

/// Evaluate whether a single resource is allowed by the policy set.
fn evaluate_resource(
    policies: &[PolicyDef],
    resource: &str,
    action: &str,
    user: &UserContext,
    env: &EnvironmentContext,
    regex_cache: Option<&HashMap<String, Regex>>,
    owner_reports_to: Option<&str>,
) -> EvaluationResult {
    let mut best_allow: Option<(i32, String)> = None;
    let mut best_deny: Option<(i32, String)> = None;

    for policy in policies {
        // Check conditions
        if !policy_covers_resource(policy, resource, regex_cache) {
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
        if !matches_hierarchy(policy, user, owner_reports_to) {
            continue;
        }

        let is_allow = policy.effect.to_lowercase() == "allow";
        let priority = policy.priority;
        let policy_name = policy.name.clone();

        if policy.enforcing {
            return EvaluationResult {
                allowed: is_allow,
                effect: policy.effect.clone(),
                matched_policy: Some(policy_name.clone()),
                reason: format!("Enforcing policy '{}' matched", policy_name),
            };
        }

        if is_allow {
            if best_allow.is_none() || priority > best_allow.as_ref().unwrap().0 {
                best_allow = Some((priority, policy_name));
            }
        } else if best_deny.is_none() || priority >= best_deny.as_ref().unwrap().0 {
            // Deny takes precedence at equal priority, so we use >=
            best_deny = Some((priority, policy_name));
        }
    }

    // Determine outcome
    match (best_deny, best_allow) {
        (Some((dp, dn)), Some((ap, an))) => {
            if ap > dp {
                EvaluationResult {
                    allowed: true,
                    effect: "allow".into(),
                    matched_policy: Some(an),
                    reason: "Highest priority Allow policy won".into(),
                }
            } else {
                EvaluationResult {
                    allowed: false,
                    effect: "deny".into(),
                    matched_policy: Some(dn),
                    reason: "Deny policy wins on priority or tie".into(),
                }
            }
        }
        (None, Some((_, an))) => EvaluationResult {
            allowed: true,
            effect: "allow".into(),
            matched_policy: Some(an),
            reason: "Matched Allow policy".into(),
        },
        (Some((_, dn)), None) => EvaluationResult {
            allowed: false,
            effect: "deny".into(),
            matched_policy: Some(dn),
            reason: "Matched Deny policy".into(),
        },
        (None, None) => EvaluationResult {
            allowed: false,
            effect: "deny".into(),
            matched_policy: None,
            reason: "Default deny (no policies matched)".into(),
        },
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

    // Parse the action from user_context
    let action = user_context
        .get_item("action")?
        .map(|v| v.extract::<String>().unwrap_or_default())
        .unwrap_or_default();

    // Pre-compile regexes for all patterns
    let regex_cache = build_regex_cache(&policies);

    // Parallel batch evaluation using rayon
    let results: Vec<(String, bool)> = py.allow_threads(|| {
        resources
            .par_iter()
            .map(|resource| {
                let result = evaluate_resource(
                    &policies,
                    resource,
                    &action,
                    &user,
                    &env,
                    Some(&regex_cache),
                    None, // Batch filter doesn't support per-resource owner yet
                );
                (resource.clone(), result.allowed)
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

/// Evaluate a single resource against policies.
///
/// Returns:
///     Dict with {allowed: bool, effect: str, matched_policy: str, reason: str}
#[pyfunction]
#[pyo3(signature = (policies_json, resource, action, user_context, environment, owner_reports_to=None))]
fn evaluate_single(
    py: Python<'_>,
    policies_json: &str,
    resource: &str,
    action: &str,
    user_context: &Bound<'_, PyDict>,
    environment: &Bound<'_, PyDict>,
    owner_reports_to: Option<String>,
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

    // Pre-compile regexes for all patterns
    let regex_cache = build_regex_cache(&policies);

    // Single evaluation (no rayon needed)
    let result = py.allow_threads(|| {
        evaluate_resource(
            &policies,
            resource,
            action,
            &user,
            &env,
            Some(&regex_cache),
            owner_reports_to.as_deref(),
        )
    });

    // Build result dict
    let result_dict = PyDict::new_bound(py);
    result_dict.set_item("allowed", result.allowed)?;
    result_dict.set_item("effect", result.effect)?;
    result_dict.set_item("matched_policy", result.matched_policy)?;
    result_dict.set_item("reason", result.reason)?;

    Ok(result_dict.into())
}

/// Navigator Auth PEP module — high-performance batch resource filtering.
#[pymodule]
fn navigator_auth_pep(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(filter_resources_batch, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_single, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*", "anything", None));
        assert!(matches_pattern("jira_*", "jira_create", None));
        assert!(matches_pattern("jira_*", "jira_delete", None));
        assert!(!matches_pattern("jira_*", "github_pr", None));
        assert!(matches_pattern("exact", "exact", None));
        assert!(!matches_pattern("exact", "other", None));
    }

    #[test]
    fn test_regex_matching() {
        assert!(matches_pattern("epson.*$", "epson_lx350", None));
        assert!(matches_pattern("^/api/v[12]/.*", "/api/v1/users", None));
        assert!(matches_pattern("^/api/v[12]/.*", "/api/v2/admin", None));
        assert!(!matches_pattern("^/api/v[12]/.*", "/web/home", None));
    }

    #[test]
    fn test_invalid_regex_no_panic() {
        assert!(!matches_pattern("invalid(regex[", "anything", None));
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
        assert!(policy_covers_resource(&policy, "tool:jira_create", None));
        assert!(policy_covers_resource(&policy, "tool:github_pr", None));
        assert!(!policy_covers_resource(&policy, "tool:slack_send", None));
        assert!(!policy_covers_resource(&policy, "kb:docs", None));
    }

    #[test]
    fn test_evaluate_resource_basic() {
        let policies = vec![PolicyDef {
            name: "allow_engineering".into(),
            effect: "allow".into(),
            resources: vec!["tool:*".into()],
            actions: vec!["tool:execute".into()],
            subjects: SubjectSpec {
                groups: ["engineering".to_string()].into_iter().collect(),
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

        let result = evaluate_resource(
            &policies,
            "tool:jira_create",
            "tool:execute",
            &user,
            &env,
            None,
            None,
        );
        assert!(result.allowed);
        assert_eq!(result.matched_policy, Some("allow_engineering".into()));
    }

    #[test]
    fn test_evaluate_resource_with_regex() {
        let policies = vec![PolicyDef {
            name: "block_printers".into(),
            effect: "deny".into(),
            resources: vec!["uri:epson.*$".into()],
            actions: vec![],
            subjects: SubjectSpec {
                groups: ["*".to_string()].into_iter().collect(),
                ..Default::default()
            },
            conditions: ConditionSpec::default(),
            priority: 100,
            enforcing: true,
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

        let result = evaluate_resource(&policies, "uri:epson_lx350", "uri:read", &user, &env, None, None);
        assert!(!result.allowed);
        assert_eq!(result.matched_policy, Some("block_printers".into()));
    }
}
