#[derive(Debug, Clone)]
pub struct FlowPredicateSet {
    pub source_names: Vec<&'static str>,
    pub sink_names: Vec<&'static str>,
    pub guard_names: Vec<&'static str>,
    pub sensitive_function_keywords: Vec<&'static str>,
}

pub fn generic_security() -> FlowPredicateSet {
    FlowPredicateSet::generic_security()
}

pub fn web_api() -> FlowPredicateSet {
    FlowPredicateSet::web_api()
}

impl FlowPredicateSet {
    pub fn generic_security() -> Self {
        Self {
            source_names: vec![],
            sink_names: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ],
            guard_names: vec![
                "validate",
                "verify",
                "authorize",
                "authenticate",
                "check_permission",
                "guard",
                "sanitize",
            ],
            sensitive_function_keywords: vec![
                "auth",
                "login",
                "permission",
                "token",
                "delete",
                "update",
                "charge",
                "payment",
                "admin",
            ],
        }
    }

    pub fn web_api() -> Self {
        Self {
            source_names: vec!["request", "req", "params", "body", "query"],
            sink_names: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ],
            guard_names: vec![
                "validate",
                "verify",
                "authorize",
                "authenticate",
                "check_permission",
                "guard",
                "sanitize",
                "escape",
            ],
            sensitive_function_keywords: vec![
                "auth",
                "login",
                "permission",
                "token",
                "delete",
                "update",
                "charge",
                "payment",
                "admin",
                "user",
                "profile",
            ],
        }
    }

    pub fn is_sensitive_function(&self, fn_name: &str) -> bool {
        let lower = fn_name.to_lowercase();
        self.sensitive_function_keywords
            .iter()
            .any(|needle| lower.contains(needle))
    }

    pub fn is_sink(&self, call_name: &str) -> bool {
        let lower = call_name.to_lowercase();
        self.sink_names.iter().any(|s| lower.contains(s))
    }

    pub fn is_guard(&self, call_name: &str) -> bool {
        let lower = call_name.to_lowercase();
        self.guard_names.iter().any(|g| lower.contains(g))
    }
}

pub fn generic_security_policy() -> FlowPredicateSet {
    FlowPredicateSet::generic_security()
}

pub fn web_api_policy() -> FlowPredicateSet {
    FlowPredicateSet::web_api()
}

#[cfg(test)]
mod tests {
    use super::FlowPredicateSet;

    #[test]
    fn generic_set_marks_auth_function_sensitive() {
        let p = FlowPredicateSet::generic_security();
        assert!(p.is_sensitive_function("authorizePayment"));
    }

    #[test]
    fn generic_set_ignores_unrelated_function_name() {
        let p = FlowPredicateSet::generic_security();
        assert!(!p.is_sensitive_function("renderHeader"));
    }
}
