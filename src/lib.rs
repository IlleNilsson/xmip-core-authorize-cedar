#![forbid(unsafe_code)]

//! The cedar authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: a Cedar policy set, evaluated with the
//! Cedar engine (ADR-0050 section 5). The language, its parser and its
//! evaluator are the `cedar-policy` crate's; what is this crate's is the
//! mapping ([`request`]): the accountable identity is the principal, a child
//! of its Party; the attempt's action is the action; the artifact is the
//! resource; and the facts the gates recorded are the context.
//!
//! A policy set that does not parse is refused at load with Cedar's own
//! message. At the gate, Cedar's answer is read for what it was made of: an
//! allow is a permit; a deny that an explicit `forbid` produced is a denial
//! naming this policy and the forbid; a deny that nothing produced — no
//! policy matched — is no opinion, because Cedar's default deny is Cedar's
//! way of saying nothing and the capability already closes a gate nobody
//! spoke for. A deny where nothing matched and a policy failed to evaluate
//! is a denial saying so: a policy that could not be read is never silence.
//!
//! No schema is loaded, so a policy reads the context as it finds it and
//! guards what may be absent with `has`. Name a policy with Cedar's
//! `@id("...")` annotation and a denial carries that name.

pub mod request;

use authorize::{Attempt, AuthorizeError, Authorizer, Decision};
use cedar_policy::{PolicyId, PolicySet, Response};
use context::IdentityFacts;
use std::str::FromStr;
use xcore::Layer;

pub use request::request;

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "cedar";

/// A Cedar policy set, loaded.
#[derive(Debug)]
pub struct Cedar {
    policies: PolicySet,
    engine: cedar_policy::Authorizer,
}

impl Cedar {
    /// Load a policy set from Cedar's own text.
    ///
    /// # Errors
    ///
    /// Refuses text the Cedar parser refuses, with Cedar's own message.
    pub fn load(text: &str) -> Result<Self, AuthorizeError> {
        let policies = PolicySet::from_str(text).map_err(|refused| {
            AuthorizeError::new(format!("the Cedar policy set is refused: {refused}"))
        })?;

        Ok(Self {
            policies,
            engine: cedar_policy::Authorizer::new(),
        })
    }

    /// The name an operator gave a policy with `@id("...")`, or Cedar's own.
    fn named(&self, id: &PolicyId) -> String {
        self.policies
            .annotation(id, "id")
            .map_or_else(|| id.to_string(), ToString::to_string)
    }

    fn read(&self, response: &Response, attempt: &Attempt) -> Option<Decision> {
        if response.decision() == cedar_policy::Decision::Allow {
            return Some(Decision::Allowed);
        }

        let mut forbids: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|id| format!("'{}'", self.named(id)))
            .collect();
        forbids.sort();

        if !forbids.is_empty() {
            return Some(Decision::denied(
                NAME,
                format!(
                    "{} forbids {} on '{}'",
                    forbids.join(" and "),
                    attempt.action,
                    attempt.artifact
                ),
            ));
        }

        let failed: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();

        (!failed.is_empty()).then(|| {
            Decision::denied(
                NAME,
                format!(
                    "nothing permits and a policy failed to evaluate: {}",
                    failed.join("; ")
                ),
            )
        })
    }
}

impl Authorizer for Cedar {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        match request(identity, attempt) {
            Ok((request, entities)) => {
                let response = self
                    .engine
                    .is_authorized(&request, &self.policies, &entities);
                self.read(&response, attempt)
            }
            // What cannot be put to the engine is never a permit and never
            // silence either.
            Err(refused) => Some(Decision::denied(NAME, refused.message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    const POLICIES: &str = r#"
        @id("party-seven-receives")
        permit (
            principal in Xmip::Party::"00000000-0000-0000-0000-000000000007",
            action == Xmip::Action::"receive",
            resource
        ) when { context.mechanism == "mutual-tls" };

        @id("billing-sends-billing")
        permit (
            principal,
            action == Xmip::Action::"send",
            resource == Xmip::Artifact::"Billing"
        ) when { context.evidence has department && context.evidence.department == "billing" };

        @id("contractors-never-send")
        forbid (principal, action == Xmip::Action::"send", resource)
        when { context.evidence has employment && context.evidence.employment == "contractor" };

        @id("reads-what-is-not-there")
        permit (principal, action == Xmip::Action::"process", resource)
        when { context.evidence.clearance == "secret" };
    "#;

    fn party(evidence: &[(&str, &str)]) -> IdentityFacts {
        let identity = evidence.iter().fold(
            AuthenticatedIdentity::new(
                mechanism::mutual_tls(),
                "CN=party-x.example",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7)),
            |identity, (name, value)| identity.with_evidence(*name, *value),
        );

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn cedar() -> Cedar {
        Cedar::load(POLICIES).expect("the policy set parses")
    }

    #[test]
    fn what_cedar_allows_is_a_permit() {
        let policy = cedar();

        assert_eq!(
            policy.decide(&party(&[]), &Attempt::new(Action::Receive, "party-x")),
            Some(Decision::Allowed)
        );
        assert_eq!(
            policy.decide(
                &party(&[("department", "billing")]),
                &Attempt::new(Action::Send, "Billing")
            ),
            Some(Decision::Allowed)
        );
        assert_eq!(policy.name(), "cedar");
        assert_eq!(policy.layer(), Layer::Transport);
    }

    #[test]
    fn an_explicit_forbid_is_a_denial_naming_this_policy_and_the_forbid() {
        // Billing may send Billing; a contractor may send nothing, and in
        // Cedar a forbid beats every permit.
        let decision = cedar()
            .decide(
                &party(&[("department", "billing"), ("employment", "contractor")]),
                &Attempt::new(Action::Send, "Billing"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by cedar: 'contractors-never-send' forbids send on 'Billing'"
        );
    }

    #[test]
    fn no_matching_policy_is_no_opinion_and_not_cedars_default_deny() {
        assert_eq!(
            cedar().decide(&party(&[]), &Attempt::new(Action::Send, "Shipping")),
            None
        );
        assert_eq!(
            Cedar::load("")
                .expect("an empty set parses")
                .decide(&party(&[]), &Attempt::new(Action::Receive, "party-x")),
            None
        );
    }

    #[test]
    fn a_policy_set_that_does_not_parse_is_refused_at_load_with_cedars_message() {
        let refused = Cedar::load("permit (principal, action, resource) when { context. };")
            .expect_err("not Cedar");
        let misspelled =
            Cedar::load("allow (principal, action, resource);").expect_err("not Cedar");

        assert!(
            refused
                .message
                .starts_with("the Cedar policy set is refused: "),
            "{refused}"
        );
        assert!(
            refused.message.len() > "the Cedar policy set is refused: ".len(),
            "Cedar's own message follows: {refused}"
        );
        assert!(misspelled.message.contains("allow"), "{misspelled}");
    }

    #[test]
    fn a_policy_that_fails_to_evaluate_where_nothing_permits_is_a_denial_saying_so() {
        let decision = cedar()
            .decide(&party(&[]), &Attempt::new(Action::Process, "Approval"))
            .expect("an opinion");

        let Decision::Denied { by, reason } = decision else {
            panic!("a policy that could not be read is never a permit");
        };
        assert_eq!(by, "cedar");
        assert!(
            reason.starts_with("nothing permits and a policy failed to evaluate: "),
            "{reason}"
        );
        assert!(reason.contains("clearance"), "{reason}");
    }
}
