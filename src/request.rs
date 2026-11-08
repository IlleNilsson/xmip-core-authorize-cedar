//! A request: one identity attempting one thing, in Cedar's terms.

use authorize::{Attempt, AuthorizeError};
use cedar_policy::{Context, Entities, EntityId, EntityTypeName, EntityUid, Request};
use context::{AuthenticatedIdentity, IdentityFacts};
use serde_json::{Map, Value, json};
use std::str::FromStr;
use xcore::Assurance;

/// The entity type of a principal: `Xmip::Identity::"CN=party-x.example"`.
pub const IDENTITY: &str = "Xmip::Identity";

/// The entity type a principal is `in` where its identity resolved to a
/// Party: `Xmip::Party::"00000000-0000-0000-0000-000000000007"`.
pub const PARTY: &str = "Xmip::Party";

/// The entity type of an action: `Xmip::Action::"receive"`.
pub const ACTION: &str = "Xmip::Action";

/// The entity type of a resource: `Xmip::Artifact::"Billing"`.
pub const ARTIFACT: &str = "Xmip::Artifact";

/// Map an identity attempting something to a Cedar request and the entities
/// it is evaluated over.
///
/// The principal is the accountable identity by the value it presented, a
/// child of its Party where it resolved to one, so `principal in
/// Xmip::Party::"…"` reads as it should. The action is the attempt's, by its
/// word; the resource is the artifact, by its name. Everything else the
/// record knows is the context:
///
/// ```text
/// context.mechanism   context.class      context.assurance
/// context.value       context.verified   context.party      (where resolved)
/// context.evidence    a record, one attribute per evidence name
/// context.message     the same again for the message identity (where one)
/// context.contract    context.path       (where the attempt carries them)
/// context.at          unix seconds       (where the attempt says when)
/// ```
///
/// # Errors
///
/// Refuses where the engine refuses the entities or the context it is
/// given, with the engine's own message.
pub fn request(
    identity: &IdentityFacts,
    attempt: &Attempt,
) -> Result<(Request, Entities), AuthorizeError> {
    let accountable = identity.accountable();
    let principal = uid(IDENTITY, &accountable.value);
    let party = accountable
        .party_id
        .map(|party| uid(PARTY, &party.to_string()));

    let mut described = vec![json!({
        "uid": reference(&principal),
        "attrs": {},
        "parents": party.iter().map(reference).collect::<Vec<Value>>(),
    })];
    described.extend(party.iter().map(|party| {
        json!({
            "uid": reference(party),
            "attrs": {},
            "parents": [],
        })
    }));

    let entities = Entities::from_json_value(Value::Array(described), None)
        .map_err(|refused| AuthorizeError::new(format!("cedar refuses the entities: {refused}")))?;
    let context = Context::from_json_value(facts(identity, attempt), None)
        .map_err(|refused| AuthorizeError::new(format!("cedar refuses the context: {refused}")))?;
    let request = Request::new(
        principal,
        uid(ACTION, &attempt.action.to_string()),
        uid(ARTIFACT, &attempt.artifact),
        context,
        None,
    )
    .map_err(|refused| AuthorizeError::new(format!("cedar refuses the request: {refused}")))?;

    Ok((request, entities))
}

fn uid(kind: &str, id: &str) -> EntityUid {
    let kind = EntityTypeName::from_str(kind).expect("the entity types are this file's constants");
    EntityUid::from_type_name_and_id(kind, EntityId::new(id))
}

fn reference(uid: &EntityUid) -> Value {
    let id: &str = uid.id().as_ref();
    json!({ "type": uid.type_name().to_string(), "id": id })
}

/// The facts and the rest of the attempt, as the context's JSON.
fn facts(identity: &IdentityFacts, attempt: &Attempt) -> Value {
    let mut context = held(identity.accountable());

    if let Some(message) = &identity.message {
        context.insert("message".into(), Value::Object(held(message)));
    }
    if let Some(contract) = &attempt.contract {
        context.insert("contract".into(), contract.clone().into());
    }
    if let Some(path) = &attempt.path {
        context.insert("path".into(), path.clone().into());
    }
    // Cedar's Long is 64 bits and the estate's clock is nanoseconds in 128;
    // seconds fit, and zero means the attempt did not say when.
    if let Some(seconds) = i64::try_from(attempt.at / 1_000_000_000)
        .ok()
        .filter(|seconds| *seconds != 0)
    {
        context.insert("at".into(), seconds.into());
    }

    Value::Object(context)
}

fn held(identity: &AuthenticatedIdentity) -> Map<String, Value> {
    let mut evidence = Map::new();
    for (name, value) in &identity.evidence {
        // The first entry under a name is the one a policy reads.
        evidence
            .entry(name.clone())
            .or_insert_with(|| value.clone().into());
    }

    let mut record = Map::new();
    record.insert("mechanism".into(), identity.mechanism.name().into());
    record.insert("class".into(), identity.class().to_string().into());
    record.insert(
        "assurance".into(),
        match identity.mechanism.assurance() {
            Assurance::Identifies => "identifies",
            Assurance::Authenticates => "authenticates",
        }
        .into(),
    );
    record.insert("value".into(), identity.value.clone().into());
    record.insert("verified".into(), identity.verified.word().into());
    if let Some(party) = identity.party_id {
        record.insert("party".into(), party.to_string().into());
    }
    record.insert("evidence".into(), Value::Object(evidence));

    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, Verified};
    use xcore::{Established, PartyId, mechanism};

    fn party() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::mutual_tls(),
                "CN=party-x.example",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("issuer", "CN=Example CA")
            .with_evidence("issuer", "CN=Another CA"),
            None,
        )
    }

    #[test]
    fn the_identity_is_the_principal_the_action_the_action_the_artifact_the_resource() {
        let attempt = Attempt::now(Action::Receive, "party-x");
        let (request, entities) = request(&party(), &attempt).expect("a request");

        assert_eq!(
            request.principal().expect("a principal").to_string(),
            r#"Xmip::Identity::"CN=party-x.example""#
        );
        assert_eq!(
            request.action().expect("an action").to_string(),
            r#"Xmip::Action::"receive""#
        );
        assert_eq!(
            request.resource().expect("a resource").to_string(),
            r#"Xmip::Artifact::"party-x""#
        );
        assert!(entities.is_ancestor_of(
            &uid(PARTY, "00000000-0000-0000-0000-000000000007"),
            &uid(IDENTITY, "CN=party-x.example")
        ));
    }

    #[test]
    fn the_facts_are_the_context_and_the_clock_is_in_seconds() {
        let attempt = Attempt::new(Action::Send, "Billing", 1_700_000_000 * 1_000_000_000)
            .on_contract("X12-850");
        let context = facts(&party(), &attempt);

        assert_eq!(context["mechanism"], "mutual-tls");
        assert_eq!(context["class"], "highAssurance");
        assert_eq!(context["assurance"], "authenticates");
        assert_eq!(context["verified"], "proven");
        assert_eq!(context["party"], "00000000-0000-0000-0000-000000000007");
        assert_eq!(context["evidence"]["issuer"], "CN=Example CA");
        assert_eq!(context["contract"], "X12-850");
        assert_eq!(context["at"], 1_700_000_000_i64);
        assert!(context.get("path").is_none());
        assert!(context.get("message").is_none());
    }
}
