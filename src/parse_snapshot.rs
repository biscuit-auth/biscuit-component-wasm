use crate::Fact;
use biscuit_auth::{datalog::RunLimits, error, Authorizer};
use serde::{Deserialize, Serialize};
use std::{default::Default, time::Duration};
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct InspectSnapshotQuery {
    pub data: String,
    pub extra_authorizer: Option<String>,
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InspectionResult {
    pub snapshot: Result<ParseResult, error::Token>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParseResult {
    pub code: String,
    pub iterations: u64,
    pub elapsed_micros: u128,
    pub authorization_result: Result<usize, error::Token>,
    pub query_result: Option<Result<Vec<Fact>, error::Token>>,
}

#[wasm_bindgen]
pub fn inspect_snapshot(query: &JsValue) -> JsValue {
    let query = serde_wasm_bindgen::from_value(query.clone()).unwrap();

    let result = InspectionResult {
        snapshot: inspect_snapshot_inner(query),
    };

    serde_wasm_bindgen::to_value(&result).unwrap()
}

fn inspect_snapshot_inner(query: InspectSnapshotQuery) -> Result<ParseResult, error::Token> {
    let mut authorizer = Authorizer::from_base64_snapshot(&query.data)?;
    let code = {
        let mut new_authorizer = authorizer.clone();
        // authorizer.to_string() does not show authorizer rules or generated facts. Running authorize() on an authorizer populates them. Here we don't care about the authorization results, we just want to see facts and rules. See https://github.com/biscuit-auth/biscuit-rust/pull/195
        let _ = new_authorizer.authorize();
        new_authorizer.to_string()
    };
    let iterations = authorizer.iterations();
    let elapsed_micros = authorizer.execution_time().as_micros();

    let authorization_result = {
        if let Some(extra_code) = query.extra_authorizer {
            authorizer.add_code(extra_code).and_then(|()| {
                authorizer.authorize_with_limits(RunLimits {
                    max_time: Duration::from_millis(100),
                    ..Default::default()
                })
            })
        } else {
            authorizer.authorize_with_limits(RunLimits {
                max_time: Duration::from_millis(100),
                ..Default::default()
            })
        }
    };

    let query_result = query.query.map(|q| authorizer.query(q.as_str()));

    Ok(ParseResult {
        code,
        iterations,
        elapsed_micros,
        authorization_result,
        query_result,
    })
}
