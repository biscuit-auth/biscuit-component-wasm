use crate::execute_serialized;
use crate::generate_token;
use crate::{Editor, Fact, ParseErrors};
use biscuit_auth::{error, KeyPair};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitQuery {
    pub token_blocks: Vec<String>,
    pub external_private_keys: Vec<Option<String>>,
    pub authorizer_code: Option<String>,
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitResult {
    pub token_blocks: Vec<Editor>,
    pub token_content: String,
    pub authorizer_editor: Option<Editor>,
    pub authorizer_result: Result<usize, error::Token>,
    pub authorizer_world: Vec<Fact>,
    pub query_result: Vec<Fact>,
}

impl Default for BiscuitResult {
    fn default() -> Self {
        BiscuitResult {
            token_blocks: Vec::new(),
            token_content: String::new(),
            authorizer_editor: None,
            authorizer_result: Ok(0),
            authorizer_world: Vec::new(),
            query_result: Vec::new(),
        }
    }
}

#[wasm_bindgen]
pub fn execute(query: &JsValue) -> JsValue {
    let query: BiscuitQuery = query.into_serde().unwrap();

    let result = execute_inner(query);

    JsValue::from_serde(&result).unwrap()
}

fn execute_inner(query: BiscuitQuery) -> Result<BiscuitResult, ParseErrors> {
    let mut rng: StdRng = SeedableRng::seed_from_u64(0);
    let root_key = KeyPair::new_with_rng(&mut rng);
    let creation_query = generate_token::GenerateToken {
        token_blocks: query.token_blocks.clone(),
        external_private_keys: query.external_private_keys,
        private_key: root_key.private().to_bytes_hex(),
    };

    let serialized = generate_token::generate_token_inner(creation_query).map_err(|e| match e {
        generate_token::GenerateTokenError::Parse(e) => e,
        _ => panic!("Unhandled error happened"),
    })?;

    let execute_query = execute_serialized::BiscuitQuery {
        token: serialized.clone(),
        token_blocks: Some(query.token_blocks.clone()),
        root_public_key: root_key.public().to_bytes_hex(),
        authorizer_code: query.authorizer_code.unwrap_or(String::new()),
        query: query.query,
    };

    let execute_results =
        execute_serialized::execute_inner(execute_query).map_err(|e| ParseErrors {
            blocks: Vec::new(),
            authorizer: e.authorizer,
        })?;
    Ok(BiscuitResult {
        token_blocks: execute_results.token_blocks,
        token_content: serialized,
        authorizer_editor: Some(execute_results.authorizer_editor),
        authorizer_result: execute_results.authorizer_result,
        authorizer_world: execute_results.authorizer_world,
        query_result: execute_results.query_result,
    })
}
