use biscuit_auth::UnverifiedBiscuit;
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ParseTokenQuery {
    pub data: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ParseResult {
    pub token_blocks: Vec<String>,
    //pub key: String,
    pub revocation_ids: Vec<String>,
    pub error: Option<String>,
}

#[wasm_bindgen]
pub fn parse_token(query: &JsValue) -> JsValue {
    let query = query.into_serde().unwrap();

    let result = parse_token_inner(query);

    JsValue::from_serde(&result).unwrap()
}

fn parse_token_inner(query: ParseTokenQuery) -> ParseResult {
    let token = match UnverifiedBiscuit::from_base64(&query.data) {
        Err(e) => {
            let mut res = ParseResult::default();
            res.error = Some(e.to_string());
            return res;
        }
        Ok(t) => t,
    };

    let mut token_blocks = Vec::new();
    for i in 0..token.block_count() {
        token_blocks.push(token.print_block_source(i).unwrap());
    }

    let revocation_ids = token
        .revocation_identifiers()
        .into_iter()
        .map(|v| hex::encode(v))
        .collect();
    ParseResult {
        token_blocks,
        //key: "".to_string(),
        revocation_ids,
        error: None,
    }
}
