use biscuit_auth::{
    builder::BlockBuilder,
    error,
    parser::{parse_block_source, SourceResult},
    UnverifiedBiscuit,
};
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

use crate::{get_parse_errors, ParseErrors};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct AttenuateTokenQuery {
    pub token: String,
    pub blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AttenuationError {
    BlockParseErrors(ParseErrors),
    Biscuit(error::Token),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttenuateTokenResult {
    pub attenuated: Result<String, AttenuationError>,
}

#[wasm_bindgen]
pub fn attenuate_token(query: &JsValue) -> JsValue {
    let query = query.into_serde().unwrap();

    let result = attenuate_token_inner(query);

    JsValue::from_serde(&result).unwrap()
}

fn attenuate_token_inner(query: AttenuateTokenQuery) -> Result<String, AttenuationError> {
    let token =
        UnverifiedBiscuit::from_base64(&query.token).map_err(|e| AttenuationError::Biscuit(e))?;

    let mut parse_errors = ParseErrors::new();
    let mut has_errors = false;
    let mut blocks = vec![];

    for code in query.blocks.iter() {
        match parse_block_source(&code) {
            Err(errors) => {
                parse_errors.blocks.push(get_parse_errors(&code, &errors));
                has_errors = true;
            }
            Ok(block) => {
                blocks.push(block);
                parse_errors.blocks.push(Vec::new());
            }
        }
    }

    if has_errors {
        Err(AttenuationError::BlockParseErrors(parse_errors))
    } else {
        attenuate_token_from_blocks(&token, blocks).map_err(AttenuationError::Biscuit)
    }
}

fn attenuate_token_from_blocks(
    token: &UnverifiedBiscuit,
    blocks: Vec<SourceResult>,
) -> Result<String, error::Token> {
    let mut output = token.clone();
    for block_parsed in &blocks {
        let mut builder = BlockBuilder::new();

        for (_, fact) in block_parsed.facts.iter() {
            builder.add_fact(fact.clone()).unwrap();
        }

        for (_, rule) in block_parsed.rules.iter() {
            builder.add_rule(rule.clone()).unwrap();
        }

        for (_, check) in block_parsed.checks.iter() {
            builder.add_check(check.clone()).unwrap();
        }

        output = output.append(builder)?;
    }
    Ok(output.to_base64()?)
}
