use crate::{get_parse_errors, ParseErrors};
use biscuit_auth::{
    builder::BlockBuilder,
    error,
    parser::{parse_block_source, SourceResult},
    Biscuit, KeyPair, PrivateKey,
};
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct GenerateToken {
    pub token_blocks: Vec<String>,
    pub private_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenerateTokenError {
    Parse(ParseErrors),
    Biscuit(error::Token),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct KeyPairJs {
    pub private_key: String,
    pub public_key: String,
}

#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let kp = KeyPair::new();

    JsValue::from_serde(&KeyPairJs {
        private_key: hex::encode(kp.private().to_bytes()),
        public_key: hex::encode(kp.public().to_bytes()),
    })
    .unwrap()
}

#[wasm_bindgen]
pub fn generate_token(query: &JsValue) -> Result<String, JsValue> {
    let query: GenerateToken = query.into_serde().unwrap();

    generate_token_inner(query).map_err(|e| JsValue::from_serde(&e).unwrap())
}

fn generate_token_inner(query: GenerateToken) -> Result<String, GenerateTokenError> {
    let mut parse_errors = ParseErrors::new();
    let mut blocks = Vec::new();
    let mut has_errors = false;

    if query.token_blocks.is_empty() {
        return Err(GenerateTokenError::Biscuit(error::Token::InternalError));
    }

    for code in query.token_blocks.iter() {
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
        Err(GenerateTokenError::Parse(parse_errors))
    } else {
        generate_token_from_blocks(&query, blocks).map_err(GenerateTokenError::Biscuit)
    }
}

fn generate_token_from_blocks(
    query: &GenerateToken,
    blocks: Vec<SourceResult>,
) -> Result<String, error::Token> {
    let data = hex::decode(&query.private_key).map_err(|_| error::Token::InternalError)?;

    let keypair = KeyPair::from(PrivateKey::from_bytes(&data)?);
    let mut builder = Biscuit::builder();

    let authority_parsed = &blocks[0];

    for (_, fact) in authority_parsed.facts.iter() {
        builder.add_fact(fact.clone()).unwrap();
    }

    for (_, rule) in authority_parsed.rules.iter() {
        builder.add_rule(rule.clone()).unwrap();
    }

    for (_, check) in authority_parsed.checks.iter() {
        builder.add_check(check.clone()).unwrap();
    }

    let mut token = builder.build(&keypair)?;

    for block_parsed in (&blocks[1..]).iter() {
        let temp_keypair = KeyPair::new();
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

        token = token.append_with_keypair(&temp_keypair, builder)?;
    }
    Ok(token.to_base64()?)
}
