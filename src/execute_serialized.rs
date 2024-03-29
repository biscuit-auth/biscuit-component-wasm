use crate::{
    get_parse_errors, get_position, log, Editor, Fact, Marker, ParseError, SourcePosition,
};
use biscuit_auth::{
    builder, error, parser::parse_block_source, parser::parse_source, parser::SourceResult,
    AuthorizerLimits, Biscuit, PublicKey,
};
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitQuery {
    pub token: String,
    pub token_blocks: Option<Vec<String>>,
    pub root_public_key: String,
    pub authorizer_code: String,
    pub query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitResult {
    pub token_blocks: Vec<Editor>,
    pub authorizer_editor: Editor,
    pub authorizer_result: Result<usize, error::Token>,
    pub authorizer_world: Vec<Fact>,
    pub query_result: Vec<Fact>,
}

impl Default for BiscuitResult {
    fn default() -> Self {
        BiscuitResult {
            token_blocks: Vec::new(),
            authorizer_editor: Editor::default(),
            authorizer_result: Ok(0),
            authorizer_world: Vec::new(),
            query_result: Vec::new(),
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteErrors {
    pub root_key: Option<String>,
    pub token: Option<String>,
    pub authorizer: Vec<ParseError>,
}

#[derive(Clone, Debug, Default)]
struct Block {
    pub checks: Vec<(SourcePosition, bool)>,
}

#[wasm_bindgen]
pub fn execute_serialized(query: &JsValue) -> JsValue {
    let query = serde_wasm_bindgen::from_value(query.clone()).unwrap();

    let result = execute_inner(query);

    serde_wasm_bindgen::to_value(&result).unwrap()
}

pub fn execute_inner(query: BiscuitQuery) -> Result<BiscuitResult, ExecuteErrors> {
    let public_key =
        PublicKey::from_bytes_hex(&query.root_public_key).map_err(|_| error::Token::InternalError);

    let deser: Result<Biscuit, error::Token> = public_key
        .clone()
        .and_then(|pk| Biscuit::from_base64(&query.token, pk));

    let authorizer = parse_authorizer(&query.authorizer_code);

    if let (Ok(token), Ok(authorizer_source)) = (&deser, &authorizer) {
        Ok(perform_authorization(
            token,
            &query.token_blocks,
            &query.authorizer_code,
            authorizer_source,
            &query.query,
        ))
    } else {
        Err(ExecuteErrors {
            root_key: public_key.err().map(|e| e.to_string()),
            token: deser.err().map(|e| e.to_string()),
            authorizer: authorizer.err().unwrap_or(Vec::new()),
        })
    }
}

fn perform_authorization(
    token: &Biscuit,
    token_blocks: &Option<Vec<String>>,
    authorizer_code: &str,
    authorizer_source: &SourceResult,
    query: &Option<String>,
) -> BiscuitResult {
    let mut biscuit_result = BiscuitResult::default();

    let mut blocks_source = Vec::new();

    if let Some(bs) = token_blocks {
        blocks_source = bs.clone();
    } else {
        for i in 0..token.block_count() {
            blocks_source.push(token.print_block_source(i).unwrap().to_string());
        }
    }

    let mut authority = gather_checks(&blocks_source[0]);
    biscuit_result.token_blocks.push(Editor::default());

    let mut blocks = Vec::new();

    for bs in blocks_source.iter().skip(1) {
        blocks.push(gather_checks(bs));
        biscuit_result.token_blocks.push(Editor::default());
    }

    let mut authorizer = token.authorizer().unwrap();
    let mut authorizer_checks = Vec::new();
    let mut authorizer_policies = Vec::new();

    for (_, fact) in authorizer_source.facts.iter() {
        authorizer.add_fact(fact.clone()).unwrap();
    }

    for (_, rule) in authorizer_source.rules.iter() {
        authorizer.add_rule(rule.clone()).unwrap();
    }

    for (i, check) in authorizer_source.checks.iter() {
        authorizer.add_check(check.clone()).unwrap();
        let position = get_position(authorizer_code, i);
        // checks are marked as success until they fail
        authorizer_checks.push((position, true));
    }

    for (i, policy) in authorizer_source.policies.iter() {
        authorizer.add_policy(policy.clone()).unwrap();
        let position = get_position(authorizer_code, i);
        authorizer_policies.push(position);
    }

    let limits = AuthorizerLimits {
        max_time: std::time::Duration::from_secs(2),
        ..Default::default()
    };
    let authorizer_result = authorizer.authorize_with_limits(limits);

    // todo extract scope information as well
    let (mut facts, _, _, _) = authorizer.dump();
    biscuit_result.authorizer_world = facts
        .drain(..)
        .map(|mut fact| Fact {
            name: fact.predicate.name,
            terms: fact
                .predicate
                .terms
                .drain(..)
                .map(|term| term.to_string())
                .collect(),
        })
        .collect();
    match &authorizer_result {
        Err(error::Token::FailedLogic(error::Logic::Unauthorized { policy, checks })) => {
            for e in checks.iter() {
                match e {
                    error::FailedCheck::Authorizer(error::FailedAuthorizerCheck {
                        check_id,
                        ..
                    }) => {
                        authorizer_checks[*check_id as usize].1 = false;
                    }
                    error::FailedCheck::Block(error::FailedBlockCheck {
                        block_id,
                        check_id,
                        ..
                    }) => {
                        let block = if *block_id == 0 {
                            &mut authority
                        } else {
                            &mut blocks[*block_id as usize - 1]
                        };
                        block.checks[*check_id as usize].1 = false;
                    }
                }
            }
            if let error::MatchedPolicy::Deny(index) = policy {
                let position = &authorizer_policies[*index];
                biscuit_result.authorizer_editor.markers.push(Marker {
                    ok: false,
                    position: position.clone(),
                });
            }
        }
        Err(error::Token::FailedLogic(error::Logic::NoMatchingPolicy { checks })) => {
            for e in checks.iter() {
                match e {
                    error::FailedCheck::Authorizer(error::FailedAuthorizerCheck {
                        check_id,
                        ..
                    }) => {
                        authorizer_checks[*check_id as usize].1 = false;
                    }
                    error::FailedCheck::Block(error::FailedBlockCheck {
                        block_id,
                        check_id,
                        ..
                    }) => {
                        let block = if *block_id == 0 {
                            &mut authority
                        } else {
                            &mut blocks[*block_id as usize - 1]
                        };
                        block.checks[*check_id as usize].1 = false;
                    }
                }
            }
        }
        Ok(index) => {
            let position = &authorizer_policies[*index];
            biscuit_result.authorizer_editor.markers.push(Marker {
                ok: true,
                position: position.clone(),
            });
        }
        // other errors are ignored. they should not happen at this point
        Err(_) => {}
    }

    for (position, result) in authority.checks.iter() {
        if let Some(ed) = biscuit_result.token_blocks.get_mut(0) {
            ed.markers.push(Marker {
                ok: *result,
                position: position.clone(),
            });
        }
    }

    for (id, block) in blocks.iter().enumerate() {
        for (position, result) in block.checks.iter() {
            if let Some(ed) = biscuit_result.token_blocks.get_mut(id + 1) {
                ed.markers.push(Marker {
                    ok: *result,
                    position: position.clone(),
                });
            }
        }
    }

    for (position, result) in authorizer_checks.iter() {
        biscuit_result.authorizer_editor.markers.push(Marker {
            ok: *result,
            position: position.clone(),
        });
    }

    biscuit_result.authorizer_result = authorizer_result;

    if let Some(query) = query.as_ref() {
        log(&format!("got query content: {}", query));

        // todo check what the origin should be
        if !query.is_empty() {
            let query_result: Result<Vec<builder::Fact>, biscuit_auth::error::Token> =
                authorizer.query(query.as_str());
            match query_result {
                Err(e) => {
                    log(&format!("query error: {:?}", e));
                }
                Ok(mut facts) => {
                    biscuit_result.query_result = facts
                        .drain(..)
                        .map(|mut fact| Fact {
                            name: fact.predicate.name,
                            terms: fact
                                .predicate
                                .terms
                                .drain(..)
                                .map(|term| term.to_string())
                                .collect(),
                        })
                        .collect();
                }
            }
        }
    }
    biscuit_result
}

fn parse_authorizer(authorizer_code: &str) -> Result<SourceResult, Vec<ParseError>> {
    parse_source(authorizer_code).map_err(|errors| get_parse_errors(authorizer_code, &errors))
}

// extract checks with their positions
fn gather_checks(block_source: &str) -> Block {
    let mut block = Block::default();
    if let Ok(result) = parse_block_source(block_source) {
        for (i, _) in result.checks.iter() {
            let position = get_position(block_source, i);
            block.checks.push((position, true));
        }
    }

    block
}
