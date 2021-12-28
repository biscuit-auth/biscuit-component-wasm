use crate::{
    get_parse_errors, get_position, log, Editor, Fact, Marker, ParseErrors, SourcePosition,
};
use biscuit_auth::{
    builder, error,
    parser::{parse_block_source, parse_source},
    Authorizer, AuthorizerLimits, Biscuit, KeyPair,
};
use log::*;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct BiscuitQuery {
    pub token_blocks: Vec<String>,
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

#[derive(Clone, Debug)]
struct Block {
    pub checks: Vec<(SourcePosition, bool)>,
}

impl Default for Block {
    fn default() -> Self {
        Block { checks: Vec::new() }
    }
}

#[wasm_bindgen]
pub fn execute(query: &JsValue) -> JsValue {
    let query: BiscuitQuery = query.into_serde().unwrap();

    let result = execute_inner(query);

    JsValue::from_serde(&result).unwrap()
}

fn execute_inner(query: BiscuitQuery) -> Result<BiscuitResult, ParseErrors> {
    let mut biscuit_result = BiscuitResult::default();

    info!("will generate token");

    let mut rng: StdRng = SeedableRng::seed_from_u64(0);
    let root = KeyPair::new_with_rng(&mut rng);

    let mut builder = Biscuit::builder(&root);

    let mut authority = Block::default();
    let mut blocks = Vec::new();

    let mut token_opt = None;
    let mut has_errors = false;
    let mut parse_errors = ParseErrors::new();

    if !query.token_blocks.is_empty() {
        match parse_block_source(&query.token_blocks[0]) {
            Err(errors) => {
                error!("error: {:?}", errors);
                parse_errors
                    .blocks
                    .push(get_parse_errors(&query.token_blocks[0], &errors));
                has_errors = true;
            }
            Ok(authority_parsed) => {
                parse_errors.blocks.push(Vec::new());

                for (_, fact) in authority_parsed.facts.iter() {
                    builder.add_authority_fact(fact.clone()).unwrap();
                }

                for (_, rule) in authority_parsed.rules.iter() {
                    builder.add_authority_rule(rule.clone()).unwrap();
                }

                for (i, check) in authority_parsed.checks.iter() {
                    builder.add_authority_check(check.clone()).unwrap();
                    let position = get_position(&query.token_blocks[0], i);
                    authority.checks.push((position, true));
                }
            }
        }

        biscuit_result.token_blocks.push(Editor::default());

        let mut token = builder.build_with_rng(&mut rng).unwrap();

        for code in (&query.token_blocks[1..]).iter() {
            let mut block = Block::default();

            let temp_keypair = KeyPair::new_with_rng(&mut rng);
            let mut builder = token.create_block();

            match parse_block_source(&code) {
                Err(errors) => {
                    error!("error: {:?}", errors);
                    parse_errors.blocks.push(get_parse_errors(&code, &errors));
                    has_errors = true;
                }
                Ok(block_parsed) => {
                    parse_errors.blocks.push(Vec::new());

                    for (_, fact) in block_parsed.facts.iter() {
                        builder.add_fact(fact.clone()).unwrap();
                    }

                    for (_, rule) in block_parsed.rules.iter() {
                        builder.add_rule(rule.clone()).unwrap();
                    }

                    for (i, check) in block_parsed.checks.iter() {
                        builder.add_check(check.clone()).unwrap();
                        let position = get_position(&code, i);
                        block.checks.push((position, true));
                    }
                }
            }

            token = token.append_with_keypair(&temp_keypair, builder).unwrap();

            blocks.push(block);
            biscuit_result.token_blocks.push(Editor::default());
        }

        biscuit_result.token_content = token.print();

        token_opt = Some(token);
    }

    if let Some(authorizer_code) = query.authorizer_code.as_ref() {
        let mut authorizer = match token_opt.as_ref() {
            Some(token) => token.authorizer().unwrap(),
            None => Authorizer::new().unwrap(),
        };

        biscuit_result.authorizer_editor = Some(Editor::default());
        //info!("authorizer source:\n{}", &authorizer_code);

        let authorizer_result;

        let res = parse_source(&authorizer_code);
        if let Err(ref errors) = res {
            parse_errors.authorizer = get_parse_errors(&authorizer_code, errors);
            has_errors = true;
        }

        // do not execute if there were parse errors
        if has_errors {
            return Err(parse_errors);
        }

        let mut authorizer_checks = Vec::new();
        let mut authorizer_policies = Vec::new();

        let parsed = res.unwrap();

        for (_, fact) in parsed.facts.iter() {
            authorizer.add_fact(fact.clone()).unwrap();
        }

        for (_, rule) in parsed.rules.iter() {
            authorizer.add_rule(rule.clone()).unwrap();
        }

        for (i, check) in parsed.checks.iter() {
            authorizer.add_check(check.clone()).unwrap();
            let position = get_position(&authorizer_code, i);
            // checks are marked as success until they fail
            authorizer_checks.push((position, true));
        }

        for (i, policy) in parsed.policies.iter() {
            authorizer.add_policy(policy.clone()).unwrap();
            let position = get_position(&authorizer_code, i);
            // checks are marked as success until they fail
            authorizer_policies.push(position);
        }

        let mut limits = AuthorizerLimits::default();
        limits.max_time = std::time::Duration::from_secs(2);
        authorizer_result = authorizer.authorize_with_limits(limits);

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
            Err(error::Token::FailedLogic(error::Logic::FailedChecks(v))) => {
                for e in v.iter() {
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
            Err(error::Token::FailedLogic(error::Logic::Deny(index))) => {
                let position = &authorizer_policies[*index];
                if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                    ed.markers.push(Marker {
                        ok: false,
                        position: position.clone(),
                    });
                }
            }
            Ok(index) => {
                let position = &authorizer_policies[*index];
                if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                    ed.markers.push(Marker {
                        ok: true,
                        position: position.clone(),
                    });
                }
            }
            _ => {}
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
            if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                ed.markers.push(Marker {
                    ok: *result,
                    position: position.clone(),
                });
            }
        }

        biscuit_result.authorizer_result = authorizer_result;

        if let Some(query) = query.query.as_ref() {
            log(&format!("got query content: {}", query));

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
    }

    Ok(biscuit_result)
}
