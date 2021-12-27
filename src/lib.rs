use wasm_bindgen::prelude::*;
use biscuit_auth::{
    KeyPair,
    PrivateKey,
    error,
    parser::{parse_block_source, parse_source, SourceResult},
    Biscuit,
    builder,
    Authorizer, AuthorizerLimits,
    UnverifiedBiscuit,
};
use log::*;
use nom::Offset;
use rand::prelude::*;
use serde::{Serialize, Deserialize};
use std::default::Default;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[derive(Serialize, Deserialize)]
pub struct BiscuitQuery {
    pub token_blocks: Vec<String>,
    pub authorizer_code: Option<String>,
    pub query: Option<String>,
}

#[derive(Serialize, Deserialize)]
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
           token_blocks:Vec::new(),
           token_content: String::new(),
           authorizer_editor: None,
           authorizer_result: Ok(0),
           authorizer_world: Vec::new(),
           query_result: Vec::new(),
       }
   }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Editor {
    pub markers: Vec<Marker>,
}


#[derive(Serialize, Deserialize)]
pub struct Marker {
    pub ok: bool,
    pub position: SourcePosition,
}

#[derive(Serialize, Deserialize)]
pub struct ParseError {
    pub message: String,
    pub position: SourcePosition,
}

#[derive(Serialize, Deserialize)]
pub struct ParseErrors {
    pub blocks: Vec<Vec<ParseError>>,
    pub authorizer: Vec<ParseError>,
}

impl ParseErrors {
    pub fn new() -> ParseErrors {
        ParseErrors {
            blocks: Vec::new(),
            authorizer: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourcePosition {
    pub line_start: usize,
    pub column_start: usize,
    pub line_end: usize,
    pub column_end: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fact {
    pub name: String,
    pub terms: Vec<String>,
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
        match parse_source(&query.token_blocks[0]) {
            Err(errors) => {
                error!("error: {:?}", errors);
                parse_errors.blocks.push(get_parse_errors(&query.token_blocks[0], &errors));
                has_errors = true;
            },
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

        for (i, code) in (&query.token_blocks[1..]).iter().enumerate() {
            let mut block = Block::default();

            let temp_keypair = KeyPair::new_with_rng(&mut rng);
            let mut builder = token.create_block();

            match parse_source(&code) {
                Err(errors) => {
                    error!("error: {:?}", errors);
                    parse_errors.blocks.push(get_parse_errors(&code, &errors));
                    has_errors = true;
                },
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

            token = token
                .append_with_keypair(&temp_keypair, builder)
                .unwrap();

            blocks.push(block);
            biscuit_result.token_blocks.push(Editor::default());
        }

        let v = token.to_vec().unwrap();
        //self.serialized = Some(base64::encode_config(&v[..], base64::URL_SAFE));
        //self.biscuit = Some(token);
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
        biscuit_result.authorizer_world = facts.drain(..).map(|mut fact| {
            Fact {
                name: fact.predicate.name,
                terms: fact.predicate.terms.drain(..).map(|term| term.to_string()).collect(),
            }
        }).collect();

        match &authorizer_result {
            Err(error::Token::FailedLogic(error::Logic::FailedChecks(v))) => {
                for e in v.iter() {
                    match e {
                        error::FailedCheck::Authorizer(error::FailedAuthorizerCheck {
                            check_id, ..
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
            },
            Err(error::Token::FailedLogic(error::Logic::Deny(index))) => {
                let position = &authorizer_policies[*index];
                if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                    ed.markers.push(Marker { ok: false, position: position.clone() });
                }
            },
            Ok(index) => {
                let position = &authorizer_policies[*index];
                if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                    ed.markers.push(Marker { ok: true, position: position.clone() });
                }
            },
            _ => {},
        }

        for (position, result) in authority.checks.iter() {
            if let Some(ed) = biscuit_result.token_blocks.get_mut(0) {
                ed.markers.push(Marker { ok: *result, position: position.clone() });
            }
        }

        for (id, block) in blocks.iter().enumerate() {
            for (position, result) in block.checks.iter() {
                if let Some(ed) = biscuit_result.token_blocks.get_mut(id+1) {
                    ed.markers.push(Marker { ok: *result, position: position.clone() });
                }
            }
        }

        for (position, result) in authorizer_checks.iter() {
            if let Some(ed) = biscuit_result.authorizer_editor.as_mut() {
                ed.markers.push(Marker { ok: *result, position: position.clone() });
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
                    },
                    Ok(mut facts) => {
                        biscuit_result.query_result = facts.drain(..).map(|mut fact| {
                            Fact {
                                name: fact.predicate.name,
                                terms: fact.predicate.terms.drain(..).map(|term| term.to_string()).collect(),
                            }
                        }).collect();
                    }
                }
            }
        }

    }

    Ok(biscuit_result)
}

#[derive(Serialize, Deserialize)]
pub struct GenerateToken {
    pub token_blocks: Vec<String>,
    pub private_key: String,
}

#[derive(Serialize, Deserialize)]
pub enum GenerateTokenError {
    Parse(ParseErrors),
    Biscuit(error::Token),
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

fn generate_token_from_blocks(query: &GenerateToken, blocks: Vec<SourceResult>) -> Result<String, error::Token> {
    let data = hex::decode(&query.private_key).map_err(|_| error::Token::InternalError)?;

    let keypair = KeyPair::from(PrivateKey::from_bytes(&data)?);
    let mut builder = Biscuit::builder(&keypair);

        let authority_parsed = &blocks[0];

        for (_, fact) in authority_parsed.facts.iter() {
            builder.add_authority_fact(fact.clone()).unwrap();
        }

        for (_, rule) in authority_parsed.rules.iter() {
            builder.add_authority_rule(rule.clone()).unwrap();
        }

        for (_, check) in authority_parsed.checks.iter() {
            builder.add_authority_check(check.clone()).unwrap();
        }

        let mut token = builder.build()?;

        for block_parsed in (&blocks[1..]).iter() {
            let temp_keypair = KeyPair::new();
            let mut builder = token.create_block();

            for (_, fact) in block_parsed.facts.iter() {
                builder.add_fact(fact.clone()).unwrap();
            }

            for (_, rule) in block_parsed.rules.iter() {
                builder.add_rule(rule.clone()).unwrap();
            }

            for (_, check) in block_parsed.checks.iter() {
                builder.add_check(check.clone()).unwrap();
            }

            token = token
                .append_with_keypair(&temp_keypair, builder)?;

        }
        Ok(token.to_base64()?)
}

#[wasm_bindgen(start)]
pub fn run_app() {
    wasm_logger::init(wasm_logger::Config::default());
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    unsafe { log("wasm run_app") }
}

// based on nom's convert_error
fn get_position(input: &str, span: &str) -> SourcePosition {
    let offset = input.offset(span);
    let prefix = &input.as_bytes()[..offset];
    let start = offset;

    // Count the number of newlines in the first `offset` bytes of input
    let line_start = prefix.iter().filter(|&&b| b == b'\n').count();

    // Find the line that includes the subslice:
    // find the *last* newline before the substring starts
    let line_begin = prefix
        .iter()
        .rev()
        .position(|&b| b == b'\n')
        .map(|pos| offset - pos)
        .unwrap_or(0);

    // Find the full line after that newline
    let line = input[line_begin..]
        .lines()
        .next()
        .unwrap_or(&input[line_begin..])
        .trim_end();

    // The (1-indexed) column number is the offset of our substring into that line
    let column_start = line.offset(span);

    let offset = offset + span.len();
    let prefix = &input.as_bytes()[..offset];
    let end = offset;

    // Count the number of newlines in the first `offset` bytes of input
    let line_end = prefix.iter().filter(|&&b| b == b'\n').count();

    // Find the line that includes the subslice:
    // find the *last* newline before the substring starts
    let line_begin = prefix
        .iter()
        .rev()
        .position(|&b| b == b'\n')
        .map(|pos| offset - pos)
        .unwrap_or(0);

    // Find the full line after that newline
    let line = input[line_begin..]
        .lines()
        .next()
        .unwrap_or(&input[line_begin..])
        .trim_end();

    // The (1-indexed) column number is the offset of our substring into that line
    let column_end = line.offset(&span[span.len()..]) + 1;

    SourcePosition {
        line_start,
        column_start,
        line_end,
        column_end,
        start,
        end,
    }
}

#[derive(Clone, Debug)]
struct Block {
    pub code: String,
    pub checks: Vec<(SourcePosition, bool)>,
    pub enabled: bool,
}

impl Default for Block {
    fn default() -> Self {
        Block {
            code: String::new(),
            checks: Vec::new(),
            enabled: true,
        }
    }
}

fn get_parse_errors(input: &str, errors: &[biscuit_auth::parser::Error]) -> Vec<ParseError> {
    let mut res = Vec::new();

    error!("got errors: {:?}", errors);
    for e in errors.iter() {
        let position = get_position(input, e.input);
        let message = e.message.as_ref().cloned().unwrap_or_else(|| format!("error: {:?}", e.code));

        error!("position for error({:?}) \"{}\": {:?}", e.code, message, position);
        res.push(ParseError { message, position });
    }

    res
}

#[derive(Serialize, Deserialize)]
struct ParseTokenQuery {
    pub data: String,
}

#[derive(Default, Serialize, Deserialize)]
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
        },
        Ok(t) => t,
    };

    let mut token_blocks = Vec::new();
    for i in 0..token.block_count() {
        token_blocks.push(token.print_block_source(i).unwrap());
    }

    let revocation_ids = token.revocation_identifiers().into_iter().map(|v| hex::encode(v)).collect();
    ParseResult {
        token_blocks,
        //key: "".to_string(),
        revocation_ids,
        error: None,
    }
}
