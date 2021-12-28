use log::*;
use nom::Offset;
use serde::{Deserialize, Serialize};
use std::default::Default;
use wasm_bindgen::prelude::*;

mod execute;
mod generate_token;
mod parse_token;
pub use execute::execute;
pub use generate_token::generate_token;
pub use parse_token::parse_token;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
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
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fact {
    pub name: String,
    pub terms: Vec<String>,
}

#[wasm_bindgen(start)]
pub fn run_app() {
    wasm_logger::init(wasm_logger::Config::default());
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    log("wasm run_app")
}

// based on nom's convert_error
fn get_position(input: &str, span: &str) -> SourcePosition {
    let offset = input.offset(span);
    let start = offset;

    let offset = offset + span.len();
    let end = offset;

    SourcePosition { start, end }
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
        let message = e
            .message
            .as_ref()
            .cloned()
            .unwrap_or_else(|| format!("error: {:?}", e.code));

        error!(
            "position for error({:?}) \"{}\": {:?}",
            e.code, message, position
        );
        res.push(ParseError { message, position });
    }

    res
}
