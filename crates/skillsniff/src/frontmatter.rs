//! YAML frontmatter parsing for `SKILL.md`.
//!
//! The YAML is read through the low-level event parser rather than a document
//! loader, because the loader deep-copies anchored nodes on every alias and a
//! small hostile document could expand without bound. Aliases are rejected.

use std::collections::BTreeMap;

use yaml_rust2::parser::{EventReceiver, Parser};
use yaml_rust2::scanner::TScalarStyle;
use yaml_rust2::{Event, Yaml};

/// Largest accepted frontmatter, in bytes between the fences.
const MAX_FRONTMATTER_BYTES: usize = 64 * 1024;

/// A rendered node and whether it was a YAML string scalar.
type Node = (String, bool);

/// Top-level keys with rendered values.
pub(crate) type Fields = BTreeMap<String, Node>;

struct Frame {
    is_map: bool,
    items: Vec<Node>,
}

#[derive(Default)]
struct Collector {
    stack: Vec<Frame>,
    root: Option<Fields>,
    error: Option<String>,
}

impl Collector {
    fn finish(&mut self, node: Node) {
        match self.stack.last_mut() {
            Some(frame) => frame.items.push(node),
            None => {
                // A scalar at the top level: only an empty document is allowed.
                if node.0.is_empty() {
                    self.root.get_or_insert_with(BTreeMap::new);
                } else {
                    self.error = Some("frontmatter must be a mapping".to_string());
                }
            }
        }
    }

    fn close(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        if self.stack.is_empty() && frame.is_map {
            let mut map = BTreeMap::new();
            for pair in frame.items.chunks(2) {
                if let [k, v] = pair {
                    map.insert(k.0.clone(), v.clone());
                }
            }
            self.root = Some(map);
            return;
        }
        let text = if frame.is_map {
            frame
                .items
                .chunks(2)
                .map(|p| match p {
                    [k, v] => format!("{}: {}", k.0, v.0),
                    [k] => k.0.clone(),
                    _ => String::new(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            frame
                .items
                .iter()
                .map(|n| n.0.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        self.finish((text, false));
    }

    fn open(&mut self, is_map: bool) {
        if self.stack.is_empty() && !is_map {
            self.error = Some("frontmatter must be a mapping".to_string());
        }
        self.stack.push(Frame {
            is_map,
            items: Vec::new(),
        });
    }
}

impl EventReceiver for Collector {
    fn on_event(&mut self, ev: Event) {
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::Alias(_) => {
                self.error = Some("YAML aliases are not allowed in frontmatter".to_string());
            }
            Event::Scalar(text, style, _, _) => {
                let is_string = style != TScalarStyle::Plain
                    || matches!(Yaml::from_str(&text), Yaml::String(_));
                let null =
                    style == TScalarStyle::Plain && matches!(Yaml::from_str(&text), Yaml::Null);
                self.finish((if null { String::new() } else { text }, is_string));
            }
            Event::SequenceStart(..) => self.open(false),
            Event::MappingStart(..) => self.open(true),
            Event::SequenceEnd | Event::MappingEnd => self.close(),
            _ => {}
        }
    }
}

/// Parse the leading `---` block of `text`.
///
/// Returns the top-level keys and the 1-based line number of the first line
/// after the closing `---`. A leading BOM is ignored and both `\n` and `\r\n`
/// line endings are accepted.
pub fn parse_frontmatter(text: &str) -> Result<(BTreeMap<String, String>, u32), String> {
    let (map, line) = parse_typed(text)?;
    Ok((map.into_iter().map(|(k, (v, _))| (k, v)).collect(), line))
}

/// Like [`parse_frontmatter`], but each value also says whether it was a YAML string.
pub(crate) fn parse_typed(text: &str) -> Result<(Fields, u32), String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let is_fence = |l: &str| l.trim_end() == "---";
    if !lines.next().is_some_and(is_fence) {
        return Err("missing opening --- line".to_string());
    }
    let mut yaml = String::new();
    // 1-based number of the line being examined; the opening fence is line 1.
    let mut line_no: usize = 1;
    let close_line = loop {
        line_no += 1;
        let Some(line) = lines.next() else {
            return Err("missing closing --- line".to_string());
        };
        if is_fence(line) {
            break line_no;
        }
        if yaml.len() + line.len() + 1 > MAX_FRONTMATTER_BYTES {
            return Err("frontmatter is larger than 64 KiB".to_string());
        }
        yaml.push_str(line);
        yaml.push('\n');
    };
    let mut collector = Collector::default();
    Parser::new_from_str(&yaml)
        .load(&mut collector, false)
        .map_err(|e| format!("invalid YAML: {e}"))?;
    if let Some(e) = collector.error {
        return Err(e);
    }
    Ok((
        collector.root.unwrap_or_default(),
        u32::try_from(close_line + 1).unwrap_or(u32::MAX),
    ))
}
