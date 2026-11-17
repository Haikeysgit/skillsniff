//! YAML frontmatter parsing for `SKILL.md`.

use std::collections::BTreeMap;

use yaml_rust2::{Yaml, YamlLoader};

/// Render a YAML value to a plain string. Collections are flattened to a
/// comma-separated form so unusual keys never make a skill unreadable.
fn render(v: &Yaml) -> String {
    match v {
        Yaml::String(s) | Yaml::Real(s) => s.clone(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Boolean(b) => b.to_string(),
        Yaml::Array(a) => a.iter().map(render).collect::<Vec<_>>().join(", "),
        Yaml::Hash(h) => h
            .iter()
            .map(|(k, v)| format!("{}: {}", render(k), render(v)))
            .collect::<Vec<_>>()
            .join(", "),
        Yaml::Null | Yaml::BadValue | Yaml::Alias(_) => String::new(),
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
pub(crate) fn parse_typed(text: &str) -> Result<(BTreeMap<String, (String, bool)>, u32), String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    let is_fence = |l: &str| l.trim_end() == "---";
    if !lines.first().is_some_and(|l| is_fence(l)) {
        return Err("missing opening --- line".to_string());
    }
    let close = lines
        .iter()
        .skip(1)
        .position(|l| is_fence(l))
        .map(|i| i + 1)
        .ok_or_else(|| "missing closing --- line".to_string())?;
    let yaml = lines[1..close].join("\n");
    let docs = YamlLoader::load_from_str(&yaml).map_err(|e| format!("invalid YAML: {e}"))?;
    let mut map = BTreeMap::new();
    match docs.first() {
        None | Some(Yaml::Null) => {}
        Some(Yaml::Hash(h)) => {
            for (k, v) in h {
                map.insert(render(k), (render(v), matches!(v, Yaml::String(_))));
            }
        }
        Some(_) => return Err("frontmatter must be a mapping".to_string()),
    }
    // `close` is 0-based, so the following line is `close + 2` in 1-based terms.
    Ok((map, u32::try_from(close + 2).unwrap_or(u32::MAX)))
}
