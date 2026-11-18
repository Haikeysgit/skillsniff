//! Language-neutral facts about one file and flow-insensitive taint tracking.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::patterns::{DOWNLOAD_EXEC, EVAL, EXEC, NETWORK};

/// Fixed-point rounds before propagation gives up.
const MAX_ROUNDS: usize = 32;
/// Reference lookups one spread may make before giving up.
const MAX_SPREAD_WORK: usize = 20_000_000;

/// A source or sink occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Unique within the file and never a valid identifier (starts with `#`).
    pub id: String,
    /// One of `SOURCE_CLASSES` or `SINK_CLASSES`.
    pub class: String,
    /// 1-based line.
    pub line: u32,
    /// Identifiers and site ids referenced by the call's arguments (sinks).
    pub args_refs: Vec<String>,
    /// Short display text for evidence, for example `requests.post(...)`.
    pub text: String,
}

/// What a language extracted from one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub sources: Vec<Site>,
    pub sinks: Vec<Site>,
    /// `(variable, identifiers and site ids referenced on the right, line)`.
    pub assigns: Vec<(String, Vec<String>, u32)>,
    /// Extraction ran out of time; the facts above are partial.
    pub budget_exceeded: bool,
    /// For an `exec` or `eval` sink id, the references it runs as code. A
    /// sink listed here becomes `download_exec` only when fetched data
    /// reaches these; other sinks use all of their argument references.
    pub code_refs: BTreeMap<String, Vec<String>>,
}

/// A source class reaching a sink class within one file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Flow {
    pub from_class: String,
    pub to_class: String,
    pub source_line: u32,
    pub sink_line: u32,
    pub source_id: String,
    pub sink_id: String,
}

/// Representative origin of a taint class: the earliest source, by line then id.
type Origin = (u32, usize);

/// `class -> earliest origin` reaching a name.
type Taint = BTreeMap<String, Origin>;

fn merge(into: &mut Taint, from: &Taint) -> bool {
    let mut changed = false;
    for (class, origin) in from {
        match into.get_mut(class) {
            Some(cur) if *cur <= *origin => {}
            Some(cur) => {
                *cur = *origin;
                changed = true;
            }
            None => {
                into.insert(class.clone(), *origin);
                changed = true;
            }
        }
    }
    changed
}

/// Taint of every name and seed id. `seeds` maps a site id to its class and
/// origin; assignments spread it to variables until a fixed point, for at most
/// [`MAX_ROUNDS`] rounds and [`MAX_SPREAD_WORK`] reference lookups. The flag
/// is true when the work limit cut the spread short.
fn spread(
    assigns: &[(String, Vec<String>, u32)],
    seeds: HashMap<&str, Taint>,
) -> (HashMap<String, Taint>, bool) {
    let mut tainted: HashMap<String, Taint> =
        seeds.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    if tainted.is_empty() {
        return (tainted, false);
    }
    let mut work = 0usize;
    for _ in 0..MAX_ROUNDS {
        let mut changed = false;
        for (var, refs, _) in assigns {
            work += refs.len() + 1;
            if work > MAX_SPREAD_WORK {
                return (tainted, true);
            }
            let mut acc = Taint::new();
            for r in refs {
                if let Some(t) = tainted.get(r) {
                    merge(&mut acc, t);
                }
            }
            if acc.is_empty() {
                continue;
            }
            changed |= merge(tainted.entry(var.clone()).or_default(), &acc);
        }
        if !changed {
            break;
        }
    }
    (tainted, false)
}

fn reaching(refs: &[String], tainted: &HashMap<String, Taint>) -> Taint {
    let mut acc = Taint::new();
    for r in refs {
        if let Some(t) = tainted.get(r) {
            merge(&mut acc, t);
        }
    }
    acc
}

/// Flows from sources to sinks, one per (sink, source class), each naming
/// the earliest contributing source. Sorted and free of duplicates.
pub fn propagate(facts: &Facts) -> Vec<Flow> {
    propagate_bounded(facts).0
}

/// [`propagate`], also reporting whether the work limit cut it short.
pub fn propagate_bounded(facts: &Facts) -> (Vec<Flow>, bool) {
    let seeds = facts
        .sources
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), Taint::from([(s.class.clone(), (s.line, i))])))
        .collect();
    let (tainted, cut) = spread(&facts.assigns, seeds);
    let mut flows = BTreeSet::new();
    for sink in &facts.sinks {
        for (class, (line, idx)) in reaching(&sink.args_refs, &tainted) {
            flows.insert(Flow {
                from_class: class,
                to_class: sink.class.clone(),
                source_line: line,
                sink_line: sink.line,
                source_id: facts.sources[idx].id.clone(),
                sink_id: sink.id.clone(),
            });
        }
    }
    (flows.into_iter().collect(), cut)
}

/// Variables and ids that `seeds` reach through `assigns` (seeds included),
/// and whether the work limit cut the search short.
pub fn reached(assigns: &[(String, Vec<String>, u32)], seeds: &[&str]) -> (HashSet<String>, bool) {
    let seeds = seeds
        .iter()
        .map(|s| (*s, Taint::from([(String::new(), (0, 0))])))
        .collect();
    let (tainted, cut) = spread(assigns, seeds);
    (tainted.into_keys().collect(), cut)
}

/// Turns `eval` and `exec` sinks whose arguments reach the result of a
/// `network` sink into `download_exec` sinks (fetched code being run).
/// Returns true when the work limit cut the search short.
pub fn mark_download_exec(facts: &mut Facts) -> bool {
    let seeds = facts
        .sinks
        .iter()
        .enumerate()
        .filter(|(_, s)| s.class == NETWORK)
        .map(|(i, s)| {
            (
                s.id.as_str(),
                Taint::from([(NETWORK.to_string(), (s.line, i))]),
            )
        })
        .collect::<HashMap<_, _>>();
    let (tainted, cut) = spread(&facts.assigns, seeds);
    for sink in &mut facts.sinks {
        let code = facts.code_refs.get(&sink.id).unwrap_or(&sink.args_refs);
        if (sink.class == EVAL || sink.class == EXEC) && !reaching(code, &tainted).is_empty() {
            sink.class = DOWNLOAD_EXEC.to_string();
        }
    }
    cut
}
