//! Language-neutral fact extraction shared by the language rules.
//!
//! A language walks its tree once, recording reference tokens (identifiers,
//! dotted names and site ids, each with its byte range), calls and bindings
//! in a [`Core`]. The core then turns byte ranges into the identifiers and
//! site ids they reference, under fixed caps and a scan budget, and builds
//! the final [`Facts`].

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

use tree_sitter::{Node, Query, QueryCursor, StreamingIterator, Tree};

use super::taint::{Facts, Site, reached};
use super::{PARSE_BUDGET, clip};

/// Sources, sinks and sensitive paths kept per file.
pub(super) const MAX_SITES: usize = 10_000;
pub(super) const MAX_ASSIGNS: usize = 100_000;
/// Distinct references kept per site or assignment.
const MAX_REFS: usize = 1_024;
/// Tokens scanned per range before giving up on the rest.
const MAX_REF_SCAN: usize = 65_536;
/// Token visits allowed across all reference lookups in one file.
const MAX_TOTAL_SCAN: usize = 20_000_000;
/// Reference entries stored across all assignments of one file.
const MAX_TOTAL_REFS: usize = 2_000_000;
pub(super) const MAX_NAME_SEGMENTS: usize = 32;
pub(super) const MAX_FOLD_NODES: usize = 256;
pub(super) const MAX_CHILDREN: u32 = 64;
/// Distinct meanings kept per alias or object name.
const MAX_RESOLUTIONS: usize = 16;
pub(super) const TEXT_CHARS: usize = 80;
/// Captures between budget checks.
const BUDGET_CHECK_EVERY: usize = 4_096;

/// 1-based line of a node.
pub(super) fn line(node: Node) -> u32 {
    u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX)
}

/// Last segment of a dotted name, without a call suffix.
pub(super) fn last_segment(name: &str) -> &str {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches("()")
}

/// Runs `query` over the tree and hands every capture, in document order, to
/// `f` with its capture name. Returns false when the time budget ran out.
pub(super) fn run_query<'t>(
    query: &Query,
    tree: &'t Tree,
    src: &[u8],
    mut f: impl FnMut(&str, Node<'t>),
) -> bool {
    let started = Instant::now();
    let names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut caps = cursor.captures(query, tree.root_node(), src);
    let mut seen = 0usize;
    while let Some((m, i)) = caps.next() {
        seen += 1;
        if seen.is_multiple_of(BUDGET_CHECK_EVERY) && started.elapsed() > PARSE_BUDGET {
            return false;
        }
        let cap = m.captures()[*i];
        f(names[cap.index as usize], cap.node);
    }
    true
}

/// A call seen in the tree.
pub(super) struct Call<'t> {
    pub node: Node<'t>,
    pub id: String,
    pub callee: Option<String>,
    pub args: Option<Node<'t>>,
}

/// A binding: `targets = <ranges> + extra`.
pub(super) struct Bind {
    pub targets: Vec<String>,
    pub ranges: Vec<(usize, usize)>,
    pub extra: Vec<String>,
    pub line: u32,
    pub rhs_callee: Option<String>,
}

/// A reference inside a byte range: an identifier, a dotted name or a site id.
struct Token {
    start: usize,
    end: usize,
    name: String,
    ident: bool,
}

/// Extraction state shared by every language.
pub(super) struct Core<'t> {
    pub src: &'t [u8],
    tokens: Vec<Token>,
    /// Start bytes of identifiers that name something rather than read a
    /// value (attribute names, keyword names, function names).
    pub not_values: HashSet<usize>,
    pub calls: Vec<Call<'t>>,
    pub binds: Vec<Bind>,
    /// Imported or required names and everything they may stand for. Every
    /// binding is kept, so a later (possibly dead) rebinding cannot hide an
    /// earlier one.
    aliases: HashMap<String, Vec<String>>,
    /// Variables holding a network client, and the constructor calls.
    objects: HashMap<String, Vec<String>>,
    pub sources: Vec<Site>,
    pub sensitive: Vec<String>,
    next_id: usize,
    /// Token visits left for reference lookups before analysis gives up.
    scan_left: Cell<usize>,
    /// Some cap dropped facts; the analysis is partial.
    truncated: Cell<bool>,
    /// Site ids worth keeping in references (sources, sensitive paths,
    /// network sinks); other ids are skipped.
    interesting: HashSet<String>,
}

impl<'t> Core<'t> {
    pub fn new(src: &'t [u8]) -> Self {
        Self {
            src,
            tokens: Vec::new(),
            not_values: HashSet::new(),
            calls: Vec::new(),
            binds: Vec::new(),
            aliases: HashMap::new(),
            objects: HashMap::new(),
            sources: Vec::new(),
            sensitive: Vec::new(),
            next_id: 0,
            scan_left: Cell::new(MAX_TOTAL_SCAN),
            truncated: Cell::new(false),
            interesting: HashSet::new(),
        }
    }

    pub fn text(&self, node: Node) -> &'t str {
        let src: &'t [u8] = self.src;
        std::str::from_utf8(&src[node.byte_range()]).unwrap_or("")
    }

    pub fn truncate(&self) {
        self.truncated.set(true);
    }

    /// Spends one unit of the scan budget; false (and truncated) when it is
    /// used up.
    fn spend(&self) -> bool {
        let left = self.scan_left.get();
        if left == 0 {
            self.truncate();
            return false;
        }
        self.scan_left.set(left - 1);
        true
    }

    /// Named children of `node` other than comments, at most
    /// [`MAX_CHILDREN`]. Comments do not count toward the cap; hitting the cap
    /// marks the facts truncated.
    pub fn children<'n>(&self, node: Node<'n>) -> Vec<Node<'n>> {
        let mut out = Vec::new();
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if !self.spend() {
                break;
            }
            if c.kind() == "comment" {
                continue;
            }
            if out.len() == MAX_CHILDREN as usize {
                self.truncate();
                break;
            }
            out.push(c);
        }
        out
    }

    /// Named children of `node` other than comments, for walks that bind
    /// nothing (folding, scanning call arguments). At most `limit` are
    /// returned and more mark the facts truncated; the walk spends the scan
    /// budget. Pass `usize::MAX` for no limit.
    pub fn children_upto<'n>(&self, node: Node<'n>, limit: usize) -> Vec<Node<'n>> {
        let mut out = Vec::new();
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if !self.spend() {
                break;
            }
            if c.kind() == "comment" {
                continue;
            }
            if out.len() == limit {
                self.truncate();
                break;
            }
            out.push(c);
        }
        out
    }

    /// Last named child of `node` that is not a comment.
    pub fn last_child<'n>(&self, node: Node<'n>) -> Option<Node<'n>> {
        self.children_upto(node, usize::MAX).pop()
    }

    /// First named child of `node` that is not a comment.
    pub fn first_child<'n>(&self, node: Node<'n>) -> Option<Node<'n>> {
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if !self.spend() {
                return None;
            }
            if c.kind() != "comment" {
                return Some(c);
            }
        }
        None
    }

    /// Whether `node` has a named child of `kind` (no cap on the search).
    pub fn has_child_kind(&self, node: Node, kind: &str) -> bool {
        let mut cursor = node.walk();
        for c in node.named_children(&mut cursor) {
            if !self.spend() {
                return false;
            }
            if c.kind() == kind {
                return true;
            }
        }
        false
    }

    /// Records that `local` may stand for `full`. `relevant` tells meanings
    /// the rules care about (sink or client modules and names) from the rest.
    /// When a name already has [`MAX_RESOLUTIONS`] meanings, a relevant one
    /// replaces an irrelevant one, and an irrelevant one is dropped: relevant
    /// meanings are never evicted. Only a relevant meaning with no room left
    /// marks the facts truncated.
    pub fn add_alias(&mut self, local: &str, full: String, relevant: impl Fn(&str) -> bool) {
        if local == full {
            return;
        }
        let entry = self.aliases.entry(local.to_string()).or_default();
        if entry.contains(&full) {
            return;
        }
        if entry.len() < MAX_RESOLUTIONS {
            entry.push(full);
            return;
        }
        if !relevant(&full) {
            return;
        }
        match entry.iter().position(|e| !relevant(e)) {
            Some(i) => entry[i] = full,
            None => self.truncated.set(true),
        }
    }

    /// Every name `name` may stand for once an imported alias or a network
    /// object variable at its head is replaced; `name` itself when neither
    /// applies.
    pub fn resolutions(&self, name: &str) -> Vec<String> {
        let cut = name.find(['.', '(']).unwrap_or(name.len());
        let (head, rest) = name.split_at(cut);
        let mut out: Vec<String> = Vec::new();
        if let Some(fulls) = self.aliases.get(head) {
            out.extend(fulls.iter().map(|f| format!("{f}{rest}")));
        }
        if rest.starts_with('.')
            && let Some(objs) = self.objects.get(head)
        {
            out.extend(objs.iter().map(|o| format!("{o}{rest}")));
        }
        if out.is_empty() {
            out.push(name.to_string());
        }
        out
    }

    /// The first resolution of `name` that `pred` accepts.
    pub fn resolve_where(&self, name: &str, pred: impl Fn(&str) -> bool) -> Option<String> {
        self.resolutions(name).into_iter().find(|r| pred(r))
    }

    /// The first resolution of `name` that `pred` accepts, else the first.
    pub fn resolve_best(&self, name: &str, pred: impl Fn(&str) -> bool) -> String {
        let all = self.resolutions(name);
        let pick = all.iter().position(|r| pred(r)).unwrap_or(0);
        all.into_iter().nth(pick).unwrap_or_default()
    }

    /// A new site id. Site ids start with `#` and are never identifiers in
    /// any supported language (languages that allow `#` in names, such as
    /// JavaScript private fields, rewrite those names first).
    pub fn fresh_id(&mut self, prefix: char) -> String {
        self.next_id += 1;
        format!("#{prefix}{}", self.next_id)
    }

    pub fn token(&mut self, node: Node, name: String, ident: bool) {
        self.tokens.push(Token {
            start: node.start_byte(),
            end: node.end_byte(),
            name,
            ident,
        });
    }

    /// Records a call node under a fresh `#c` id.
    pub fn add_call(&mut self, node: Node<'t>, callee: Option<String>, args: Option<Node<'t>>) {
        let id = self.fresh_id('c');
        self.token(node, id.clone(), false);
        self.calls.push(Call {
            node,
            id,
            callee,
            args,
        });
    }

    /// Records `targets = <rhs range>`; `end` overrides the range end.
    pub fn bind(
        &mut self,
        targets: Vec<String>,
        rhs: Option<Node>,
        end: Option<usize>,
        line: u32,
        rhs_callee: Option<String>,
    ) {
        let Some(rhs) = rhs else { return };
        if targets.is_empty() {
            return;
        }
        if self.binds.len() >= MAX_ASSIGNS {
            self.truncate();
            return;
        }
        self.binds.push(Bind {
            targets,
            ranges: vec![(rhs.start_byte(), end.unwrap_or(rhs.end_byte()))],
            extra: Vec::new(),
            line,
            rhs_callee,
        });
    }

    /// Records a prepared binding, unless it has no targets or the cap is
    /// reached.
    pub fn push_bind(&mut self, bind: Bind) {
        if bind.targets.is_empty() {
            return;
        }
        if self.binds.len() >= MAX_ASSIGNS {
            self.truncate();
            return;
        }
        self.binds.push(bind);
    }

    /// Identifiers and interesting site ids inside the byte ranges,
    /// deduplicated, site ids first. Any cap hit marks the facts truncated.
    /// Needs [`Core::index_tokens`] first.
    pub fn refs(&self, ranges: &[(usize, usize)]) -> Vec<String> {
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        'ranges: for &(s, e) in ranges {
            let first = self.tokens.partition_point(|t| t.start < s);
            for (scanned, t) in self.tokens[first..].iter().enumerate() {
                if t.start >= e {
                    break;
                }
                let left = self.scan_left.get();
                if left == 0 || scanned == MAX_REF_SCAN {
                    self.truncate();
                    break 'ranges;
                }
                self.scan_left.set(left - 1);
                if t.end > e {
                    continue;
                }
                let name = t.name.as_str();
                let (set, keep) = if name.starts_with('#') {
                    (&mut ids, self.interesting.contains(name))
                } else {
                    (&mut names, true)
                };
                if !keep || set.contains(name) {
                    continue;
                }
                if set.len() >= MAX_REFS {
                    self.truncate();
                    continue;
                }
                set.insert(name);
            }
        }
        ids.into_iter().chain(names).map(str::to_string).collect()
    }

    /// References of one node's byte range.
    pub fn node_refs(&self, node: Node) -> Vec<String> {
        self.refs(&[(node.start_byte(), node.end_byte())])
    }

    /// `callee(literal)` for the innermost call (other than one `skip`
    /// accepts) whose arguments contain `node`, else the literal quoted.
    pub fn describe_in_call(&self, node: Node, shown: &str, skip: impl Fn(&str) -> bool) -> String {
        let shown = clip(shown, TEXT_CHARS);
        let upto = self
            .calls
            .partition_point(|c| c.node.start_byte() <= node.start_byte());
        for c in self.calls[..upto].iter().rev().take(64) {
            let (Some(args), Some(name)) = (c.args, c.callee.as_deref()) else {
                continue;
            };
            let inside =
                args.start_byte() <= node.start_byte() && node.end_byte() <= args.end_byte();
            if inside && !skip(name) {
                return format!("{}({shown})", clip(name, TEXT_CHARS));
            }
        }
        format!("'{shown}'")
    }

    /// Adds a source site; `id` reuses an existing token (a call) when given.
    pub fn add_source(&mut self, node: Node, class: &str, text: String, id: Option<String>) {
        if self.sources.len() >= MAX_SITES {
            self.truncate();
            return;
        }
        let id = id.unwrap_or_else(|| {
            let id = self.fresh_id('s');
            self.token(node, id.clone(), false);
            id
        });
        self.sources.push(Site {
            id,
            class: class.to_string(),
            line: line(node),
            args_refs: Vec::new(),
            text,
            dynamic: false,
        });
    }

    /// Forgets sources whose token lies inside one of the byte ranges.
    pub fn drop_sources_within(&mut self, cuts: &[(usize, usize)]) {
        let inside: HashSet<&str> = self
            .tokens
            .iter()
            .filter(|t| cuts.iter().any(|&(s, e)| t.start >= s && t.end <= e))
            .map(|t| t.name.as_str())
            .collect();
        self.sources.retain(|s| !inside.contains(s.id.as_str()));
    }

    pub fn add_sensitive(&mut self, node: Node) {
        if self.sensitive.len() >= MAX_SITES {
            self.truncate();
            return;
        }
        let id = self.fresh_id('p');
        self.token(node, id.clone(), false);
        self.sensitive.push(id);
    }

    /// Whether spans sorted by start have one of `class` inside `node`.
    pub fn has_span_within(spans: &[(usize, usize, &str)], node: Node, class: &str) -> bool {
        let first = spans.partition_point(|s| s.0 < node.start_byte());
        spans[first..]
            .iter()
            .take_while(|s| s.0 < node.end_byte())
            .any(|s| s.1 <= node.end_byte() && s.2 == class)
    }

    /// Network client objects: a single-target binding whose right side calls
    /// one of `constructors` (under any alias resolution). Then resolves every
    /// call name, preferring a resolution that `relevant` accepts (a sink or
    /// another name the language classifies).
    pub fn resolve_calls(&mut self, constructors: &[&str], relevant: impl Fn(&str) -> bool) {
        let mut objects: HashMap<String, Vec<String>> = HashMap::new();
        for b in &self.binds {
            let ([target], Some(callee)) = (b.targets.as_slice(), b.rhs_callee.as_deref()) else {
                continue;
            };
            for full in self.resolutions(callee) {
                if !constructors.contains(&full.as_str()) {
                    continue;
                }
                let entry = objects.entry(target.clone()).or_default();
                let obj = format!("{full}()");
                if entry.contains(&obj) {
                    continue;
                }
                if entry.len() >= MAX_RESOLUTIONS {
                    self.truncated.set(true);
                } else {
                    entry.push(obj);
                }
            }
        }
        self.objects = objects;
        let mut calls = std::mem::take(&mut self.calls);
        for c in &mut calls {
            c.callee = c.callee.take().map(|n| self.resolve_best(&n, &relevant));
        }
        self.calls = calls;
    }

    /// Drops identifiers that are not values and sorts tokens for lookups.
    /// Call once every site token has been added.
    pub fn index_tokens(&mut self) {
        let not_values = std::mem::take(&mut self.not_values);
        self.tokens
            .retain(|t| !(t.ident && not_values.contains(&t.start)));
        self.tokens
            .sort_by_key(|t| (t.start, std::cmp::Reverse(t.end)));
    }

    /// Marks source ids, sensitive path ids and `network` ids as worth
    /// keeping in references.
    pub fn set_interesting(&mut self, network: impl IntoIterator<Item = String>) {
        let interesting: HashSet<String> = self
            .sources
            .iter()
            .map(|s| s.id.clone())
            .chain(self.sensitive.iter().cloned())
            .chain(network)
            .collect();
        self.interesting = interesting;
    }

    /// Assignments with resolved references. A binding with several targets
    /// stores its references once under a synthetic `@b<n>` name that each
    /// target then references.
    pub fn assigns(&self) -> Vec<(String, Vec<String>, u32)> {
        let mut assigns = Vec::new();
        let mut stored = 0usize;
        for (i, b) in self.binds.iter().enumerate() {
            let mut refs = self.refs(&b.ranges);
            refs.extend(b.extra.iter().cloned());
            stored += refs.len() + b.targets.len();
            if stored > MAX_TOTAL_REFS || assigns.len() + b.targets.len() > MAX_ASSIGNS {
                self.truncate();
                break;
            }
            if let [target] = b.targets.as_slice() {
                assigns.push((target.clone(), refs, b.line));
                continue;
            }
            let shared = format!("@b{i}");
            assigns.push((shared.clone(), refs, b.line));
            for t in &b.targets {
                assigns.push((t.clone(), vec![shared.clone()], b.line));
            }
        }
        assigns
    }

    /// Variables and ids that sensitive path literals reach.
    pub fn sensitive_reach(&self, assigns: &[(String, Vec<String>, u32)]) -> HashSet<String> {
        let seeds: Vec<&str> = self.sensitive.iter().map(String::as_str).collect();
        let (sensitive, cut) = reached(assigns, &seeds);
        if cut {
            self.truncate();
        }
        sensitive
    }

    /// A sink at call `c`, referencing what its arguments reference.
    pub fn sink(&self, c: &Call, name: &str, class: &str, text: Option<String>) -> Site {
        let args_refs = c.args.map(|a| self.node_refs(a)).unwrap_or_default();
        Site {
            id: c.id.clone(),
            class: class.to_string(),
            line: line(c.node),
            args_refs,
            text: text.unwrap_or_else(|| format!("{}(...)", clip(name, TEXT_CHARS))),
            dynamic: false,
        }
    }

    /// Pushes a sink unless the per-file cap is reached.
    pub fn push_sink(&self, sinks: &mut Vec<Site>, site: impl FnOnce() -> Site) {
        if sinks.len() >= MAX_SITES {
            self.truncate();
            return;
        }
        sinks.push(site());
    }

    /// Final facts: drops references to ids that are neither sources nor
    /// sinks.
    pub fn into_facts(
        self,
        mut sinks: Vec<Site>,
        mut assigns: Vec<(String, Vec<String>, u32)>,
    ) -> Facts {
        let valid: HashSet<String> = self
            .sources
            .iter()
            .chain(&sinks)
            .map(|s| s.id.clone())
            .collect();
        let keep = |r: &String| !r.starts_with('#') || valid.contains(r);
        for a in &mut assigns {
            a.1.retain(keep);
        }
        for s in &mut sinks {
            s.args_refs.retain(keep);
        }
        Facts {
            sources: self.sources,
            sinks,
            assigns,
            budget_exceeded: self.truncated.get(),
            code_refs: Default::default(),
        }
    }
}
