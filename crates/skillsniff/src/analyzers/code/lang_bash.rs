//! Bash facts from a tree-sitter-bash tree.
//!
//! One walk over the tree records variable references, literal words,
//! commands, bindings and what each command reads on stdin; a second step
//! classifies commands and redirections and resolves references.
//!
//! Variables are names, flow-insensitive per file. What a command reads on
//! stdin is a synthetic name bound to whatever feeds it: earlier pipeline
//! stages, input redirections, here-strings and here-documents, or the
//! callers of the function it runs in.

use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

use tree_sitter::{Language, Node, Tree, TreeCursor};

use super::common::{Bind, Core, TEXT_CHARS, line};
use super::patterns::{
    DOWNLOAD_EXEC, EVAL, EXEC, KEYCHAIN, NETWORK, REVERSE_SHELL, SECRET_ENV, SENSITIVE_WRITE,
    UNKNOWN_PIECE, env_class, invocation_class, is_posix_shell, is_sensitive_write_path,
    is_shell_flag, literal_source_class, may_name_path, pipes_download_to_shell, program_index,
    program_name,
};
use super::taint::{Facts, Site};
use super::{LangRules, PARSE_BUDGET, clip};

/// Nodes visited between time checks.
const CHECK_EVERY: usize = 4_096;

/// Stands for `$IFS` in folded text: a word separator.
const IFS_SEP: char = '\u{2}';

/// Rules for Bash and POSIX shell scripts.
pub struct BashRules;

impl LangRules for BashRules {
    fn language(&self) -> Language {
        tree_sitter_bash::LANGUAGE.into()
    }

    fn facts(&self, tree: &Tree, src: &str) -> Facts {
        let mut w = Walk::new(src.as_bytes());
        let complete = w.walk(tree);
        let mut facts = w.finish();
        facts.budget_exceeded |= !complete;
        facts
    }
}

/// Context a node inherits from its ancestors. Indexes point into
/// [`Walk::names`].
#[derive(Clone, Copy, Default)]
struct Scope {
    /// Name bound to what the node reads on stdin.
    input: Option<usize>,
    /// Function whose body holds the node.
    func: Option<usize>,
    /// Program of the enclosing command, shown in source evidence.
    cmd: Option<usize>,
    /// Inside a literal already classified as a whole.
    in_literal: bool,
    /// A direct child of a command node.
    in_cmd: bool,
}

/// What an `exec` or `eval` sink runs as code.
#[derive(Clone, Default)]
enum Code<'t> {
    /// Nothing fetched can become code here.
    #[default]
    None,
    /// What the command reads on stdin.
    Input,
    /// Every argument (`eval`).
    All,
    /// These words.
    Nodes(Vec<Node<'t>>),
}

/// A command seen in the tree, or one meaning of a command whose program
/// is a variable.
#[derive(Clone)]
struct Cmd<'t> {
    node: Node<'t>,
    /// Site id of the sink this command may become.
    id: String,
    /// Id of the token covering the command, whose output later stages read.
    token: String,
    /// The program word as written, after launchers such as `sudo`.
    word: Option<String>,
    /// Starts with `exec`: redirections then apply to the shell itself.
    exec: bool,
    class: Option<&'static str>,
    /// Whether what the command reads on stdin flows into the sink.
    reads_input: bool,
    input: Option<usize>,
    /// Arguments naming files the command writes.
    writes: Vec<Node<'t>>,
    /// Installs persistence whatever the path (`crontab -`).
    always_write: bool,
    /// Runs command text that pipes a download into a shell.
    fetch_pipe: bool,
    /// A shell reading commands from stdin or a terminal (not `-c`).
    shell_reader: bool,
    /// `nc`, `telnet`, `socat` and other raw socket tools.
    socket: bool,
    /// What an `exec`/`eval` runs as code.
    code: Code<'t>,
    /// Arguments a network client reads to authenticate but does not send
    /// (`ssh -i key`, `curl --cert file`).
    exclude: Vec<Node<'t>>,
}

/// A command whose program is a variable (`$c args`).
struct Dynamic<'t> {
    /// Index into [`Walk::cmds`] before they are sorted.
    cmd: usize,
    var: String,
    rest: Vec<(Node<'t>, String)>,
    has_input: bool,
}

/// A file redirection with a word destination.
struct Redir<'t> {
    /// The redirected statement or command, for evidence.
    stmt: Node<'t>,
    body: Option<Node<'t>>,
    dest: Node<'t>,
    input: Option<usize>,
    output: bool,
    /// `<>`: the file is both read and written.
    read_write: bool,
}

struct Walk<'t> {
    core: Core<'t>,
    names: Vec<String>,
    cmds: Vec<Cmd<'t>>,
    /// Further meanings of commands whose program is a variable.
    extra: Vec<Cmd<'t>>,
    redirs: Vec<Redir<'t>>,
    pipes: Vec<Node<'t>>,
    funcs: HashSet<String>,
    dynamic: Vec<Dynamic<'t>>,
    code_refs: BTreeMap<String, Vec<String>>,
    next_name: usize,
    cursor: Option<TreeCursor<'t>>,
}

impl<'t> Walk<'t> {
    fn new(src: &'t [u8]) -> Self {
        Self {
            core: Core::new(src),
            names: Vec::new(),
            cmds: Vec::new(),
            extra: Vec::new(),
            redirs: Vec::new(),
            pipes: Vec::new(),
            funcs: HashSet::new(),
            dynamic: Vec::new(),
            code_refs: BTreeMap::new(),
            next_name: 0,
            cursor: None,
        }
    }

    fn text(&self, node: Node) -> &'t str {
        self.core.text(node)
    }

    fn intern(&mut self, name: String) -> usize {
        self.names.push(name);
        self.names.len() - 1
    }

    fn input_names(&self, input: Option<usize>) -> Vec<String> {
        input.map(|i| self.names[i].clone()).into_iter().collect()
    }

    /// Binds a fresh stdin name to `ranges` and to `input`; returns it.
    fn input_bind(
        &mut self,
        prefix: char,
        ranges: Vec<(usize, usize)>,
        input: Option<usize>,
        line: u32,
    ) -> usize {
        self.next_name += 1;
        let name = format!("{prefix}{}", self.next_name);
        let extra = self.input_names(input);
        self.core.push_bind(Bind {
            targets: vec![name.clone()],
            ranges,
            extra,
            line,
            rhs_callee: None,
        });
        self.intern(name)
    }

    /// Short evidence text for a node: its source with whitespace collapsed.
    fn display(&self, node: Node) -> String {
        let text = self.text(node);
        let mut end = text.len().min(TEXT_CHARS * 4);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let words: Vec<&str> = text[..end].split_whitespace().collect();
        clip(&words.join(" "), TEXT_CHARS)
    }

    /// Text a word stands for: quotes and backslash escapes removed, ANSI-C
    /// escapes decoded, pieces joined, expansions kept as written
    /// (`$HOME/.ssh`), `$IFS` as [`IFS_SEP`], substitutions as an unknown
    /// piece.
    fn fold(&self, node: Node<'t>) -> String {
        match node.kind() {
            "word" => return unescape_word(self.text(node)),
            "number" => return self.text(node).to_string(),
            _ => {}
        }
        let mut out = String::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let text = self.text(n);
            match n.kind() {
                "word" => out.push_str(&unescape_word(text)),
                "number" | "string_content" => out.push_str(text),
                "simple_expansion" | "expansion" => {
                    if matches!(text, "$IFS" | "${IFS}") {
                        out.push(IFS_SEP);
                    } else {
                        out.push_str(text);
                    }
                }
                "raw_string" => out.push_str(
                    text.strip_prefix('\'')
                        .and_then(|t| t.strip_suffix('\''))
                        .unwrap_or(text),
                ),
                "ansi_c_string" => out.push_str(&decode_ansi_c(
                    text.strip_prefix("$'")
                        .and_then(|t| t.strip_suffix('\''))
                        .unwrap_or(text),
                )),
                "string" | "translated_string" | "concatenation" | "command_name" => {
                    stack.extend(self.core.children_upto(n, usize::MAX).into_iter().rev());
                }
                _ => out.push(UNKNOWN_PIECE),
            }
        }
        out
    }

    /// The words an argument stands for: split at `$IFS`, and an unquoted
    /// brace list (`{a,b,c}`) expanded. tree-sitter-bash keeps the opening
    /// brace of a list in command position out of the word, so a word right
    /// after a `{` counts as opened.
    fn split_word(&self, node: Node<'t>, folded: &str) -> Vec<String> {
        let opened = node
            .start_byte()
            .checked_sub(1)
            .and_then(|i| self.core.src.get(i))
            == Some(&b'{');
        let unquoted = matches!(node.kind(), "word" | "concatenation" | "command_name");
        let mut out = Vec::new();
        for (i, part) in folded.split(IFS_SEP).filter(|p| !p.is_empty()).enumerate() {
            let inner = part
                .strip_suffix('}')
                .and_then(|p| p.strip_prefix('{').or((i == 0 && opened).then_some(p)));
            match inner {
                Some(list)
                    if unquoted
                        && list.contains(',')
                        && !list.contains(['{', '}'])
                        && !list.contains(char::is_whitespace) =>
                {
                    out.extend(
                        list.split(',')
                            .filter(|w| !w.is_empty())
                            .map(str::to_string),
                    );
                }
                _ => out.push(part.to_string()),
            }
        }
        out
    }

    /// Whether a word is only an expansion or substitution, as in `$CMD`,
    /// `"${CMD}"` or `$(curl …)`.
    fn is_dynamic(&self, node: Node<'t>) -> bool {
        let mut n = node;
        for _ in 0..4 {
            match n.kind() {
                "simple_expansion"
                | "expansion"
                | "command_substitution"
                | "process_substitution" => return true,
                "command_name" => match n.named_child(0) {
                    Some(c) => n = c,
                    None => return false,
                },
                "string" => {
                    let kids = self.core.children_upto(n, usize::MAX);
                    match kids.as_slice() {
                        [only] => n = *only,
                        _ => return false,
                    }
                }
                _ => return false,
            }
        }
        false
    }

    /// Whether a word holds a command or process substitution.
    fn has_substitution(&self, node: Node<'t>) -> bool {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "command_substitution" | "process_substitution" => return true,
                "string" | "concatenation" => {
                    stack.extend(self.core.children_upto(n, usize::MAX));
                }
                _ => {}
            }
        }
        false
    }

    /// Whether any reference of `node` is a sensitive path.
    fn touches(&self, node: Node, sensitive: &HashSet<String>) -> bool {
        self.core
            .node_refs(node)
            .iter()
            .any(|r| sensitive.contains(r))
    }
}

// ---- First pass: the walk ----

impl<'t> Walk<'t> {
    /// Visits every node. Returns false when the time budget ran out.
    fn walk(&mut self, tree: &'t Tree) -> bool {
        let started = Instant::now();
        let mut stack = vec![(tree.root_node(), Scope::default())];
        let mut seen = 0usize;
        while let Some((node, scope)) = stack.pop() {
            seen += 1;
            if seen.is_multiple_of(CHECK_EVERY) && started.elapsed() > PARSE_BUDGET {
                return false;
            }
            self.visit(node, scope, &mut stack);
        }
        true
    }

    /// Pushes the named children of `node` other than comments so they pop
    /// in document order. One cursor serves the whole walk.
    fn push_children(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let start = stack.len();
        let cursor = self.cursor.get_or_insert_with(|| node.walk());
        cursor.reset(node);
        if cursor.goto_first_child() {
            loop {
                let c = cursor.node();
                if c.is_named() && c.kind() != "comment" {
                    stack.push((c, scope));
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        stack[start..].reverse();
    }

    fn visit(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let mut inner = Scope {
            in_literal: false,
            in_cmd: false,
            ..scope
        };
        match node.kind() {
            "comment" | "heredoc_start" | "heredoc_end" => return,
            "variable_name" | "special_variable_name" => {
                self.variable(node, scope);
                return;
            }
            "simple_expansion" | "expansion" => self.expansion(node),
            "word" | "string" | "raw_string" | "concatenation" | "ansi_c_string"
            | "translated_string" => {
                if !scope.in_literal {
                    self.literal(node, scope);
                }
                inner.in_literal = true;
            }
            "variable_assignment" => self.assignment(node),
            "declaration_command" => {
                for c in self.core.children_upto(node, usize::MAX) {
                    if c.kind() == "variable_name" {
                        self.core.not_values.insert(c.start_byte());
                    }
                }
            }
            "for_statement" => self.for_loop(node, scope),
            "command" => return self.command(node, scope, stack),
            // Error recovery can leave a command name outside a command.
            "command_name" if !scope.in_cmd => {
                return self.simple_command(node, Some(node), Vec::new(), &[], scope, stack);
            }
            "ERROR" if self.has_pipe_token(node) => return self.pipeline(node, scope, stack),
            "redirected_statement" => return self.redirected(node, scope, stack),
            "pipeline" => return self.pipeline(node, scope, stack),
            "function_definition" => return self.function(node, scope, stack),
            _ => {}
        }
        self.push_children(node, inner, stack);
    }

    /// A variable reference. Positional parameters (`$1`, `$@`) inside a
    /// function are the function's arguments.
    fn variable(&mut self, node: Node<'t>, scope: Scope) {
        let text = self.text(node);
        let positional = matches!(text, "@" | "*")
            || (text != "0" && !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()));
        let name = if positional {
            match scope.func {
                Some(f) => format!("{}@", self.names[f]),
                None => "@".to_string(),
            }
        } else if node.kind() == "variable_name" {
            text.to_string()
        } else {
            return;
        };
        self.core.token(node, name, true);
    }

    /// `$NAME` and `${NAME…}` of a secret-looking variable is a source.
    fn expansion(&mut self, node: Node<'t>) {
        let var = self
            .core
            .children_upto(node, usize::MAX)
            .into_iter()
            .find(|c| c.kind() == "variable_name");
        let Some(var) = var else { return };
        let name = self.text(var);
        if let Some(class) = env_class(name) {
            let text = format!("${}", clip(name, TEXT_CHARS));
            self.core.add_source(node, class, text, None);
        }
    }

    /// A literal word: a source or sensitive path when its text names one.
    /// `@` and `=` separate a path from a flag (`-d@file`, `--x=file`).
    fn literal(&mut self, node: Node<'t>, scope: Scope) {
        let folded = self.fold(node);
        let text: String = folded
            .chars()
            .map(|c| {
                if matches!(c, '@' | '=' | ',' | '{' | '}' | IFS_SEP) {
                    ' '
                } else {
                    c
                }
            })
            .collect();
        if !may_name_path(&text) {
            return;
        }
        if let Some(class) = literal_source_class(&text) {
            let shown = self.display(node);
            let shown = match scope.cmd {
                Some(c) => format!("{} {shown}", self.names[c]),
                None => shown,
            };
            self.core.add_source(node, class, shown, None);
        }
        if is_sensitive_write_path(&text) {
            self.core.add_sensitive(node);
        }
    }

    fn assignment(&mut self, node: Node<'t>) {
        let Some(mut name) = node.child_by_field_name("name") else {
            return;
        };
        if name.kind() == "subscript" {
            match name.child_by_field_name("name") {
                Some(n) => name = n,
                None => return,
            }
        }
        self.core.not_values.insert(name.start_byte());
        let target = self.text(name).to_string();
        let value = node.child_by_field_name("value");
        if let Some(v) = value {
            // `c=curl`: `$c …` may run curl. Every value is kept.
            let text = self.fold(v);
            let plain = !text.is_empty()
                && !text.contains(['$', UNKNOWN_PIECE])
                && !text.contains(char::is_whitespace);
            if plain {
                let local = format!("${target}");
                self.core.add_alias(&local, program_name(&text), classified);
            }
        }
        self.core.bind(vec![target], value, None, line(node), None);
    }

    /// Name of the variable a word only expands: `$X`, `${X}`, `"$X"`.
    fn expanded_variable(&self, node: Node<'t>) -> Option<String> {
        let mut n = node;
        for _ in 0..4 {
            match n.kind() {
                "simple_expansion" | "expansion" => {
                    let kids = self.core.children_upto(n, usize::MAX);
                    let [var] = kids.as_slice() else {
                        return None;
                    };
                    return (var.kind() == "variable_name").then(|| self.text(*var).to_string());
                }
                "command_name" | "string" => {
                    let kids = self.core.children_upto(n, usize::MAX);
                    let [only] = kids.as_slice() else {
                        return None;
                    };
                    n = *only;
                }
                _ => return None,
            }
        }
        None
    }

    /// `for x in words`: `x` takes every word; without `in`, the arguments.
    fn for_loop(&mut self, node: Node<'t>, scope: Scope) {
        let Some(var) = node.child_by_field_name("variable") else {
            return;
        };
        self.core.not_values.insert(var.start_byte());
        let mut cursor = node.walk();
        let ranges: Vec<(usize, usize)> = node
            .children_by_field_name("value", &mut cursor)
            .map(|v| (v.start_byte(), v.end_byte()))
            .collect();
        let extra = if ranges.is_empty() {
            vec![match scope.func {
                Some(f) => format!("{}@", self.names[f]),
                None => "@".to_string(),
            }]
        } else {
            Vec::new()
        };
        self.core.push_bind(Bind {
            targets: vec![self.text(var).to_string()],
            ranges,
            extra,
            line: line(node),
            rhs_callee: None,
        });
    }

    /// A pipeline: each stage reads the stages before it.
    fn pipeline(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        self.pipes.push(node);
        let stages = self.core.children_upto(node, usize::MAX);
        let mut input = scope.input;
        let mut items = Vec::with_capacity(stages.len());
        for (i, s) in stages.iter().enumerate() {
            if let Some(prev) = i.checked_sub(1).map(|j| stages[j]) {
                let range = vec![(prev.start_byte(), prev.end_byte())];
                input = Some(self.input_bind('|', range, input, line(*s)));
            }
            items.push((
                *s,
                Scope {
                    input,
                    in_literal: false,
                    ..scope
                },
            ));
        }
        stack.extend(items.into_iter().rev());
    }

    /// `name() { body }`: the body's output is the function's output, its
    /// positional parameters and stdin come from the calls.
    fn function(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let (Some(name), Some(body)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("body"),
        ) else {
            return self.push_children(node, scope, stack);
        };
        let fname = self.text(name).to_string();
        self.funcs.insert(fname.clone());
        self.core.bind(
            vec![format!("{fname}()")],
            Some(body),
            None,
            line(node),
            None,
        );
        let input = self.intern(format!("{fname}<"));
        let func = self.intern(fname);
        let inner = Scope {
            input: Some(input),
            func: Some(func),
            cmd: None,
            in_literal: false,
            in_cmd: false,
        };
        stack.push((body, inner));
        for c in self.core.children_upto(node, usize::MAX) {
            if c.id() != name.id() && c.id() != body.id() {
                stack.push((c, scope));
            }
        }
    }

    /// Operator of a file redirection: the text before its destination,
    /// without a descriptor (`2>`, `{fd}<`).
    fn redirect_op(&self, r: Node<'t>, dest: Node<'t>) -> &'t str {
        let text = self.text(r);
        let cut = dest
            .start_byte()
            .saturating_sub(r.start_byte())
            .min(text.len());
        let op = text.get(..cut).unwrap_or("").trim();
        let op = op.trim_start_matches(|c: char| c.is_ascii_digit());
        match op.strip_prefix('{') {
            Some(rest) => rest.split_once('}').map_or(rest, |(_, r)| r),
            None => op,
        }
    }

    /// Records a file redirection on `body`; returns the range it reads
    /// from when it is an input.
    fn file_redirect(
        &mut self,
        r: Node<'t>,
        stmt: Node<'t>,
        body: Option<Node<'t>>,
        input: Option<usize>,
    ) -> Option<(usize, usize)> {
        let dest = r.child_by_field_name("destination")?;
        let op = self.redirect_op(r, dest);
        let reads = op.starts_with('<');
        if !matches!(dest.kind(), "number" | "file_descriptor") {
            self.redirs.push(Redir {
                stmt,
                body,
                dest,
                input,
                output: op.contains('>'),
                read_write: op.contains("<>"),
            });
        }
        reads.then(|| (r.start_byte(), r.end_byte()))
    }

    /// A statement with redirections: input redirections feed the body;
    /// output redirections are checked for sensitive paths and sockets.
    fn redirected(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let body = node.child_by_field_name("body");
        let mut cursor = node.walk();
        let redirects: Vec<Node<'t>> = node
            .children_by_field_name("redirect", &mut cursor)
            .collect();
        let mut inputs = Vec::new();
        let mut files = Vec::new();
        let mut heredoc_rest = Vec::new();
        for r in &redirects {
            match r.kind() {
                "file_redirect" => files.push(*r),
                "herestring_redirect" => inputs.push((r.start_byte(), r.end_byte())),
                "heredoc_redirect" => {
                    for c in self.core.children_upto(*r, usize::MAX) {
                        match c.kind() {
                            "heredoc_body" => inputs.push((c.start_byte(), c.end_byte())),
                            "file_redirect" => files.push(c),
                            "heredoc_start" | "heredoc_end" => {}
                            _ => heredoc_rest.push(c),
                        }
                    }
                }
                _ => {}
            }
        }
        // Redirections apply in order; record outputs with the body input
        // decided below, so collect inputs first.
        let mut outputs = Vec::new();
        for f in files {
            let before = self.redirs.len();
            if let Some(range) = self.file_redirect(f, node, body, None) {
                inputs.push(range);
            }
            outputs.extend(before..self.redirs.len());
        }
        let line = line(node);
        let body_input = if inputs.is_empty() {
            scope.input
        } else {
            Some(self.input_bind('<', inputs, scope.input, line))
        };
        for i in outputs {
            self.redirs[i].input = body_input;
        }
        let outer = Scope {
            in_literal: false,
            ..scope
        };
        // What follows `<<EOF` on its line (`| curl …`) reads the body.
        let piped = match (body, heredoc_rest.is_empty()) {
            (Some(b), false) => {
                let range = vec![(b.start_byte(), b.end_byte())];
                Some(self.input_bind('|', range, body_input, line))
            }
            _ => None,
        };
        for c in heredoc_rest.into_iter().rev() {
            let input = piped.filter(|_| c.kind() == "pipeline").or(scope.input);
            stack.push((c, Scope { input, ..outer }));
        }
        if let Some(b) = body {
            let inner = Scope {
                input: body_input,
                ..outer
            };
            stack.push((b, inner));
        }
        for r in redirects.into_iter().rev() {
            if r.kind() == "heredoc_redirect" {
                for c in self.core.children_upto(r, usize::MAX) {
                    if matches!(c.kind(), "file_redirect" | "heredoc_body") {
                        stack.push((c, outer));
                    }
                }
            } else {
                stack.push((r, outer));
            }
        }
    }
}

/// Options of `xargs` that take the next word as a value.
const XARGS_VALUE_OPTIONS: &[&str] = &["-I", "-d", "-E", "-L", "-n", "-P", "-s", "-a"];

/// Index of the command `xargs` runs, given the index just past `xargs`.
fn skip_xargs(words: &[&str], mut i: usize) -> usize {
    while let Some(w) = words.get(i) {
        if *w == "--" {
            return i + 1;
        }
        if !w.starts_with('-') {
            break;
        }
        if XARGS_VALUE_OPTIONS.contains(w) {
            i += 1;
        }
        i += 1;
    }
    i.min(words.len())
}

/// Whether an `nc`/`ncat` argument runs a program for the peer.
fn nc_runs_program(arg: &str) -> bool {
    if ["--exec", "--sh-exec", "--lua-exec"]
        .iter()
        .any(|o| arg.starts_with(o))
    {
        return true;
    }
    arg.strip_prefix('-').is_some_and(|rest| {
        !rest.starts_with('-')
            && rest.bytes().all(|b| b.is_ascii_alphanumeric())
            && rest.contains(['e', 'c'])
    })
}

/// Interpreters and the flags that make them run their next word as code.
fn code_flags(prog: &str) -> Option<&'static [&'static str]> {
    let python = prog
        .strip_prefix("python")
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    Some(match prog {
        "perl" | "ruby" => &["-e", "-E"],
        "node" | "nodejs" => &["-e", "--eval", "-p", "--print"],
        "php" => &["-r"],
        "lua" => &["-e"],
        _ if python => &["-c"],
        _ => return None,
    })
}

/// Whether `classify` gives a program a meaning.
fn classified(prog: &str) -> bool {
    matches!(
        prog,
        "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "netcat"
            | "socat"
            | "telnet"
            | "openssl"
            | "ssh"
            | "sftp"
            | "ftp"
            | "scp"
            | "rsync"
            | "cp"
            | "mv"
            | "install"
            | "ln"
            | "tee"
            | "sed"
            | "dd"
            | "crontab"
            | "eval"
            | "source"
            | "."
            | "powershell"
            | "pwsh"
            | "cmd"
            | "sudo"
            | "doas"
            | "env"
            | "xargs"
            | "nohup"
    ) || is_posix_shell(prog)
        || code_flags(prog).is_some()
}

fn is_option(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-')
}

/// The destination of `cp`/`mv`/`install`/`ln`: `-t DIR`,
/// `--target-directory=DIR`, else the last of two or more operands.
fn copy_target<'t>(rest: &[(Node<'t>, String)]) -> Vec<Node<'t>> {
    let mut operands = Vec::new();
    let mut i = 0;
    while let Some((n, t)) = rest.get(i) {
        if t == "-t" {
            return rest.get(i + 1).map(|(n, _)| *n).into_iter().collect();
        }
        if t.starts_with("--target-directory") {
            return vec![*n];
        }
        if !is_option(t) {
            operands.push(*n);
        }
        i += 1;
    }
    if operands.len() >= 2 {
        operands.pop().into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Operand words (not options) of a command.
fn operands<'t>(rest: &[(Node<'t>, String)]) -> Vec<Node<'t>> {
    rest.iter()
        .filter(|(_, t)| !is_option(t))
        .map(|(n, _)| *n)
        .collect()
}

impl<'t> Walk<'t> {
    /// A simple command: classifies its program and records bindings.
    fn command(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let mut name = None;
        let mut args = Vec::new();
        let mut redirects = Vec::new();
        let cursor = self.cursor.get_or_insert_with(|| node.walk());
        cursor.reset(node);
        if cursor.goto_first_child() {
            loop {
                match cursor.field_name() {
                    Some("name") => name = Some(cursor.node()),
                    Some("argument") => args.push(cursor.node()),
                    Some("redirect") => redirects.push(cursor.node()),
                    _ => {}
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        self.simple_command(node, name, args, &redirects, scope, stack);
    }

    /// Whether a node has a `|` or `|&` token among its children: error
    /// recovery can leave a pipeline without a pipeline node.
    fn has_pipe_token(&mut self, node: Node<'t>) -> bool {
        let cursor = self.cursor.get_or_insert_with(|| node.walk());
        cursor.reset(node);
        if !cursor.goto_first_child() {
            return false;
        }
        loop {
            if matches!(cursor.node().kind(), "|" | "|&") {
                return true;
            }
            if !cursor.goto_next_sibling() {
                return false;
            }
        }
    }

    /// A command given as its name and argument nodes. `node` is the
    /// command, or a lone command name that error recovery left behind.
    fn simple_command(
        &mut self,
        node: Node<'t>,
        name: Option<Node<'t>>,
        args: Vec<Node<'t>>,
        redirects: &[Node<'t>],
        scope: Scope,
        stack: &mut Vec<(Node<'t>, Scope)>,
    ) {
        let mut words: Vec<(Node<'t>, String)> = Vec::new();
        let mut name_split = false;
        for (i, n) in name.into_iter().chain(args).enumerate() {
            let folded = self.fold(n);
            let parts = self.split_word(n, &folded);
            if i == 0 && name.is_some() && parts.len() != 1 {
                name_split = true;
            }
            if parts.is_empty() {
                words.push((n, folded));
            } else {
                words.extend(parts.into_iter().map(|p| (n, p)));
            }
        }
        let texts: Vec<&str> = words.iter().map(|(_, t)| t.as_str()).collect();
        let mut idx = program_index(&texts);
        let mut stdin_args = false;
        if texts.get(idx).is_some_and(|t| program_name(t) == "xargs") {
            idx = skip_xargs(&texts, idx + 1);
            idx += program_index(&texts[idx..]);
            stdin_args = true;
        }
        let exec = texts.first().is_some_and(|t| program_name(t) == "exec");
        let dynamic = words.get(idx).is_some_and(|(n, _)| self.is_dynamic(*n));
        let word = words.get(idx).filter(|_| !dynamic).map(|(_, t)| t.clone());
        let prog = word.as_deref().map(program_name);

        let id = self.core.fresh_id('c');
        self.core.token(node, id.clone(), false);

        let mut own_input = false;
        for r in redirects {
            match r.kind() {
                "herestring_redirect" => own_input = true,
                "file_redirect" => {
                    let reads = self.file_redirect(*r, node, Some(node), scope.input);
                    own_input |= reads.is_some();
                }
                _ => {}
            }
        }
        let mut cmd = Cmd {
            node,
            id: id.clone(),
            token: id,
            word,
            exec,
            class: None,
            reads_input: stdin_args,
            input: scope.input,
            writes: Vec::new(),
            always_write: false,
            fetch_pipe: false,
            shell_reader: false,
            socket: false,
            code: Code::None,
            exclude: Vec::new(),
        };
        if dynamic && let Some((n, _)) = words.get(idx) {
            // A computed program runs its own name: `$(curl …)`, `$X`.
            cmd.class = Some(EXEC);
            cmd.code = Code::Nodes(vec![*n]);
        }
        let has_input = scope.input.is_some() || stdin_args || own_input;
        let rest = words.get(idx + 1..).unwrap_or_default();
        if let Some(p) = prog.as_deref() {
            self.classify(&mut cmd, p, rest, has_input);
        }
        let env_dump = match prog.as_deref() {
            None => idx == words.len() && texts.first().is_some_and(|t| program_name(t) == "env"),
            Some("printenv") => {
                let names = operands(rest);
                names.is_empty()
                    || rest
                        .iter()
                        .any(|(_, t)| !is_option(t) && env_class(t).is_some())
            }
            Some("set") => rest.is_empty(),
            _ => false,
        };
        if env_dump {
            let text = self.display(node);
            self.core
                .add_source(node, SECRET_ENV, text, Some(cmd.id.clone()));
        }
        // `$X args` where X holds a program name: classified once every
        // assignment is known.
        if let Some(var) = words
            .get(idx)
            .filter(|_| dynamic)
            .and_then(|(n, _)| self.expanded_variable(*n))
        {
            self.dynamic.push(Dynamic {
                cmd: self.cmds.len(),
                var,
                rest: rest.to_vec(),
                has_input,
            });
        }
        self.cmds.push(cmd);

        let shown = prog.map(|p| self.intern(p));
        let inner = Scope {
            cmd: shown.or(scope.cmd),
            in_literal: false,
            in_cmd: true,
            ..scope
        };
        let start = stack.len();
        self.push_children(node, inner, stack);
        // The program word is not a path literal, unless it held several
        // words (`{curl,-d,@file}`, `curl${IFS}-d…`).
        for entry in &mut stack[start..] {
            let whole_name = name.is_some_and(|n| n.id() == node.id());
            if whole_name || name.is_some_and(|n| n.id() == entry.0.id()) {
                entry.1.in_literal = !name_split;
            }
        }
    }

    /// Sets the class, inputs and written paths of a command running `prog`
    /// with argument words `rest`.
    fn classify(
        &mut self,
        cmd: &mut Cmd<'t>,
        prog: &str,
        rest: &[(Node<'t>, String)],
        has_input: bool,
    ) {
        let texts: Vec<&str> = rest.iter().map(|(_, t)| t.as_str()).collect();
        let any = |f: &dyn Fn(&str) -> bool| texts.iter().any(|t| f(t));
        match prog {
            "curl" => {
                cmd.class = Some(NETWORK);
                cmd.reads_input |=
                    any(&|t| t.ends_with("@-") || t == "-" || t.contains("/dev/stdin"));
                cmd.exclude = credential_options(prog, rest);
            }
            "wget" => {
                cmd.class = Some(NETWORK);
                cmd.reads_input |= any(&|t| t.ends_with("=-") || t.contains("/dev/stdin"));
                cmd.exclude = credential_options(prog, rest);
            }
            "nc" | "ncat" | "netcat" | "socat" | "telnet" => {
                let runs = match prog {
                    "socat" => any(&|t| {
                        let l = t.to_ascii_lowercase();
                        l.contains("exec:") || l.contains("system:")
                    }),
                    "telnet" => false,
                    _ => any(&nc_runs_program),
                };
                cmd.socket = true;
                cmd.class = Some(if runs { REVERSE_SHELL } else { NETWORK });
                cmd.reads_input = true;
            }
            "openssl" if texts.first() == Some(&"s_client") => {
                cmd.socket = true;
                cmd.class = Some(NETWORK);
                cmd.reads_input = true;
            }
            "ssh" | "sftp" | "ftp" => {
                cmd.class = Some(NETWORK);
                cmd.reads_input = true;
                cmd.exclude = credential_options(prog, rest);
            }
            "scp" => {
                cmd.class = Some(NETWORK);
                cmd.exclude = credential_options(prog, rest);
            }
            "rsync" if any(&|t| !is_option(t) && t.contains(':')) => {
                cmd.class = Some(NETWORK);
                cmd.exclude = credential_options(prog, rest);
            }
            "cp" | "mv" | "install" | "ln" | "rsync" => cmd.writes = copy_target(rest),
            "tee" => {
                cmd.writes = operands(rest);
                cmd.reads_input = true;
            }
            "sed"
                if any(&|t| {
                    t.starts_with("--in-place")
                        || (is_option(t) && !t.starts_with("--") && t.contains('i'))
                }) =>
            {
                cmd.writes = operands(rest);
            }
            "dd" => {
                cmd.writes = rest
                    .iter()
                    .filter(|(_, t)| t.starts_with("of="))
                    .map(|(n, _)| *n)
                    .collect();
                cmd.reads_input = true;
            }
            "crontab" => {
                let mut i = 0;
                while let Some(t) = texts.get(i) {
                    if *t == "-u" {
                        i += 2;
                        continue;
                    }
                    if *t == "-" || !is_option(t) {
                        cmd.always_write = true;
                        cmd.reads_input = true;
                        break;
                    }
                    i += 1;
                }
            }
            "eval" => {
                cmd.class = Some(EVAL);
                cmd.code = Code::All;
                cmd.fetch_pipe = pipes_download_to_shell(&spaced(&texts.join(" ")));
            }
            "source" | "." => {
                if let Some((n, t)) = rest.first() {
                    let stdin = t == "/dev/stdin" || t == "-";
                    if stdin || self.has_substitution(*n) {
                        cmd.class = Some(EVAL);
                        cmd.reads_input = stdin;
                        cmd.code = if stdin {
                            Code::Input
                        } else {
                            Code::Nodes(vec![*n])
                        };
                    }
                }
            }
            "powershell" | "pwsh" | "cmd" => {
                if let Some(class) = invocation_class(prog, &texts) {
                    cmd.class = Some(class);
                }
            }
            "security"
                if matches!(
                    texts.first().copied(),
                    Some("find-generic-password" | "find-internet-password" | "dump-keychain")
                ) =>
            {
                self.keychain(cmd);
            }
            "secret-tool" if texts.first() == Some(&"lookup") => self.keychain(cmd),
            "read" => self.read_bind(cmd, "adinNptu", "REPLY", false),
            "mapfile" | "readarray" => self.read_bind(cmd, "dnOsuCc", "MAPFILE", true),
            "printf" => {
                let target = texts
                    .iter()
                    .position(|t| *t == "-v")
                    .and_then(|i| texts.get(i + 1));
                if let Some(target) = target {
                    let extra = self.input_names(cmd.input);
                    self.core.push_bind(Bind {
                        targets: vec![(*target).to_string()],
                        ranges: vec![(cmd.node.start_byte(), cmd.node.end_byte())],
                        extra,
                        line: line(cmd.node),
                        rhs_callee: None,
                    });
                }
            }
            _ if is_posix_shell(prog) => self.shell(cmd, rest, has_input),
            _ => {
                if let Some(flags) = code_flags(prog) {
                    self.interpreter(cmd, flags, rest, has_input);
                }
            }
        }
    }

    fn keychain(&mut self, cmd: &Cmd<'t>) {
        let text = self.display(cmd.node);
        self.core
            .add_source(cmd.node, KEYCHAIN, text, Some(cmd.id.clone()));
    }

    /// Code word of `-c CODE`: only a word that is wholly an expansion or
    /// substitution counts as fetched code; one interpolated into a larger
    /// literal (`-c "print('$V')"`) does not.
    fn code_word(&self, word: Option<&(Node<'t>, String)>) -> Code<'t> {
        match word {
            Some((n, _)) if self.is_dynamic(*n) => Code::Nodes(vec![*n]),
            _ => Code::None,
        }
    }

    /// A shell: `-c` runs its next word; with no script (or `-s`) it runs
    /// what it reads on stdin; a substitution as the script runs its output.
    fn shell(&self, cmd: &mut Cmd<'t>, rest: &[(Node<'t>, String)], has_input: bool) {
        let mut i = 0;
        let mut stdin = false;
        let mut script = None;
        while let Some((n, t)) = rest.get(i) {
            if t == "--" {
                script = rest.get(i + 1).map(|(n, t)| (*n, t.as_str()));
                break;
            }
            if is_shell_flag(t) {
                cmd.class = Some(EXEC);
                cmd.code = self.code_word(rest.get(i + 1));
                cmd.fetch_pipe = rest
                    .get(i + 1)
                    .is_some_and(|(_, code)| pipes_download_to_shell(&spaced(code)));
                return;
            }
            if is_option(t) || (t.len() > 1 && t.starts_with('+')) {
                if matches!(
                    t.as_str(),
                    "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file"
                ) {
                    i += 1;
                }
                stdin |= t.starts_with('-') && !t.starts_with("--") && t.contains('s');
                i += 1;
                continue;
            }
            script = Some((*n, t.as_str()));
            break;
        }
        let reads_stdin = match script {
            None | Some((_, "/dev/stdin" | "-")) => true,
            Some((n, _)) if self.has_substitution(n) => {
                cmd.class = Some(EXEC);
                cmd.code = Code::Nodes(vec![n]);
                return;
            }
            Some(_) => stdin,
        };
        if reads_stdin {
            cmd.shell_reader = true;
            if has_input {
                cmd.class = Some(EXEC);
                cmd.reads_input = true;
                cmd.code = Code::Input;
            }
        }
    }

    /// An interpreter: a code flag runs its next word; with no script or
    /// `-` it runs what it reads on stdin.
    fn interpreter(
        &self,
        cmd: &mut Cmd<'t>,
        flags: &[&str],
        rest: &[(Node<'t>, String)],
        has_input: bool,
    ) {
        if let Some(i) = rest.iter().position(|(_, t)| flags.contains(&t.as_str())) {
            cmd.class = Some(EXEC);
            cmd.code = self.code_word(rest.get(i + 1));
            return;
        }
        if rest.iter().any(|(_, t)| t == "-m") {
            return;
        }
        let script = rest.iter().find(|(_, t)| !is_option(t));
        if script.is_none_or(|(_, t)| t == "-") && has_input {
            cmd.class = Some(EXEC);
            cmd.reads_input = true;
            cmd.code = Code::Input;
        }
    }

    /// `read`, `mapfile`: the named variables take what stdin and any
    /// here-string carry. Arguments go through the capped child list.
    fn read_bind(&mut self, cmd: &Cmd<'t>, value_opts: &str, default: &str, single: bool) {
        let args: Vec<String> = self
            .core
            .children(cmd.node)
            .into_iter()
            .filter(|k| {
                !matches!(
                    k.kind(),
                    "command_name"
                        | "variable_assignment"
                        | "file_redirect"
                        | "herestring_redirect"
                )
            })
            .map(|k| self.fold(k))
            .collect();
        let mut targets = Vec::new();
        let mut i = 0;
        let mut options = true;
        while let Some(t) = args.get(i) {
            i += 1;
            if options && t == "--" {
                options = false;
                continue;
            }
            if options && is_option(t) {
                if let Some(c) = t.chars().last().filter(|c| value_opts.contains(*c)) {
                    if c == 'a' {
                        targets.extend(args.get(i).cloned());
                    }
                    i += 1;
                }
                continue;
            }
            targets.push(t.clone());
            if single {
                break;
            }
        }
        if targets.is_empty() {
            targets.push(default.to_string());
        }
        targets.retain(|t| !t.contains(['$', UNKNOWN_PIECE]));
        let extra = self.input_names(cmd.input);
        self.core.push_bind(Bind {
            targets,
            ranges: vec![(cmd.node.start_byte(), cmd.node.end_byte())],
            extra,
            line: line(cmd.node),
            rhs_callee: None,
        });
    }
}

// ---- Second pass ----

impl<'t> Walk<'t> {
    fn site(
        &self,
        id: String,
        class: &str,
        shown: Node,
        refs_of: Node,
        input: Option<usize>,
    ) -> Site {
        let mut args_refs = self.core.node_refs(refs_of);
        args_refs.extend(self.input_names(input));
        Site {
            id,
            class: class.to_string(),
            line: line(shown),
            args_refs,
            text: self.display(shown),
        }
    }

    /// References inside `node` outside the `exclude` nodes.
    fn refs_except(&self, node: Node, exclude: &[Node]) -> Vec<String> {
        let mut cuts: Vec<(usize, usize)> = exclude
            .iter()
            .map(|n| (n.start_byte(), n.end_byte()))
            .collect();
        cuts.sort_unstable();
        let mut ranges = Vec::new();
        let mut at = node.start_byte();
        for (s, e) in cuts {
            if s > at {
                ranges.push((at, s));
            }
            at = at.max(e);
        }
        if at < node.end_byte() {
            ranges.push((at, node.end_byte()));
        }
        self.core.refs(&ranges)
    }

    /// The sink of a command meaning. Its own output is not its input.
    fn cmd_site(&self, c: &Cmd<'t>, class: &str) -> Site {
        let mut args_refs = if class == NETWORK && !c.exclude.is_empty() {
            self.refs_except(c.node, &c.exclude)
        } else {
            self.core.node_refs(c.node)
        };
        args_refs.retain(|r| *r != c.token);
        if c.reads_input {
            args_refs.extend(self.input_names(c.input));
        }
        Site {
            id: c.id.clone(),
            class: class.to_string(),
            line: line(c.node),
            args_refs,
            text: self.display(c.node),
        }
    }

    /// References an `exec` or `eval` sink runs as code.
    fn code_of(&self, c: &Cmd<'t>) -> Vec<String> {
        let mut refs = match &c.code {
            Code::None => Vec::new(),
            Code::Input => self.input_names(c.input),
            Code::All => self.core.node_refs(c.node),
            Code::Nodes(nodes) => nodes.iter().flat_map(|n| self.core.node_refs(*n)).collect(),
        };
        refs.retain(|r| *r != c.token);
        refs
    }

    /// The command recorded for `node`. Commands are sorted by start byte.
    fn cmd_at(&self, node: Node) -> Option<&Cmd<'t>> {
        let from = self
            .cmds
            .partition_point(|c| c.node.start_byte() < node.start_byte());
        self.cmds[from..]
            .iter()
            .take_while(|c| c.node.start_byte() == node.start_byte())
            .find(|c| c.node.id() == node.id())
    }

    /// Commands of a pipeline's stages in order, with nested pipelines (as
    /// in `a | b 2>&1 | c`) flattened. Their ids go into `flat`. `pipe` may
    /// be an error node holding a pipeline's stages.
    fn stage_cmds(&self, pipe: Node<'t>, flat: &mut HashSet<usize>) -> Vec<Option<&Cmd<'t>>> {
        let mut out = Vec::new();
        flat.insert(pipe.id());
        let mut stack: Vec<Node<'t>> = self
            .core
            .children_upto(pipe, usize::MAX)
            .into_iter()
            .rev()
            .collect();
        while let Some(n) = stack.pop() {
            match n.kind() {
                "pipeline" => {
                    flat.insert(n.id());
                    stack.extend(self.core.children_upto(n, usize::MAX).into_iter().rev());
                }
                "redirected_statement" => stack.extend(n.child_by_field_name("body")),
                "command" | "command_name" => out.push(self.cmd_at(n)),
                _ => out.push(None),
            }
        }
        out
    }

    /// Sinks of a redirection: a socket path, or a sensitive file written.
    fn redirect_sink(&mut self, i: usize, sensitive: &HashSet<String>) -> Option<Site> {
        let r = &self.redirs[i];
        let dest = self.fold(r.dest);
        let class = if dest.contains("/dev/tcp/") || dest.contains("/dev/udp/") {
            let shell = r
                .body
                .and_then(|b| self.cmd_at(b))
                .is_some_and(|c| c.exec || c.shell_reader);
            if shell || r.read_write {
                REVERSE_SHELL
            } else {
                NETWORK
            }
        } else if r.output && self.touches(r.dest, sensitive) {
            SENSITIVE_WRITE
        } else {
            return None;
        };
        let (stmt, refs_of, input) = (r.stmt, r.body.unwrap_or(r.stmt), r.input);
        let id = self.core.fresh_id('r');
        Some(self.site(id, class, stmt, refs_of, input))
    }

    fn sinks(&mut self, sensitive: &HashSet<String>) -> Vec<Site> {
        let mut out = Vec::new();
        let mut code_refs = BTreeMap::new();
        for c in self.cmds.iter().chain(&self.extra) {
            let class = if c.fetch_pipe {
                Some(DOWNLOAD_EXEC)
            } else if c.class.is_some() {
                c.class
            } else if c.always_write || c.writes.iter().any(|w| self.touches(*w, sensitive)) {
                Some(SENSITIVE_WRITE)
            } else {
                None
            };
            let Some(class) = class else { continue };
            let site = self.cmd_site(c, class);
            if matches!(class, EXEC | EVAL) {
                code_refs.insert(site.id.clone(), self.code_of(c));
            }
            self.core.push_sink(&mut out, || site);
        }
        self.code_refs = code_refs;
        for i in 0..self.redirs.len() {
            if let Some(site) = self.redirect_sink(i, sensitive) {
                self.core.push_sink(&mut out, || site);
            }
        }
        let mut flat = HashSet::new();
        for i in 0..self.pipes.len() {
            let p = self.pipes[i];
            if flat.contains(&p.id()) {
                continue;
            }
            let stages = self.stage_cmds(p, &mut flat);
            let shell = stages
                .iter()
                .position(|c| c.is_some_and(|c| c.shell_reader));
            let socket = stages.iter().rposition(|c| c.is_some_and(|c| c.socket));
            if let (Some(s), Some(k)) = (shell, socket)
                && k > s
            {
                let id = self.core.fresh_id('r');
                let site = self.site(id, REVERSE_SHELL, p, p, None);
                self.core.push_sink(&mut out, || site);
            }
        }
        out
    }

    /// Classifies `$c args` as every program `c` was assigned. The command
    /// stays an `exec` of a computed program, and each meaning the rules
    /// classify adds its own sink. A wrapper meaning (`sudo`, `env`,
    /// `xargs`) is classified as the program it runs.
    fn resolve_dynamic(&mut self) {
        for d in std::mem::take(&mut self.dynamic) {
            let local = format!("${}", d.var);
            let mut network_seen = false;
            for meaning in self.core.resolutions(&local) {
                if meaning == local {
                    continue;
                }
                let mut texts: Vec<&str> = vec![meaning.as_str()];
                texts.extend(d.rest.iter().map(|(_, t)| t.as_str()));
                let mut idx = program_index(&texts);
                let mut stdin_args = false;
                if texts.get(idx).is_some_and(|t| program_name(t) == "xargs") {
                    idx = skip_xargs(&texts, idx + 1);
                    idx += program_index(&texts[idx..]);
                    stdin_args = true;
                }
                let Some(prog) = texts.get(idx).map(|t| program_name(t)) else {
                    continue;
                };
                // The program after a wrapper is word `idx - 1` of the rest.
                let computed = idx
                    .checked_sub(1)
                    .and_then(|i| d.rest.get(i))
                    .is_some_and(|(n, _)| self.is_dynamic(*n));
                if computed {
                    continue;
                }
                let rest = d.rest.get(idx..).unwrap_or_default();
                let base = &self.cmds[d.cmd];
                let mut probe = Cmd {
                    id: String::new(),
                    class: None,
                    reads_input: base.reads_input || stdin_args,
                    writes: Vec::new(),
                    always_write: false,
                    fetch_pipe: false,
                    shell_reader: false,
                    socket: false,
                    code: Code::None,
                    exclude: Vec::new(),
                    ..base.clone()
                };
                probe.id = self.core.fresh_id('c');
                self.classify(&mut probe, &prog, rest, d.has_input || stdin_args);
                if probe.class.is_none() && !probe.always_write && probe.writes.is_empty() {
                    continue;
                }
                // Later stages read the command's output through its token:
                // a network meaning takes the token's id.
                if probe.class == Some(NETWORK) && !network_seen {
                    network_seen = true;
                    probe.id = probe.token.clone();
                    self.cmds[d.cmd].id = self.core.fresh_id('c');
                }
                self.extra.push(probe);
            }
        }
    }

    /// Second pass: calls of functions defined in the file, references and
    /// the final facts.
    fn finish(mut self) -> Facts {
        self.resolve_dynamic();
        self.cmds.sort_by_key(|c| c.node.start_byte());
        for i in 0..self.cmds.len() {
            let c = &self.cmds[i];
            let Some(word) = c.word.as_deref().filter(|w| self.funcs.contains(*w)) else {
                continue;
            };
            let (node, input, word) = (c.node, c.input, word.to_string());
            self.core.token(node, format!("{word}()"), false);
            let extra = self.input_names(input);
            self.core.push_bind(Bind {
                targets: vec![format!("{word}@"), format!("{word}<")],
                ranges: vec![(node.start_byte(), node.end_byte())],
                extra,
                line: line(node),
                rhs_callee: None,
            });
        }
        self.core.index_tokens();
        let network: Vec<String> = self
            .cmds
            .iter()
            .chain(&self.extra)
            .filter(|c| c.class == Some(NETWORK))
            .map(|c| c.id.clone())
            .collect();
        self.core.set_interesting(network);
        let assigns = self.core.assigns();
        let sensitive = self.core.sensitive_reach(&assigns);
        let sinks = self.sinks(&sensitive);
        let mut facts = self.core.into_facts(sinks, assigns);
        facts.code_refs = self.code_refs;
        facts
    }
}

/// Backslash escapes of an unquoted word removed (`cu\rl` is `curl`).
fn unescape_word(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
        } else if let Some(next) = chars.next().filter(|n| *n != '\n') {
            out.push(next);
        }
    }
    out
}

/// Text of an ANSI-C quoted string (`$'…'`) with its escapes decoded.
fn decode_ansi_c(text: &str) -> String {
    let b = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    // Up to `max` digits of `radix` from position `i`.
    let digits = |i: usize, max: usize, radix: u32| -> (u32, usize) {
        let mut value = 0u32;
        let mut n = 0;
        while n < max {
            match b.get(i + n).and_then(|c| char::from(*c).to_digit(radix)) {
                Some(d) => value = value * radix + d,
                None => break,
            }
            n += 1;
        }
        (value, n)
    };
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let c = b[i + 1];
        i += 2;
        let simple = match c {
            b'n' => Some(b'\n'),
            b't' => Some(b'\t'),
            b'r' => Some(b'\r'),
            b'a' => Some(7),
            b'b' => Some(8),
            b'e' | b'E' => Some(27),
            b'f' => Some(12),
            b'v' => Some(11),
            b'\\' | b'\'' | b'"' | b'?' => Some(c),
            _ => None,
        };
        if let Some(byte) = simple {
            out.push(byte);
            continue;
        }
        let (value, used, unicode) = match c {
            b'x' => {
                let (v, n) = digits(i, 2, 16);
                (v, n, false)
            }
            b'u' => {
                let (v, n) = digits(i, 4, 16);
                (v, n, true)
            }
            b'U' => {
                let (v, n) = digits(i, 8, 16);
                (v, n, true)
            }
            b'0'..=b'7' => {
                let (v, n) = digits(i - 1, 3, 8);
                (v, n.saturating_sub(1), false)
            }
            b'c' if i < b.len() => {
                out.push(b[i] & 0x1f);
                i += 1;
                continue;
            }
            _ => {
                out.extend([b'\\', c]);
                continue;
            }
        };
        if used == 0 && matches!(c, b'x' | b'u' | b'U') {
            out.extend([b'\\', c]);
            continue;
        }
        i += used;
        if unicode {
            let ch = char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER);
            out.extend(ch.to_string().as_bytes());
        } else {
            out.push((value & 0xff) as u8);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Text with `$IFS` separators as spaces, for command-text checks.
fn spaced(text: &str) -> String {
    text.replace(IFS_SEP, " ")
}

/// Arguments of a network client that name the key, certificate or netrc
/// file it authenticates with: read locally, not sent. A value shared with
/// other words (after `$IFS` or brace splitting) is kept.
fn credential_options<'t>(prog: &str, rest: &[(Node<'t>, String)]) -> Vec<Node<'t>> {
    let with_value: &[&str] = match prog {
        "ssh" | "scp" | "sftp" => &["-i", "-F"],
        "rsync" => &["-e", "--rsh"],
        "curl" => &[
            "--netrc-file",
            "--cacert",
            "--capath",
            "--cert",
            "--key",
            "-E",
            "--proxy-cacert",
            "--proxy-cert",
            "--proxy-key",
        ],
        "wget" => &["--certificate", "--private-key", "--ca-certificate"],
        _ => return Vec::new(),
    };
    let ssh = matches!(prog, "ssh" | "scp" | "sftp");
    let identity = |v: &str| {
        let v = v.to_ascii_lowercase();
        v.starts_with("identityfile") || v.starts_with("certificatefile")
    };
    let mut picked = Vec::new();
    let mut i = 0;
    while let Some((n, t)) = rest.get(i) {
        let value = rest.get(i + 1);
        if with_value.contains(&t.as_str())
            || (ssh && t == "-o" && value.is_some_and(|v| identity(&v.1)))
        {
            picked.extend(value.map(|(v, _)| *v));
            i += 2;
            continue;
        }
        let attached = with_value.iter().any(|o| {
            t.len() > o.len() && t.starts_with(o) && (o.len() == 2 || t.as_bytes()[o.len()] == b'=')
        });
        if attached || (ssh && t.strip_prefix("-o").is_some_and(identity)) {
            picked.push(*n);
        }
        i += 1;
    }
    picked.retain(|p| rest.iter().filter(|(n, _)| n.id() == p.id()).count() == 1);
    picked
}
