//! PowerShell facts from a tree-sitter-powershell tree.
//!
//! One walk over the tree records variable references, literals, commands,
//! method calls, bindings and what each pipeline stage reads; a second step
//! resolves aliases and client objects, classifies sites and resolves
//! references.
//!
//! Command names, parameters, variables and type names are compared without
//! case, as PowerShell does.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use tree_sitter::{Language, Node, Tree, TreeCursor};

use super::common::{Bind, Core, MAX_NAME_SEGMENTS, TEXT_CHARS, line};
use super::patterns::{
    DOWNLOAD_EXEC, EVAL, EXEC, KEYCHAIN, NETWORK, REVERSE_SHELL, SECRET_ENV, SENSITIVE_WRITE,
    UNKNOWN_PIECE, env_class, is_sensitive_write_path, is_shell_flag, literal_source_class,
    pipes_download_to_shell, program_name,
};
use super::taint::{Facts, Site};
use super::{LangRules, PARSE_BUDGET, clip};

/// Nodes visited between time checks.
const CHECK_EVERY: usize = 4_096;

/// Types whose instances are network clients: after `$c = New-Object T`,
/// `$c.M(...)` resolves to `t().m(...)`. A stream taken from a TCP client is
/// one too. Responses are not clients.
const CLIENT_CONSTRUCTORS: &[&str] = &[
    "net.webclient",
    "net.http.httpclient",
    "net.sockets.tcpclient",
    "net.sockets.udpclient",
    "net.sockets.socket",
    "net.sockets.tcpclient().getstream",
];

/// Built-in aliases (and Windows PowerShell's `curl`/`wget`) and the
/// commands they stand for.
const BUILTIN_ALIASES: &[(&str, &str)] = &[
    ("iex", "invoke-expression"),
    ("iwr", "invoke-webrequest"),
    ("curl", "invoke-webrequest"),
    ("wget", "invoke-webrequest"),
    ("irm", "invoke-restmethod"),
    ("gc", "get-content"),
    ("cat", "get-content"),
    ("type", "get-content"),
    ("saps", "start-process"),
    ("start", "start-process"),
    ("ac", "add-content"),
    ("sc", "set-content"),
    ("sp", "set-itemproperty"),
    ("ni", "new-item"),
    ("cp", "copy-item"),
    ("copy", "copy-item"),
    ("cpi", "copy-item"),
    ("mv", "move-item"),
    ("move", "move-item"),
    ("mi", "move-item"),
    ("tee", "tee-object"),
    ("icm", "invoke-command"),
    ("%", "foreach-object"),
    ("foreach", "foreach-object"),
    ("?", "where-object"),
    ("where", "where-object"),
    ("sal", "set-alias"),
    ("nal", "new-alias"),
    ("sv", "set-variable"),
    ("set", "set-variable"),
    ("nv", "new-variable"),
    ("gi", "get-item"),
];

const NETWORK_COMMANDS: &[&str] = &[
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "send-mailmessage",
];

const SHELL_PROGRAMS: &[&str] = &["powershell", "pwsh", "cmd", "bash", "sh", "wsl"];

/// Parameters that never take a value, so the next element is positional.
const SWITCHES: &[&str] = &[
    "append",
    "force",
    "nonewline",
    "passthru",
    "usebasicparsing",
    "wait",
    "nonewwindow",
    "recurse",
    "raw",
    "noprofile",
    "noninteractive",
    "nologo",
    "disablekeepalive",
    "skipcertificatecheck",
    "asjob",
    "whatif",
    "confirm",
    "verbose",
    "debug",
    "asbytestream",
    "noclobber",
];

/// Rules for PowerShell scripts.
pub struct PowerShellRules;

impl LangRules for PowerShellRules {
    fn language(&self) -> Language {
        tree_sitter_powershell::LANGUAGE.into()
    }

    fn facts(&self, tree: &Tree, src: &str) -> Facts {
        let mut w = Walk::new(src.as_bytes());
        let complete = w.walk(tree);
        let mut facts = w.finish();
        facts.budget_exceeded |= !complete;
        facts
    }
}

/// The command a name stands for: built-in aliases expanded.
fn canonical(name: &str) -> &str {
    BUILTIN_ALIASES
        .iter()
        .find(|(a, _)| *a == name)
        .map_or(name, |(_, full)| full)
}

/// A command name as compared: no backtick escapes, module qualifier,
/// directories, case or `.exe` suffix.
fn command_key(text: &str) -> String {
    let plain: String = text.chars().filter(|c| *c != '`').collect();
    program_name(plain.trim())
}

/// A type name as compared: lowercase, without brackets or `System.`.
fn type_key(text: &str) -> String {
    let lower: String = text
        .chars()
        .filter(|c| !matches!(c, '[' | ']' | '`') && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    lower.strip_prefix("system.").unwrap_or(&lower).to_string()
}

/// A variable name as compared: no sigil, braces, scope prefix or case.
/// `$PSItem` is `$_`.
fn variable_key(text: &str) -> String {
    let t = text.trim_start_matches(['$', '@']);
    let t = t
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or(t);
    let lower = t.to_ascii_lowercase();
    let mut name = lower.as_str();
    for scope in [
        "global:",
        "script:",
        "local:",
        "private:",
        "using:",
        "variable:",
    ] {
        if let Some(rest) = name.strip_prefix(scope) {
            name = rest;
        }
    }
    if name == "psitem" { "_" } else { name }.to_string()
}

/// Whether a resolved name is one the rules classify.
fn relevant(name: &str) -> bool {
    let name = canonical(name);
    call_class(name).is_some()
        || NETWORK_COMMANDS.contains(&name)
        || SHELL_PROGRAMS.contains(&name)
        || matches!(
            name,
            "invoke-expression"
                | "start-process"
                | "add-content"
                | "set-content"
                | "out-file"
                | "new-item"
                | "tee-object"
                | "copy-item"
                | "move-item"
                | "set-itemproperty"
                | "new-itemproperty"
                | "register-scheduledtask"
                | "get-storedcredential"
        )
}

/// Sink class of a resolved method call name.
fn call_class(name: &str) -> Option<&'static str> {
    let (recv, method) = name.rsplit_once('.')?;
    let class = match recv {
        "net.webclient()"
            if ["download", "upload", "openread", "openwrite"]
                .iter()
                .any(|p| method.starts_with(p)) =>
        {
            NETWORK
        }
        "net.http.httpclient()"
            if matches!(
                method,
                "getasync"
                    | "getstringasync"
                    | "getbytearrayasync"
                    | "getstreamasync"
                    | "postasync"
                    | "putasync"
                    | "patchasync"
                    | "deleteasync"
                    | "sendasync"
                    | "send"
            ) =>
        {
            NETWORK
        }
        "net.sockets.tcpclient().getstream()"
            if matches!(method, "write" | "writeasync" | "beginwrite" | "writebyte") =>
        {
            NETWORK
        }
        "net.sockets.socket()" | "net.sockets.udpclient()" if method.starts_with("send") => NETWORK,
        "scriptblock" if method == "create" => EVAL,
        "executioncontext.invokecommand" if matches!(method, "invokescript" | "newscriptblock") => {
            EVAL
        }
        "diagnostics.process" if method == "start" => EXEC,
        _ => return None,
    };
    Some(class)
}

/// Index of the path argument of an `[IO.File]` method that writes.
fn file_write_arg(name: &str) -> Option<usize> {
    let method = name.strip_prefix("io.file.")?;
    if method.starts_with("write") || method.starts_with("append") || method == "create" {
        Some(0)
    } else if matches!(method, "copy" | "move") {
        Some(1)
    } else {
        None
    }
}

/// Whether command text fetches code and runs it (`iwr u | iex`,
/// `IEX (New-Object Net.WebClient).DownloadString(u)`, `curl u | sh`).
fn runs_download(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
        .collect();
    let runs = words
        .iter()
        .any(|w| matches!(*w, "iex" | "invoke-expression"));
    let fetches = words.iter().any(|w| {
        matches!(
            *w,
            "iwr" | "irm" | "invoke-webrequest" | "invoke-restmethod" | "curl" | "wget"
        ) || w.contains("downloadstring")
            || w.contains("downloaddata")
    });
    (runs && fetches) || pipes_download_to_shell(text)
}

#[derive(Clone, Copy, Default)]
struct Scope {
    /// Name bound to what the node reads from the pipeline.
    input: Option<usize>,
    /// Function whose body holds the node.
    func: Option<usize>,
    /// Command whose arguments hold the node, shown in source evidence.
    cmd: Option<usize>,
    /// Inside a literal already classified as a whole.
    in_literal: bool,
    /// Inside a loop body or condition.
    in_loop: bool,
}

/// A command seen in the tree.
struct Cmd<'t> {
    node: Node<'t>,
    /// Index into the core's calls.
    call: usize,
    elements: Option<Node<'t>>,
    /// Lowercase name as written, before alias resolution.
    raw: Option<String>,
    /// `& $x`, `& (expr)`: the program is computed.
    dynamic: bool,
    /// Started with the `.` operator.
    dot: bool,
    /// Started with the `&` operator.
    amp: bool,
    input: Option<usize>,
}

/// An output redirection.
struct Redir<'t> {
    /// Statement shown in evidence.
    shown: Node<'t>,
    /// What the redirection writes.
    stmt: Node<'t>,
    dest: Node<'t>,
    input: Option<usize>,
}

struct Walk<'t> {
    core: Core<'t>,
    names: Vec<String>,
    cmds: Vec<Cmd<'t>>,
    redirs: Vec<Redir<'t>>,
    funcs: HashSet<String>,
    /// Call index of a method call and its argument list, by call index.
    method_args: HashMap<usize, Node<'t>>,
    /// Expressions that may build a path from pieces.
    candidates: Vec<Node<'t>>,
    /// Literal source spans: start, end, class.
    spans: Vec<(usize, usize, &'static str)>,
    /// A `.Read(...)` call inside a loop.
    loop_read: bool,
    next_name: usize,
    cursor: Option<TreeCursor<'t>>,
}

impl<'t> Walk<'t> {
    fn new(src: &'t [u8]) -> Self {
        Self {
            core: Core::new(src),
            names: Vec::new(),
            cmds: Vec::new(),
            redirs: Vec::new(),
            funcs: HashSet::new(),
            method_args: HashMap::new(),
            candidates: Vec::new(),
            spans: Vec::new(),
            loop_read: false,
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

    /// The node an expression wrapper (`unary_expression`, `pipeline` …)
    /// with a single child of the same extent stands for.
    fn unwrap(&self, mut node: Node<'t>) -> Node<'t> {
        for _ in 0..64 {
            if node.kind() == "command" || node.named_child_count() != 1 {
                break;
            }
            let Some(c) = node.named_child(0) else { break };
            let same = c.byte_range() == node.byte_range();
            let paren = matches!(
                node.kind(),
                "parenthesized_expression" | "sub_expression" | "string_literal"
            );
            if !(same || paren) {
                break;
            }
            node = c;
        }
        node
    }

    /// Type named by `New-Object T`, `New-Object -TypeName T` or `[T]::new()`.
    fn constructed_type(&self, node: Node<'t>) -> Option<String> {
        let node = self.unwrap(node);
        match node.kind() {
            "command" => {
                let name = node.child_by_field_name("command_name")?;
                if command_key(self.text(name)) != "new-object" {
                    return None;
                }
                let elements = node.child_by_field_name("command_elements")?;
                let (params, pos) = self.elements(elements);
                let ty = param(&params, &["typename"]).or_else(|| pos.first().copied())?;
                Some(type_key(&self.fold(ty)))
            }
            "invokation_expression" => {
                let (obj, method) = self.member_parts(node)?;
                (method == "new" && obj.kind() == "type_literal").then(|| type_key(self.text(obj)))
            }
            _ => None,
        }
    }

    /// Object and lowercase member name of a member access or method call.
    fn member_parts(&self, node: Node<'t>) -> Option<(Node<'t>, String)> {
        let kids = self.core.children_upto(node, usize::MAX);
        let obj = *kids.first()?;
        let member = kids
            .iter()
            .skip(1)
            .find(|k| matches!(k.kind(), "simple_name" | "member_name"))?;
        let name: String = self
            .text(*member)
            .chars()
            .filter(|c| *c != '`')
            .collect::<String>()
            .to_ascii_lowercase();
        Some((obj, name))
    }

    /// Dotted value name: `wc`, `net.webclient()`, `c.getstream()`,
    /// `io.file`. `None` for other shapes.
    fn dotted(&self, node: Node<'t>) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = node;
        for _ in 0..MAX_NAME_SEGMENTS {
            let n = self.unwrap(cur);
            let head = match self.constructed_type(n) {
                Some(ty) => Some(format!("{ty}()")),
                None => match n.kind() {
                    "variable" | "braced_variable" => Some(variable_key(self.text(n))),
                    "type_literal" => Some(type_key(self.text(n))),
                    "member_access" | "invokation_expression" => None,
                    _ => return None,
                },
            };
            if let Some(head) = head {
                parts.push(head);
                parts.reverse();
                return Some(parts.join("."));
            }
            let (obj, name) = self.member_parts(n)?;
            let call = if n.kind() == "invokation_expression" {
                "()"
            } else {
                ""
            };
            parts.push(format!("{name}{call}"));
            cur = obj;
        }
        None
    }

    /// Name of the method a call invokes: `wc.uploadstring`,
    /// `net.webclient().downloadstring`, `io.file.readallbytes`.
    fn callee(&self, node: Node<'t>) -> Option<String> {
        let (obj, name) = self.member_parts(node)?;
        Some(format!("{}.{name}", self.dotted(obj)?))
    }

    /// Text a literal or a path expression stands for: quotes and backtick
    /// escapes removed, `+` pieces joined, `Join-Path` and
    /// `[IO.Path]::Combine` pieces joined with `/`, variables as written,
    /// anything else as an unknown piece. Nodes walked go into `visited`.
    fn fold_into(&self, node: Node<'t>, visited: &mut HashSet<usize>) -> String {
        enum Item<'n> {
            Node(Node<'n>),
            Sep,
        }
        let mut out = String::new();
        let mut stack = vec![Item::Node(node)];
        while let Some(item) = stack.pop() {
            let n = match item {
                Item::Sep => {
                    out.push('/');
                    continue;
                }
                Item::Node(n) => self.unwrap(n),
            };
            visited.insert(n.id());
            let text = self.text(n);
            match n.kind() {
                "expandable_string_literal" | "expandable_here_string_literal" => {
                    let mut s = String::new();
                    let mut at = n.start_byte();
                    for c in self.core.children_upto(n, usize::MAX) {
                        if c.kind() == "sub_expression" {
                            s.push_str(&self.slice(at, c.start_byte()));
                            s.push(UNKNOWN_PIECE);
                            at = c.end_byte();
                        }
                    }
                    s.push_str(&self.slice(at, n.end_byte()));
                    let s = s.trim_start_matches('@').trim_end_matches('@');
                    out.extend(s.trim_matches('"').chars().filter(|c| *c != '`'));
                }
                "verbatim_string_characters" | "verbatim_here_string_characters" => {
                    let s = text.trim_start_matches('@').trim_end_matches('@');
                    out.push_str(&s.trim_matches('\'').replace("''", "'"));
                }
                "generic_token" => out.extend(text.chars().filter(|c| *c != '`')),
                "variable" | "braced_variable" => out.push_str(text),
                "additive_expression" => {
                    if n.child(1).is_some_and(|o| o.kind() == "+") {
                        let kids = self.core.children_upto(n, usize::MAX);
                        stack.extend(kids.into_iter().rev().map(Item::Node));
                    } else {
                        out.push(UNKNOWN_PIECE);
                    }
                }
                "command" if self.is_join_path(n) => {
                    if let Some(el) = n.child_by_field_name("command_elements") {
                        let (_, pos) = self.elements(el);
                        for (i, p) in pos.into_iter().enumerate().rev() {
                            stack.push(Item::Node(p));
                            if i > 0 {
                                stack.push(Item::Sep);
                            }
                        }
                    }
                }
                "invokation_expression" if self.callee(n).as_deref() == Some("io.path.combine") => {
                    let args = self.call_args(n);
                    for (i, p) in args.into_iter().enumerate().rev() {
                        stack.push(Item::Node(p));
                        if i > 0 {
                            stack.push(Item::Sep);
                        }
                    }
                }
                _ => out.push(UNKNOWN_PIECE),
            }
        }
        out
    }

    fn fold(&self, node: Node<'t>) -> String {
        self.fold_into(node, &mut HashSet::new())
    }

    fn slice(&self, from: usize, to: usize) -> String {
        let src: &'t [u8] = self.core.src;
        String::from_utf8_lossy(src.get(from..to).unwrap_or_default()).into_owned()
    }

    fn is_join_path(&self, node: Node<'t>) -> bool {
        node.child_by_field_name("command_name")
            .is_some_and(|n| command_key(self.text(n)) == "join-path")
    }

    /// Argument expressions of a method call's argument list.
    fn call_args(&self, call: Node<'t>) -> Vec<Node<'t>> {
        let list = self
            .core
            .children_upto(call, usize::MAX)
            .into_iter()
            .find(|k| k.kind() == "argument_list");
        list.map(|l| self.list_items(l)).unwrap_or_default()
    }

    /// Items of an `argument_list`, flattening `argument_expression_list`.
    fn list_items(&self, list: Node<'t>) -> Vec<Node<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![list];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "argument_list" | "argument_expression_list" => {
                    stack.extend(self.core.children_upto(n, usize::MAX).into_iter().rev());
                }
                _ => out.push(n),
            }
        }
        out
    }

    /// Named parameters (lowercase, without `-` or `:`) with their values,
    /// and positional arguments of a command. A method call written as
    /// `(x).M(args)` in argument position is one argument.
    fn elements(&self, el: Node<'t>) -> (Vec<(String, Option<Node<'t>>)>, Vec<Node<'t>>) {
        let kids: Vec<Node<'t>> = self
            .core
            .children_upto(el, usize::MAX)
            .into_iter()
            .filter(|k| {
                !matches!(
                    k.kind(),
                    "command_argument_sep"
                        | "redirection"
                        | "redirections"
                        | "merging_redirection_operator"
                )
            })
            .collect();
        let mut params = Vec::new();
        let mut pos = Vec::new();
        let mut i = 0;
        while let Some(k) = kids.get(i) {
            i += 1;
            if k.kind() == "argument_list" && i >= 2 {
                continue;
            }
            if k.kind() != "command_parameter" {
                pos.push(*k);
                continue;
            }
            let name = self
                .text(*k)
                .trim_start_matches('-')
                .trim_end_matches(':')
                .to_ascii_lowercase();
            let next = kids.get(i).filter(|n| n.kind() != "command_parameter");
            let value = next.filter(|_| !SWITCHES.contains(&name.as_str())).copied();
            if value.is_some() {
                i += 1;
            }
            params.push((name, value));
        }
        (params, pos)
    }

    /// Whether any reference of `node` is a sensitive path.
    fn touches(&self, node: Node, sensitive: &HashSet<String>) -> bool {
        self.core
            .node_refs(node)
            .iter()
            .any(|r| sensitive.contains(r))
    }
}

/// Value of the first parameter abbreviating one of `full` names.
fn param<'t>(params: &[(String, Option<Node<'t>>)], full: &[&str]) -> Option<Node<'t>> {
    params
        .iter()
        .find(|(p, _)| !p.is_empty() && full.iter().any(|f| f.starts_with(p.as_str())))
        .and_then(|(_, v)| *v)
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
            ..scope
        };
        match node.kind() {
            "comment" => return,
            "variable" | "braced_variable" => return self.variable(node, scope),
            "expandable_string_literal"
            | "expandable_here_string_literal"
            | "verbatim_string_characters"
            | "verbatim_here_string_characters"
            | "generic_token" => {
                if !scope.in_literal {
                    self.literal(node, scope);
                }
                inner.in_literal = true;
            }
            "assignment_expression" => self.assignment(node),
            "foreach_statement" => {
                self.foreach(node);
                inner.in_loop = true;
            }
            "while_statement" | "do_statement" | "for_statement" => inner.in_loop = true,
            "invokation_expression" => {
                let args = self
                    .core
                    .children_upto(node, usize::MAX)
                    .into_iter()
                    .find(|k| k.kind() == "argument_list");
                self.method_call(node, args, scope);
            }
            "additive_expression" => {
                if node.child(1).is_some_and(|o| o.kind() == "+") {
                    self.candidates.push(node);
                }
            }
            "command" => return self.command(node, scope, stack),
            "pipeline_chain" => return self.pipeline(node, scope, stack),
            "function_statement" => return self.function(node, scope, stack),
            _ => {}
        }
        self.push_children(node, inner, stack);
    }

    /// A variable reference. `$env:NAME` of a secret-looking variable is a
    /// source; `$PROFILE` is a sensitive path; `$args` in a function is its
    /// arguments.
    fn variable(&mut self, node: Node<'t>, scope: Scope) {
        let mut name = variable_key(self.text(node));
        if let Some(env) = name.strip_prefix("env:")
            && let Some(class) = env_class(env)
        {
            let text = format!("$env:{}", clip(env, TEXT_CHARS));
            self.core.add_source(node, class, text, None);
        }
        if name == "profile" {
            self.core.add_sensitive(node);
        }
        if name == "args"
            && let Some(f) = scope.func
        {
            name = format!("{}@", self.names[f]);
        }
        self.core.token(node, name, true);
    }

    /// A literal: a source or sensitive path when its text names one.
    /// `env:NAME` names an environment variable.
    fn literal(&mut self, node: Node<'t>, scope: Scope) {
        let text = self.fold(node);
        let class = literal_source_class(&text).or_else(|| {
            let lower = text.to_ascii_lowercase();
            lower
                .strip_prefix("env:")
                .and_then(env_class)
                .filter(|c| *c == SECRET_ENV)
        });
        if let Some(class) = class {
            let shown = self.display(node);
            let shown = match scope.cmd {
                Some(c) => format!("{} {shown}", self.names[c]),
                None => shown,
            };
            self.core.add_source(node, class, shown, None);
            self.spans.push((node.start_byte(), node.end_byte(), class));
        }
        if is_sensitive_write_path(&text) {
            self.core.add_sensitive(node);
            self.spans
                .push((node.start_byte(), node.end_byte(), SENSITIVE_WRITE));
        }
    }

    /// Variable names an assignment target binds.
    fn targets(&self, node: Node<'t>) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let n = self.unwrap(n);
            match n.kind() {
                "variable" | "braced_variable" => out.push(variable_key(self.text(n))),
                "member_access" | "element_access" | "cast_expression" => {
                    let head = self
                        .core
                        .children_upto(n, usize::MAX)
                        .into_iter()
                        .find(|k| k.kind() != "type_literal");
                    stack.extend(head);
                }
                "array_literal_expression" => stack.extend(self.core.children(n)),
                _ => {}
            }
        }
        out
    }

    fn assignment(&mut self, node: Node<'t>) {
        let Some(left) = self.core.first_child(node) else {
            return;
        };
        let targets = self.targets(left);
        let value = node.child_by_field_name("value");
        // `$f = 'Invoke-Expression'`: `& $f` may run it. Every value is kept.
        if let ([target], Some(v)) = (targets.as_slice(), value) {
            let v = self.unwrap(v);
            let literal = match v.kind() {
                "verbatim_string_characters" => true,
                "expandable_string_literal" => self.core.children_upto(v, usize::MAX).is_empty(),
                _ => false,
            };
            if literal {
                let local = format!("${target}");
                let full = command_key(&self.fold(v));
                self.core.add_alias(&local, full, relevant);
            }
        }
        let rhs_callee = value.and_then(|v| {
            let v = self.unwrap(v);
            match self.constructed_type(v) {
                Some(ty) => Some(ty),
                None if v.kind() == "invokation_expression" => self.callee(v),
                None => None,
            }
        });
        self.core.bind(targets, value, None, line(node), rhs_callee);
    }

    /// `foreach ($x in $items)`: `$x` takes the items.
    fn foreach(&mut self, node: Node<'t>) {
        let kids = self.core.children_upto(node, usize::MAX);
        let mut it = kids.iter().filter(|k| k.kind() != "foreach_parameter");
        let (Some(var), Some(items)) = (it.next(), it.next()) else {
            return;
        };
        let targets = self.targets(*var);
        self.core
            .bind(targets, Some(*items), None, line(node), None);
    }

    /// A method call, or `(x).M(args)` written in argument position.
    fn method_call(&mut self, node: Node<'t>, args: Option<Node<'t>>, scope: Scope) {
        let callee = self.callee(node);
        if scope.in_loop && callee.as_deref().is_some_and(|c| c.ends_with(".read")) {
            self.loop_read = true;
        }
        if callee.as_deref() == Some("io.path.combine") {
            self.candidates.push(node);
        }
        self.core.add_call(node, callee, args);
        if let Some(a) = args {
            self.method_args.insert(self.core.calls.len() - 1, a);
        }
    }

    /// A pipeline: each stage reads the stages before it. Redirections
    /// written after a stage apply to it.
    fn pipeline(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let kids = self.core.children_upto(node, usize::MAX);
        let mut stages: Vec<Node<'t>> = Vec::new();
        let mut items = Vec::new();
        let mut input = scope.input;
        for k in kids {
            match k.kind() {
                "redirection" | "redirections" => {
                    let stmt = stages.last().copied().unwrap_or(node);
                    for dest in self.redirect_dests(k) {
                        self.redirs.push(Redir {
                            shown: node,
                            stmt,
                            dest,
                            input,
                        });
                    }
                    items.push((k, scope));
                }
                "merging_redirection_operator" => {}
                _ => {
                    if let Some(prev) = stages.last() {
                        self.next_name += 1;
                        let name = format!("|{}", self.next_name);
                        let extra = self.input_names(input);
                        self.core.push_bind(Bind {
                            targets: vec![name.clone()],
                            ranges: vec![(prev.start_byte(), prev.end_byte())],
                            extra,
                            line: line(k),
                            rhs_callee: None,
                        });
                        input = Some(self.intern(name));
                    }
                    stages.push(k);
                    items.push((
                        k,
                        Scope {
                            input,
                            in_literal: false,
                            ..scope
                        },
                    ));
                }
            }
        }
        stack.extend(items.into_iter().rev());
    }

    /// `function Name($p) { body }`: parameters take the call arguments,
    /// the body's output is the function's output.
    fn function(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let kids = self.core.children_upto(node, usize::MAX);
        let Some(name) = kids.iter().find(|k| k.kind() == "function_name").copied() else {
            return self.push_children(node, scope, stack);
        };
        let fname = command_key(self.text(name));
        self.funcs.insert(fname.clone());
        let body = kids.iter().find(|k| k.kind() == "script_block").copied();
        self.core.bind(
            vec![format!("{fname}()")],
            Some(body.unwrap_or(node)),
            None,
            line(node),
            None,
        );
        // Parameters: in `($a, $b)` after the name, or a `param(...)` block.
        let mut params = Vec::new();
        let mut look: Vec<Node<'t>> = kids
            .iter()
            .filter(|k| k.kind() == "function_parameter_declaration")
            .copied()
            .collect();
        if let Some(b) = body {
            look.extend(
                self.core
                    .children_upto(b, usize::MAX)
                    .into_iter()
                    .filter(|k| k.kind() == "param_block"),
            );
        }
        while let Some(n) = look.pop() {
            match n.kind() {
                "variable" => params.push(n),
                "function_parameter_declaration"
                | "param_block"
                | "parameter_list"
                | "script_parameter" => look.extend(self.core.children(n)),
                _ => {}
            }
        }
        for p in params {
            let parent = p.parent().filter(|q| q.kind() == "script_parameter");
            let range = parent.unwrap_or(p);
            self.core.push_bind(Bind {
                targets: vec![variable_key(self.text(p))],
                ranges: vec![(range.start_byte(), range.end_byte())],
                extra: vec![format!("{fname}@")],
                line: line(p),
                rhs_callee: None,
            });
        }
        let input = self.intern(format!("{fname}<"));
        let func = self.intern(fname);
        let inner = Scope {
            input: Some(input),
            func: Some(func),
            cmd: None,
            in_literal: false,
            in_loop: false,
        };
        for k in kids.into_iter().rev() {
            if k.id() != name.id() {
                stack.push((k, inner));
            }
        }
    }

    /// A command: records the call, aliases and variables it defines, and
    /// method calls written in argument position.
    fn command(&mut self, node: Node<'t>, scope: Scope, stack: &mut Vec<(Node<'t>, Scope)>) {
        let kids = self.core.children_upto(node, usize::MAX);
        let op = kids
            .iter()
            .find(|k| k.kind() == "command_invokation_operator")
            .map(|k| self.text(*k).trim());
        let name_node = node.child_by_field_name("command_name");
        let elements = node.child_by_field_name("command_elements");
        let mut dynamic = false;
        let raw = match (op, name_node) {
            (_, None) => None,
            (None, Some(n)) => Some(command_key(self.text(n))),
            (Some(_), Some(n)) => {
                let n = self.unwrap(n);
                let text = self.fold(n);
                // A quoted path is a program even with variables in it
                // (`& "$root/tool.exe"`); a bare variable or expression is
                // computed.
                let quoted = matches!(
                    n.kind(),
                    "expandable_string_literal" | "verbatim_string_characters" | "generic_token"
                );
                if n.kind() == "script_block_expression" {
                    None
                } else if text.contains(UNKNOWN_PIECE) || (!quoted && text.contains('$')) {
                    dynamic = true;
                    // `& $f`: resolved later through what `$f` was assigned.
                    matches!(n.kind(), "variable" | "braced_variable")
                        .then(|| format!("${}", variable_key(self.text(n))))
                } else {
                    Some(command_key(&text))
                }
            }
        };
        if raw.as_deref() == Some("join-path") {
            self.candidates.push(node);
        }
        self.core.add_call(node, raw.clone(), elements);
        let call = self.core.calls.len() - 1;
        if let Some(el) = elements {
            self.element_calls(el, scope);
            if let Some(r) = raw.as_deref().filter(|_| !dynamic) {
                self.definitions(r, el, node, scope);
            }
            for k in self.core.children_upto(el, usize::MAX) {
                for dest in self.redirect_dests(k) {
                    self.redirs.push(Redir {
                        shown: node,
                        stmt: node,
                        dest,
                        input: scope.input,
                    });
                }
            }
        }
        self.cmds.push(Cmd {
            node,
            call,
            elements,
            raw: raw.clone(),
            dynamic,
            dot: op == Some("."),
            amp: op == Some("&"),
            input: scope.input,
        });
        let shown = raw.map(|r| self.intern(r));
        let inner = Scope {
            cmd: shown.or(scope.cmd),
            in_literal: false,
            ..scope
        };
        let start = stack.len();
        self.push_children(node, inner, stack);
        if let (Some(n), None) = (name_node, op)
            && let Some(entry) = stack[start..].iter_mut().find(|(c, _)| c.id() == n.id())
        {
            entry.1.in_literal = true;
        }
    }

    /// `(expr).Method(args)` in argument position parses as a member access
    /// followed by an argument list; record it as a method call.
    fn element_calls(&mut self, el: Node<'t>, scope: Scope) {
        let kids = self.core.children_upto(el, usize::MAX);
        for pair in kids.windows(2) {
            let [m, a] = pair else { continue };
            let m = self.unwrap(*m);
            if m.kind() == "member_access"
                && a.kind() == "argument_list"
                && m.end_byte() == a.start_byte()
            {
                self.method_call(m, Some(*a), scope);
            }
        }
    }

    /// File names an output redirection (or a group of them) writes.
    fn redirect_dests(&self, node: Node<'t>) -> Vec<Node<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "redirections" | "redirection" => {
                    stack.extend(self.core.children_upto(n, usize::MAX));
                }
                "redirected_file_name" => out.push(n),
                _ => {}
            }
        }
        out
    }

    /// `Set-Alias name value` and `Set-Variable name value`.
    fn definitions(&mut self, raw: &str, el: Node<'t>, node: Node<'t>, scope: Scope) {
        let name = canonical(raw);
        let alias = matches!(name, "set-alias" | "new-alias");
        let variable = matches!(name, "set-variable" | "new-variable");
        if !alias && !variable {
            return;
        }
        let (params, pos) = self.elements(el);
        let mut pos = pos.into_iter();
        let key = param(&params, &["name"]).or_else(|| pos.next());
        let value = param(&params, &["value"]).or_else(|| pos.next());
        let (Some(key), Some(value)) = (key, value) else {
            return;
        };
        let key = self.fold(key);
        if alias {
            let target = command_key(&self.fold(value));
            self.core.add_alias(&command_key(&key), target, relevant);
        } else {
            let extra = self.input_names(scope.input);
            self.core.push_bind(Bind {
                targets: vec![variable_key(&key)],
                ranges: vec![(value.start_byte(), value.end_byte())],
                extra,
                line: line(node),
                rhs_callee: None,
            });
        }
    }
}

/// What the second pass decided about a command or method call.
#[derive(Default)]
struct Verdict<'t> {
    class: Option<&'static str>,
    /// Path arguments written; a sensitive one makes a `sensitive_write`.
    writes: Vec<Node<'t>>,
    /// Installs persistence whatever the path.
    always_write: bool,
}

// ---- Second pass ----

impl<'t> Walk<'t> {
    /// Resolved command name of a recorded command.
    fn resolved(&self, c: &Cmd<'t>) -> Option<&str> {
        let name = self.core.calls.get(c.call)?.callee.as_deref()?;
        Some(canonical(name))
    }

    fn element_texts(&self, c: &Cmd<'t>) -> Vec<String> {
        c.elements
            .map(|el| {
                self.core
                    .children_upto(el, usize::MAX)
                    .into_iter()
                    .filter(|k| k.kind() != "command_argument_sep")
                    .map(|k| match k.kind() {
                        "command_parameter" => self.text(k).to_string(),
                        _ => self.fold(k),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn command_verdict(&self, c: &Cmd<'t>) -> Verdict<'t> {
        let mut v = Verdict::default();
        let name = self.resolved(c);
        if c.dynamic && name.is_none_or(|n| n.starts_with('$')) {
            v.class = Some(if c.dot { EVAL } else { EXEC });
            return v;
        }
        let Some(name) = name else {
            return v;
        };
        let (params, pos) = c.elements.map(|e| self.elements(e)).unwrap_or_default();
        let path =
            |names: &[&str], at: usize| param(&params, names).or_else(|| pos.get(at).copied());
        match name {
            n if NETWORK_COMMANDS.contains(&n) => v.class = Some(NETWORK),
            "invoke-expression" => v.class = Some(EVAL),
            "start-process" => {
                let text = self.element_texts(c).join(" ");
                v.class = Some(if runs_download(&text) {
                    DOWNLOAD_EXEC
                } else {
                    EXEC
                });
            }
            n if SHELL_PROGRAMS.contains(&n) => {
                let texts = self.element_texts(c);
                let runs = texts.iter().any(|t| {
                    let flag = t.trim_end_matches(':');
                    is_shell_flag(flag)
                        || flag.strip_prefix('-').is_some_and(|f| {
                            f.len() >= 2 && "encodedcommand".starts_with(&f.to_ascii_lowercase())
                        })
                });
                if runs {
                    let download = runs_download(&texts.join(" "));
                    v.class = Some(if download { DOWNLOAD_EXEC } else { EXEC });
                }
            }
            "add-content" | "set-content" | "out-file" | "new-item" | "tee-object" => {
                v.writes
                    .extend(path(&["path", "literalpath", "filepath"], 0));
            }
            "copy-item" | "move-item" => v.writes.extend(path(&["destination"], 1)),
            "set-itemproperty" | "new-itemproperty" => {
                v.writes.extend(path(&["path", "literalpath"], 0));
            }
            "register-scheduledtask" => v.always_write = true,
            "schtasks" => {
                v.always_write = self
                    .element_texts(c)
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case("/create"));
            }
            _ => {}
        }
        if v.class.is_none() && v.writes.is_empty() && c.amp {
            v.class = Some(EXEC);
        }
        v
    }

    fn method_verdict(&self, idx: usize) -> Verdict<'t> {
        let mut v = Verdict::default();
        let Some(name) = self.core.calls[idx].callee.as_deref() else {
            return v;
        };
        v.class = call_class(name);
        if let Some(i) = file_write_arg(name)
            && let Some(args) = self.method_args.get(&idx)
        {
            v.writes.extend(self.list_items(*args).get(i).copied());
        }
        v
    }

    /// Sources, sensitive paths and reverse-shell parts found in calls
    /// once their names are resolved. Returns the TCP client constructor,
    /// if any, and whether a stream was taken from a client.
    fn call_facts(&mut self, cmd_calls: &HashSet<usize>) -> (Option<Node<'t>>, bool) {
        let mut tcp = None;
        let mut stream = false;
        for c in &self.cmds {
            if self.constructed_type(c.node).as_deref() == Some("net.sockets.tcpclient") {
                tcp = tcp.or(Some(c.node));
            }
        }
        let mut sources = Vec::new();
        let mut sensitive = Vec::new();
        for (i, call) in self.core.calls.iter().enumerate() {
            let Some(name) = call.callee.as_deref() else {
                continue;
            };
            if cmd_calls.contains(&i) {
                if canonical(name) == "get-storedcredential" {
                    sources.push((
                        call.node,
                        KEYCHAIN,
                        self.display(call.node),
                        call.id.clone(),
                    ));
                }
                continue;
            }
            stream |= name.ends_with(".getstream");
            if name == "net.sockets.tcpclient.new" {
                tcp = tcp.or(Some(call.node));
            }
            let first = self
                .method_args
                .get(&i)
                .and_then(|a| self.list_items(*a).first().copied())
                .map(|a| self.fold(a));
            match (name, first) {
                ("environment.getenvironmentvariable", Some(key)) => {
                    if let Some(class) = env_class(&key) {
                        let text = format!(
                            "[Environment]::GetEnvironmentVariable({})",
                            clip(&key, TEXT_CHARS)
                        );
                        sources.push((call.node, class, text, call.id.clone()));
                    }
                }
                ("environment.getfolderpath", Some(key))
                    if key.to_ascii_lowercase().contains("startup") =>
                {
                    sensitive.push(call.node);
                }
                _ => {}
            }
        }
        for (node, class, text, id) in sources {
            self.core.add_source(node, class, text, Some(id));
        }
        for node in sensitive {
            self.core.add_sensitive(node);
        }
        (tcp, stream)
    }

    /// Sources and sensitive paths built from several pieces (`+`,
    /// `Join-Path`, `[IO.Path]::Combine`). A candidate already walked by an
    /// enclosing one is skipped; a match is reported only when no single
    /// literal inside already matched.
    fn fold_sites(&mut self) {
        self.spans.sort_unstable();
        let mut cands = std::mem::take(&mut self.candidates);
        cands.sort_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())));
        let mut visited = HashSet::new();
        for n in cands {
            if visited.contains(&n.id()) {
                continue;
            }
            let folded = self.fold_into(n, &mut visited);
            if let Some(class) = literal_source_class(&folded)
                && !Core::has_span_within(&self.spans, n, class)
            {
                let text = self.display(n);
                self.core.add_source(n, class, text, None);
            }
            if is_sensitive_write_path(&folded)
                && !Core::has_span_within(&self.spans, n, SENSITIVE_WRITE)
            {
                self.core.add_sensitive(n);
            }
        }
    }

    /// Calls of functions defined in the file, and `$_` in pipelines.
    fn call_binds(&mut self) {
        for i in 0..self.cmds.len() {
            let c = &self.cmds[i];
            let (node, input, elements) = (c.node, c.input, c.elements);
            let raw = c.raw.clone().unwrap_or_default();
            let foreach = matches!(self.resolved(c), Some("foreach-object" | "where-object"));
            let extra = self.input_names(input);
            if foreach && !extra.is_empty() {
                self.core.push_bind(Bind {
                    targets: vec!["_".to_string()],
                    ranges: Vec::new(),
                    extra: extra.clone(),
                    line: line(node),
                    rhs_callee: None,
                });
            }
            if !self.funcs.contains(&raw) {
                continue;
            }
            self.core.token(node, format!("{raw}()"), false);
            let range = elements.unwrap_or(node);
            self.core.push_bind(Bind {
                targets: vec![format!("{raw}@"), format!("{raw}<")],
                ranges: vec![(range.start_byte(), range.end_byte())],
                extra,
                line: line(node),
                rhs_callee: None,
            });
        }
    }

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

    fn finish(mut self) -> Facts {
        // Twice: the second pass sees objects derived from objects found in
        // the first (`$s = $client.GetStream()`).
        self.core.resolve_calls(CLIENT_CONSTRUCTORS, relevant);
        self.core.resolve_calls(CLIENT_CONSTRUCTORS, relevant);
        let cmd_calls: HashSet<usize> = self.cmds.iter().map(|c| c.call).collect();
        let (tcp, stream) = self.call_facts(&cmd_calls);
        self.fold_sites();
        self.call_binds();

        // (call index, command index for commands, verdict)
        let mut verdicts: Vec<(usize, Option<usize>, Verdict<'t>)> = Vec::new();
        for (j, c) in self.cmds.iter().enumerate() {
            verdicts.push((c.call, Some(j), self.command_verdict(c)));
        }
        for i in 0..self.core.calls.len() {
            if !cmd_calls.contains(&i) {
                verdicts.push((i, None, self.method_verdict(i)));
            }
        }

        self.core.index_tokens();
        let network: Vec<String> = verdicts
            .iter()
            .filter(|(_, _, v)| v.class == Some(NETWORK))
            .map(|(i, _, _)| self.core.calls[*i].id.clone())
            .collect();
        self.core.set_interesting(network);
        let assigns = self.core.assigns();
        let sensitive = self.core.sensitive_reach(&assigns);

        let mut sinks = Vec::new();
        for (i, cmd, v) in &verdicts {
            let class = match v.class {
                Some(class) => class,
                None if v.always_write || v.writes.iter().any(|w| self.touches(*w, &sensitive)) => {
                    SENSITIVE_WRITE
                }
                None => continue,
            };
            let call = &self.core.calls[*i];
            let site = match cmd.map(|j| &self.cmds[j]) {
                Some(c) => self.site(call.id.clone(), class, c.node, c.node, c.input),
                None => {
                    let refs_of = self.method_args.get(i).copied().unwrap_or(call.node);
                    self.site(call.id.clone(), class, call.node, refs_of, None)
                }
            };
            self.core.push_sink(&mut sinks, || site);
        }
        for i in 0..self.redirs.len() {
            let r = &self.redirs[i];
            if !self.touches(r.dest, &sensitive) {
                continue;
            }
            let (shown, stmt, input) = (r.shown, r.stmt, r.input);
            let id = self.core.fresh_id('r');
            let site = self.site(id, SENSITIVE_WRITE, shown, stmt, input);
            self.core.push_sink(&mut sinks, || site);
        }
        if let (Some(node), true, true) = (tcp, stream, self.loop_read) {
            let id = self.core.fresh_id('r');
            let mut site = self.site(id, REVERSE_SHELL, node, node, None);
            site.text = format!("TCP client + stream read loop: {}", site.text);
            self.core.push_sink(&mut sinks, || site);
        }
        self.core.into_facts(sinks, assigns)
    }
}
