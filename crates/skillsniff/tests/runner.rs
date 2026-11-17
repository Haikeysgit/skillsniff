use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use skillsniff::analyzers::{Analyzer, AnalyzerOutput, ScanContext, run_analyzers};
use skillsniff::inventory::build_inventory;
use skillsniff::model::{Coverage, Signal};
use skillsniff::progress::{NoopProgress, ProgressEvent, ProgressSink};
use skillsniff::target::{Target, detect_skill, skill::SkillTarget};

fn make_ctx() -> (tempfile::TempDir, Arc<ScanContext>) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("SKILL.md"),
        "---\nname: demo\ndescription: a demo\n---\nbody\n",
    )
    .unwrap();
    fs::write(dir.path().join("bin.dat"), [0xffu8, 0xfe, 0x00, 0x80]).unwrap();
    fs::write(dir.path().join("bom.txt"), b"\xef\xbb\xbfhello").unwrap();
    let inv = build_inventory(dir.path()).unwrap();
    let skill: SkillTarget = detect_skill(&inv, dir.path()).unwrap();
    let roles = skillsniff::target::skill::SkillTarget::classify(&skill, &inv);
    let ctx = ScanContext {
        root: dir.path().to_path_buf(),
        inventory: inv,
        roles,
        skill,
    };
    (dir, Arc::new(ctx))
}

fn sig(kind: &str) -> Signal {
    Signal {
        kind: kind.to_string(),
        fields: BTreeMap::new(),
        locations: vec![],
        evidence: String::new(),
    }
}

enum Behavior {
    Emit(Duration),
    Panic,
}

struct Stub {
    id: &'static str,
    behavior: Behavior,
}

impl Analyzer for Stub {
    fn id(&self) -> &'static str {
        self.id
    }
    fn run(&self, _ctx: &ScanContext) -> AnalyzerOutput {
        match &self.behavior {
            Behavior::Emit(d) => {
                std::thread::sleep(*d);
                AnalyzerOutput {
                    signals: vec![sig(self.id)],
                    coverage: Coverage::Ran,
                }
            }
            Behavior::Panic => panic!("boom"),
        }
    }
}

fn stub(id: &'static str, behavior: Behavior) -> Arc<dyn Analyzer> {
    Arc::new(Stub { id, behavior })
}

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl ProgressSink for Recorder {
    fn event(&self, e: ProgressEvent) {
        let s = match e {
            ProgressEvent::Started { id } => format!("started {id}"),
            ProgressEvent::Finished { id, signals } => format!("finished {id} {signals}"),
            ProgressEvent::Failed { id } => format!("failed {id}"),
        };
        self.0.lock().unwrap().push(s);
    }
}

#[test]
fn panicking_analyzer_is_failed_others_complete() {
    let (_d, ctx) = make_ctx();
    let (signals, cov) = run_analyzers(
        ctx,
        vec![
            stub("a-ok", Behavior::Emit(Duration::ZERO)),
            stub("b-panic", Behavior::Panic),
            stub("c-ok", Behavior::Emit(Duration::ZERO)),
        ],
        Duration::from_secs(5),
        &NoopProgress,
    );
    assert_eq!(cov["a-ok"], Coverage::Ran);
    assert_eq!(cov["c-ok"], Coverage::Ran);
    assert_eq!(
        cov["b-panic"],
        Coverage::Failed {
            reason: "analyzer panicked".into()
        }
    );
    let kinds: Vec<_> = signals.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["a-ok", "c-ok"]);
}

#[test]
fn slow_analyzer_times_out() {
    let (_d, ctx) = make_ctx();
    let (signals, cov) = run_analyzers(
        ctx,
        vec![
            stub("fast", Behavior::Emit(Duration::ZERO)),
            stub("slow", Behavior::Emit(Duration::from_secs(3))),
        ],
        Duration::from_millis(200),
        &NoopProgress,
    );
    assert_eq!(cov["fast"], Coverage::Ran);
    assert_eq!(
        cov["slow"],
        Coverage::Failed {
            reason: "timed out after 1s".into()
        }
    );
    assert_eq!(signals.len(), 1);
}

#[test]
fn output_order_is_independent_of_finish_order() {
    let (_d, ctx) = make_ctx();
    let (signals, _) = run_analyzers(
        ctx,
        vec![
            stub("z", Behavior::Emit(Duration::ZERO)),
            stub("m", Behavior::Emit(Duration::from_millis(150))),
            stub("a", Behavior::Emit(Duration::from_millis(50))),
        ],
        Duration::from_secs(5),
        &NoopProgress,
    );
    let kinds: Vec<_> = signals.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["a", "m", "z"]);
}

#[test]
fn progress_events_emitted_per_analyzer() {
    let (_d, ctx) = make_ctx();
    let rec = Recorder::default();
    run_analyzers(
        ctx,
        vec![
            stub("b", Behavior::Panic),
            stub("a", Behavior::Emit(Duration::ZERO)),
        ],
        Duration::from_secs(5),
        &rec,
    );
    let ev = rec.0.lock().unwrap().clone();
    assert_eq!(&ev[..2], ["started a", "started b"]);
    assert_eq!(ev.len(), 4);
    assert!(ev.contains(&"finished a 1".to_string()));
    assert!(ev.contains(&"failed b".to_string()));
}

#[test]
fn read_text_is_restricted_and_strict() {
    let (d, ctx) = make_ctx();
    assert!(ctx.read_text("SKILL.md").unwrap().contains("body"));
    assert_eq!(ctx.read_text("bom.txt").as_deref(), Some("hello"));
    assert_eq!(ctx.read_text("bin.dat"), None);
    assert_eq!(ctx.read_text("missing.txt"), None);
    // Present on disk but absent from the inventory.
    fs::write(d.path().join("late.txt"), "x").unwrap();
    assert_eq!(ctx.read_text("late.txt"), None);
    assert_eq!(ctx.read_text("../escape.txt"), None);
}
