//! What herdr-core keeps and Rex doesn't: each terminal's address (`t7`),
//! its labels and keep flag, and the app's documents. Kept in the app's home
//! (`rex/`), read and written under a file lock so every bridge agrees.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize)]
pub struct Terminals {
    /// The number in the next address handed out.
    pub next: u64,
    /// By Rex block ID.
    pub blocks: BTreeMap<String, Known>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Known {
    pub address: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub keep: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Doc {
    pub value: Value,
    pub version: u64,
}

fn dir() -> PathBuf {
    crate::mods::app_dir().join("rex")
}

/// Reads `name`, lets `change` edit it, and writes it back if it said so.
fn with_file<T: Default + Serialize + for<'de> Deserialize<'de>, R>(name: &str, change: impl FnOnce(&mut T) -> (bool, R)) -> Result<R> {
    let dir = dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let lock = std::fs::File::create(dir.join(format!("{name}.lock")))?;
    lock.lock()?;
    let path = dir.join(format!("{name}.json"));
    let mut data: T = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let (write, result) = change(&mut data);
    if write {
        let tmp = dir.join(format!("{name}.json.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(&data)?)?;
        std::fs::rename(&tmp, &path)?;
    }
    Ok(result)
}

/// The block's address and labels, giving it the next address if it has none.
pub fn known(block: &str) -> Result<Known> {
    with_file(
        "terminals",
        |t: &mut Terminals| match t.blocks.get(block) {
            Some(k) => (false, k.clone()),
            None => {
                t.next = t.next.max(1);
                let k = Known { address: format!("t{}", t.next), ..Default::default() };
                t.next += 1;
                t.blocks.insert(block.to_owned(), k.clone());
                (true, k)
            }
        },
    )
}

pub fn update(block: &str, change: impl FnOnce(&mut Known)) -> Result<Known> {
    with_file("terminals", |t: &mut Terminals| {
        let k = t.blocks.entry(block.to_owned()).or_default();
        change(k);
        (true, k.clone())
    })
}

/// Forgets blocks Rex no longer has (their addresses are never reused).
pub fn forget(block: &str) -> Result<()> {
    with_file("terminals", |t: &mut Terminals| (t.blocks.remove(block).is_some(), ()))
}

pub fn doc_get(name: &str) -> Result<Doc> {
    with_file("docs", |d: &mut BTreeMap<String, Doc>| (false, d.get(name).map(|d| Doc { value: d.value.clone(), version: d.version }).unwrap_or_default()))
}

/// Writes when `version` is current: Ok(new version), or Err(current version).
pub fn doc_set(name: &str, value: Value, version: u64) -> Result<Result<u64, u64>> {
    with_file("docs", |d: &mut BTreeMap<String, Doc>| {
        let doc = d.entry(name.to_owned()).or_default();
        if doc.version != version {
            return (false, Err(doc.version));
        }
        doc.value = value;
        doc.version += 1;
        (true, Ok(doc.version))
    })
}

/// What the app's layout has that Rex's sessions don't (mirror.rs).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Layout {
    /// The version of the `herdr-app` document the bridge serves.
    pub version: u64,
    /// The session holding terminals started outside any space.
    pub parking: Option<String>,
    /// The app's spaces, in its order.
    pub spaces: Vec<Space>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Space {
    /// The app's ID for it.
    pub id: String,
    pub session: String,
    pub name: String,
    pub folder: String,
    /// The session's label when the app last wrote: another one now was set in Rex.
    pub label: String,
    pub tabs: Vec<Tab>,
    /// Made for a terminal before the app's layout named the space: kept out
    /// of the document until it does. When it was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_ms: Option<u64>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tab {
    pub id: String,
    /// None for a tab with no terminals (only mod panels), which only the app has.
    pub window: Option<String>,
    pub name: String,
    /// The window's label when the app last wrote.
    pub label: String,
    /// The tab's tree as the app wrote it: served back while Rex's layout still matches it.
    pub root: Value,
}

pub fn layout() -> Result<Layout> {
    with_file("layout", |l: &mut Layout| (false, l.clone()))
}

pub fn set_layout(layout: &Layout) -> Result<()> {
    with_file("layout", |l: &mut Layout| {
        *l = layout.clone();
        (true, ())
    })
}
