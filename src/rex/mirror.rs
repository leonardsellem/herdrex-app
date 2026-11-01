//! The app's spaces, tabs and splits are Rex's sessions, windows and
//! layouts. The bridge serves the `herdr-app` document as a projection of
//! every session's `session.view`, and applies the app's writes to Rex.
//! What Rex can't hold (a space's folder, the app's IDs, mod panels, pane
//! weights) stays in rex/layout.json (store::Layout), and a tab's tree as
//! the app wrote it is served back while Rex's layout still matches it.
//!
//! The document's version moves only when the projection does: the bridge's
//! own changes to Rex come back as the document the app just wrote.

use super::layout::{self, Shape, hex};
use super::{Bridge, SHELL, now_ms, store};
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::Duration;

pub const DOC: &str = "herdr-app";
/// The label of the block that holds a new window open while terminals move into it.
pub const PLACEHOLDER: &str = "herdr-placeholder";
/// The label of the session that holds terminals started outside any space.
const PARKING: &str = "herdr";
/// How long a session made for a terminal stays out of the document waiting for the app to name it.
const PENDING_MS: u64 = 10_000;

#[derive(Default)]
pub struct Mirror {
    pub layout: store::Layout,
    /// Session IDs and labels, in Rex's order.
    sessions: Vec<(String, String)>,
    views: HashMap<String, Value>,
    /// The document last served, and the sessions in it.
    served: Value,
    served_sessions: HashSet<String>,
}

/// Where each terminal is: by address, its block and session.
type Places = HashMap<String, (String, String)>;

impl Mirror {
    fn session_of(&self, space: &str) -> Option<String> {
        self.layout
            .spaces
            .iter()
            .find(|s| s.id == space)
            .map(|s| s.session.clone())
            .or_else(|| self.sessions.iter().find(|(id, _)| format!("sp{}", hex(id)) == space).map(|(id, _)| id.clone()))
    }
}

/// Rex's default window label (`Window 89abcdef`), which herdr leaves to the terminal's title.
fn tab_name(label: &str) -> &str {
    match label.strip_prefix("Window ") {
        Some(rest) if rest.len() == 8 && rest.chars().all(|c| c.is_ascii_hexdigit()) => "",
        _ => label,
    }
}

fn windows(view: &Value) -> impl Iterator<Item = &Value> {
    view["windows"].as_array().into_iter().flatten()
}

fn tiled(window: &Value) -> &Value {
    window["layers"].as_array().and_then(|l| l.iter().find(|l| l["kind"] == "tiled")).map_or(&Value::Null, |l| &l["layout"])
}

/// The blocks in a window's layout (not its floating layers).
fn tiled_blocks(window: &Value) -> Vec<String> {
    let mut found = Vec::new();
    fn walk(node: &Value, found: &mut Vec<String>) {
        if let Some(block) = node["block_id"].as_str() {
            found.push(block.to_owned());
        }
        walk_split(&node["split"], found);
    }
    fn walk_split(split: &Value, found: &mut Vec<String>) {
        if split.is_object() {
            walk(&split["before"], found);
            walk(&split["after"], found);
        }
    }
    walk(tiled(window), &mut found);
    found
}

fn window<'a>(view: &'a Value, id: &str) -> Option<&'a Value> {
    windows(view).find(|w| w["window_id"] == id)
}

impl Bridge {
    pub(super) fn start_mirror(self: &std::sync::Arc<Self>, sessions: &[Value]) -> Result<mpsc::Sender<()>> {
        let mut m = self.mirror.lock().unwrap();
        m.layout = store::layout()?;
        // Earlier bridges parked every terminal in a session labelled `herdr`.
        if m.layout.parking.is_none() {
            m.layout.parking = sessions.iter().find(|s| s["label"] == PARKING).and_then(|s| s["session_id"].as_str()).map(str::to_owned);
        }
        self.refresh(&mut m)?;
        let (served, sessions) = self.project(&m);
        m.served = served;
        m.served_sessions = sessions;
        drop(m);
        let (kick, kicks) = mpsc::channel();
        let b = self.clone();
        std::thread::Builder::new().name("rex-mirror".into()).spawn(move || {
            while kicks.recv().is_ok() {
                // A change in Rex comes as a burst of events: one look after it settles.
                while kicks.recv_timeout(Duration::from_millis(40)).is_ok() {}
                if let Err(e) = b.rex_changed() {
                    eprintln!("herdr-app rex-core: cannot read Rex's layout: {e:#}");
                }
            }
        })?;
        Ok(kick)
    }

    pub(super) fn kick_mirror(&self) {
        if let Some(kick) = self.kick.lock().unwrap().as_ref() {
            let _ = kick.send(());
        }
    }

    fn rex_changed(&self) -> Result<()> {
        let mut m = self.mirror.lock().unwrap();
        self.refresh(&mut m)?;
        let (projection, sessions) = self.project(&m);
        m.served_sessions = sessions;
        if projection != m.served {
            m.served = projection;
            m.layout.version += 1;
            store::set_layout(&m.layout)?;
            self.doc_changed(m.layout.version);
        }
        Ok(())
    }

    pub(super) fn doc_get(&self) -> Value {
        let m = self.mirror.lock().unwrap();
        json!({"value": m.served, "version": m.layout.version})
    }

    /// The session terminals outside any space go in, made when first needed.
    pub(super) fn parking(&self) -> Result<String> {
        let mut m = self.mirror.lock().unwrap();
        if let Some(id) = m.layout.parking.clone().filter(|id| m.sessions.iter().any(|(s, _)| s == id)) {
            return Ok(id);
        }
        let id = self.create_session(Some(PARKING))?;
        m.layout.parking = Some(id.clone());
        store::set_layout(&m.layout)?;
        Ok(id)
    }

    /// The session for the app's space `space`. A space the app hasn't
    /// written yet gets a session now, kept out of the document until it does.
    pub(super) fn space_session(&self, space: &str) -> Result<String> {
        let mut m = self.mirror.lock().unwrap();
        if let Some(id) = m.session_of(space) {
            return Ok(id);
        }
        let id = self.create_session(None)?;
        m.sessions.push((id.clone(), String::new()));
        m.layout.spaces.push(store::Space { id: space.to_owned(), session: id.clone(), pending_ms: Some(now_ms()), ..Default::default() });
        store::set_layout(&m.layout)?;
        Ok(id)
    }

    fn create_session(&self, label: Option<&str>) -> Result<String> {
        let made = self.rex.call("session.create", label.map_or(json!({}), |l| json!({"label": l})))?;
        made["session_id"].as_str().map(str::to_owned).ok_or_else(|| anyhow!("Rex made no session"))
    }

    fn view(&self, session: &str) -> Result<Value> {
        self.attach_session(session)?;
        self.rex.call("session.view", json!({"session_id": session}))
    }

    fn refresh(&self, m: &mut Mirror) -> Result<()> {
        let list = self.rex.call("session.list", json!({}))?;
        m.sessions = list["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| Some((s["session_id"].as_str()?.to_owned(), s["label"].as_str().unwrap_or_default().to_owned())))
            .collect();
        let mut views = HashMap::new();
        for (id, _) in &m.sessions {
            match self.view(id) {
                Ok(view) => {
                    views.insert(id.clone(), view);
                }
                // Destroyed since the list.
                Err(e) => eprintln!("herdr-app rex-core: cannot read session {id}: {e:#}"),
            }
        }
        m.views = views;
        let live: HashSet<&String> = m.sessions.iter().map(|(id, _)| id).collect();
        m.layout.spaces.retain(|s| live.contains(&s.session));
        if m.layout.parking.as_ref().is_some_and(|p| !live.contains(p)) {
            m.layout.parking = None;
        }
        Ok(())
    }

    fn places(&self) -> Places {
        let st = self.state.lock().unwrap();
        st.terms.iter().map(|(address, t)| (address.clone(), (t.block.clone(), t.session.clone()))).collect()
    }

    /// The document for Rex as it is, and the sessions in it.
    fn project(&self, m: &Mirror) -> (Value, HashSet<String>) {
        let places = self.places();
        let address_of: HashMap<&str, &str> = places.iter().map(|(a, (b, _))| (b.as_str(), a.as_str())).collect();
        let mut order: Vec<&str> = m.layout.spaces.iter().filter(|s| s.pending_ms.is_none()).map(|s| s.session.as_str()).collect();
        let pending: HashSet<&str> = m.layout.spaces.iter().filter(|s| s.pending_ms.is_some()).map(|s| s.session.as_str()).collect();
        for (id, _) in &m.sessions {
            // The parking session shows once someone gives it a window in Rex.
            let parked = m.layout.parking.as_ref() == Some(id) && m.views.get(id).is_none_or(|v| windows(v).next().is_none());
            if !order.contains(&id.as_str()) && !pending.contains(id.as_str()) && !parked {
                order.push(id);
            }
        }
        let mut spaces = Vec::new();
        let mut shown = HashSet::new();
        for session in order {
            let Some(view) = m.views.get(session) else { continue };
            let saved = m.layout.spaces.iter().find(|s| s.session == session);
            let label = view["label"].as_str().unwrap_or_default();
            let name = match saved {
                Some(s) if s.label == label => s.name.clone(),
                _ => label.to_owned(),
            };
            let mut tabs: Vec<Value> = Vec::new();
            for w in windows(view) {
                let window_id = w["window_id"].as_str().unwrap_or_default();
                let Some(shape) = layout::from_rex(tiled(w), &|b| address_of.contains_key(b)) else { continue };
                let tab = saved.and_then(|s| s.tabs.iter().find(|t| t.window.as_deref() == Some(window_id)));
                let id = tab.map_or_else(|| format!("tb{}", hex(window_id)), |t| t.id.clone());
                let root = match tab {
                    Some(t) if fits(&t.root, &shape, session, &places) => t.root.clone(),
                    _ => layout::to_herdr(&shape, &id, &|b| address_of.get(b).copied().unwrap_or_default().to_owned()),
                };
                let label = w["label"].as_str().unwrap_or_default();
                let name = match tab {
                    Some(t) if t.label == label => t.name.clone(),
                    _ => tab_name(label).to_owned(),
                };
                tabs.push(json!({"id": id, "name": name, "root": root}));
            }
            // Tabs only the app has go back after the tab they followed.
            if let Some(saved) = saved {
                for (i, t) in saved.tabs.iter().enumerate().filter(|(_, t)| t.window.is_none()) {
                    let after = saved.tabs[..i].iter().rev().find_map(|p| tabs.iter().position(|x| x["id"] == p.id.as_str()));
                    tabs.insert(after.map_or(0, |p| p + 1), json!({"id": t.id, "name": t.name, "root": t.root}));
                }
            }
            spaces.push(json!({
                "id": saved.map_or_else(|| format!("sp{}", hex(session)), |s| s.id.clone()),
                "name": name,
                "folder": saved.map(|s| s.folder.as_str()).unwrap_or_default(),
                "tabs": tabs,
            }));
            shown.insert(session.to_owned());
        }
        (json!({"spaces": spaces}), shown)
    }

    /// The app's write of the document: Rex is made to match it.
    pub(super) fn doc_set(&self, value: &Value, version: u64) -> Result<Result<u64, u64>> {
        let mut m = self.mirror.lock().unwrap();
        if version != m.layout.version {
            return Ok(Err(m.layout.version));
        }
        self.refresh(&mut m)?;
        let mut spaces = Vec::new();
        let mut wanted_sessions = HashSet::new();
        for space in value["spaces"].as_array().into_iter().flatten() {
            match self.apply_space(&mut m, space) {
                Ok(saved) => {
                    wanted_sessions.insert(saved.session.clone());
                    spaces.push(saved);
                }
                Err(e) => {
                    eprintln!("herdr-app rex-core: cannot make space {} in Rex: {e:#}", space["id"]);
                    // Not closed: kept as it was.
                    if let Some(saved) = space["id"].as_str().and_then(|id| m.layout.spaces.iter().find(|s| s.id == id)) {
                        wanted_sessions.insert(saved.session.clone());
                        spaces.push(store::Space { pending_ms: None, ..saved.clone() });
                    }
                }
            }
        }
        // Spaces the app closed.
        for session in m.served_sessions.clone() {
            if !wanted_sessions.contains(&session) {
                self.act("session.destroy", json!({"session_id": session}));
            }
        }
        let now = now_ms();
        for s in &m.layout.spaces {
            if let Some(made) = s.pending_ms
                && !wanted_sessions.contains(&s.session)
            {
                // The app never named it: show it as it is.
                let pending_ms = (now.saturating_sub(made) < PENDING_MS).then_some(made);
                spaces.push(store::Space { pending_ms, ..s.clone() });
            }
        }
        m.layout.spaces = spaces;
        m.layout.version += 1;
        let written = m.layout.version;
        self.refresh(&mut m)?;
        let (projection, sessions) = self.project(&m);
        m.served_sessions = sessions;
        let differs = &projection != value;
        m.served = projection;
        if differs {
            // Rex couldn't take all of it: the app reads what it did take.
            m.layout.version += 1;
        }
        store::set_layout(&m.layout)?;
        self.doc_changed(m.layout.version);
        Ok(Ok(written))
    }

    /// Makes one space's session match the app's space, and what to keep of it.
    fn apply_space(&self, m: &mut Mirror, space: &Value) -> Result<store::Space> {
        let id = space["id"].as_str().unwrap_or_default();
        let name = space["name"].as_str().unwrap_or_default();
        let folder = space["folder"].as_str().unwrap_or_default();
        let session = match m.session_of(id) {
            Some(s) => s,
            None => {
                let s = self.create_session(None)?;
                m.sessions.push((s.clone(), String::new()));
                s
            }
        };
        let saved = m.layout.spaces.iter().find(|s| s.session == session).cloned().unwrap_or_default();
        // An unnamed space is named after its folder in Rex, as the app shows it.
        let folder_name = std::path::Path::new(folder).file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let label = [name.trim(), folder_name].into_iter().find(|l| !l.is_empty());
        let view = self.view(&session)?;
        if let Some(label) = label
            && view["label"] != label
        {
            self.act("session.set_label", json!({"session_id": session, "label": label.chars().take(128).collect::<String>()}));
        }

        let places = self.places();
        let block_of = |a: &str| places.get(a).filter(|(_, s)| *s == session).map(|(b, _)| b.clone());
        let mut tabs = Vec::new();
        let mut wanted: HashSet<String> = HashSet::new();
        for tab in space["tabs"].as_array().into_iter().flatten() {
            let tab_id = tab["id"].as_str().unwrap_or_default();
            let shape = layout::from_herdr(&tab["root"], &block_of);
            let known = saved.tabs.iter().find(|t| t.id == tab_id).and_then(|t| t.window.clone());
            let window = match &shape {
                None => None,
                Some(shape) => {
                    wanted.extend(shape.leaves().into_iter().map(str::to_owned));
                    let view = self.view(&session)?;
                    let at = known.filter(|w| window(&view, w).is_some()).or_else(|| windows(&view).find(|w| format!("tb{}", hex(w["window_id"].as_str().unwrap_or_default())) == tab_id).and_then(|w| w["window_id"].as_str().map(str::to_owned)));
                    let fits = at.as_deref().and_then(|w| window(&view, w)).and_then(|w| layout::from_rex(tiled(w), &|b| places.values().any(|(x, _)| x == b))).is_some_and(|s| s.same(shape));
                    if fits { at } else { self.arrange(&session, at.as_deref(), shape) }
                }
            };
            let name = tab["name"].as_str().unwrap_or_default();
            if let Some(w) = &window
                && !name.trim().is_empty()
            {
                self.act("session.set_window_label", json!({"session_id": session, "window_id": w, "label": name.trim().chars().take(128).collect::<String>()}));
            }
            tabs.push(store::Tab { id: tab_id.to_owned(), window, name: name.to_owned(), label: String::new(), root: tab["root"].clone() });
        }

        // The app's tab order, then terminals it took out of every tab go on running detached.
        let view = self.view(&session)?;
        let order: Vec<&str> = tabs.iter().filter_map(|t| t.window.as_deref()).collect();
        let now: Vec<&str> = windows(&view).filter_map(|w| w["window_id"].as_str()).filter(|w| order.contains(w)).collect();
        if now != order {
            for w in &order {
                self.act("session.move_window", json!({"session_id": session, "window_id": w}));
            }
        }
        for w in windows(&view) {
            for block in tiled_blocks(w) {
                if places.values().any(|(b, _)| *b == block) && !wanted.contains(&block) {
                    self.act("session.detach_block", json!({"session_id": session, "block_id": block}));
                }
            }
        }

        let view = self.view(&session)?;
        for t in &mut tabs {
            if let Some(w) = t.window.as_deref().and_then(|w| window(&view, w)) {
                t.label = w["label"].as_str().unwrap_or_default().to_owned();
            }
        }
        Ok(store::Space {
            id: id.to_owned(),
            session,
            name: name.to_owned(),
            folder: folder.to_owned(),
            label: view["label"].as_str().unwrap_or_default().to_owned(),
            tabs,
            pending_ms: None,
        })
    }

    /// Builds `shape` in `window`, or in a new window when it has none.
    /// Returns the window.
    fn arrange(&self, session: &str, window_id: Option<&str>, shape: &Shape) -> Option<String> {
        let first = shape.first();
        let (window_id, anchor, placeholder) = match window_id {
            Some(w) => {
                let view = self.view(session).ok()?;
                let blocks = tiled_blocks(window(&view, w)?);
                (w.to_owned(), (!blocks.iter().any(|b| b == first)).then(|| blocks.first().cloned()).flatten(), None)
            }
            None => {
                // Rex makes windows with new blocks only: one holds the window while the terminals move in.
                let made = self.act("session.new_window", json!({
                    "session_id": session,
                    "focus": false,
                    "layout": {"block": {"flavor": SHELL, "label": PLACEHOLDER, "options": {"shell": "none", "command": ["/bin/sleep", "600"]}}},
                }))?;
                let block = made["block_ids"][0].as_str()?.to_owned();
                (made["window_id"].as_str()?.to_owned(), Some(block.clone()), Some(block))
            }
        };
        if let Some(anchor) = anchor {
            self.act("session.move_block", json!({"session_id": session, "block_id": first, "anchor_block_id": anchor}));
        }
        for mv in shape.moves() {
            self.act("session.move_block", json!({
                "session_id": session,
                "block_id": mv.block,
                "anchor_block_id": mv.anchor,
                "direction": if mv.side_by_side { "horizontal" } else { "vertical" },
                "side": "after",
                "ratio": mv.ratio,
            }));
        }
        if let Some(block) = placeholder {
            self.act("block.close", json!({"session_id": session, "block_id": block}));
        }
        Some(window_id)
    }

    /// A layout change that may fail on its own (the rest goes on): logged.
    fn act(&self, method: &str, payload: Value) -> Option<Value> {
        match self.rex.call(method, payload) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("herdr-app rex-core: {method}: {e:#}");
                None
            }
        }
    }
}

/// Whether the app's tree for a tab still says what Rex's window holds:
/// the same terminals, placed the same way, none of them in another session.
fn fits(root: &Value, shape: &Shape, session: &str, places: &Places) -> bool {
    let elsewhere = layout::addresses(root).iter().any(|a| places.get(a).is_some_and(|(_, s)| s != session));
    let block_of = |a: &str| places.get(a).filter(|(_, s)| s == session).map(|(b, _)| b.clone());
    !elsewhere && layout::from_herdr(root, &block_of).is_some_and(|h| h.same(shape))
}
