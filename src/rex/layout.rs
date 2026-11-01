//! A herdr tab's tree and a Rex window's layout as one shape: the terminal
//! blocks and how they split the space. Herdr's rows and columns hold any
//! number of children; Rex splits in two. Both read as `Shape`, and compare
//! after chains of same-direction splits are flattened (`Group`).

use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq)]
pub enum Shape {
    /// A Rex block ID.
    Leaf(String),
    Split { side_by_side: bool, ratio: f64, before: Box<Shape>, after: Box<Shape> },
}

/// A shape with every chain of same-direction splits made one group.
#[derive(Debug, PartialEq)]
pub enum Group {
    Leaf(String),
    Items { side_by_side: bool, items: Vec<(Group, f64)> },
}

/// One `session.move_block`: put `block` after `anchor`, splitting its space.
#[derive(Debug, PartialEq)]
pub struct Move {
    pub block: String,
    pub anchor: String,
    pub side_by_side: bool,
    pub ratio: f64,
}

impl Shape {
    pub fn first(&self) -> &str {
        match self {
            Shape::Leaf(block) => block,
            Shape::Split { before, .. } => before.first(),
        }
    }

    pub fn leaves(&self) -> Vec<&str> {
        match self {
            Shape::Leaf(block) => vec![block],
            Shape::Split { before, after, .. } => [before.leaves(), after.leaves()].concat(),
        }
    }

    pub fn group(&self) -> Group {
        match self {
            Shape::Leaf(block) => Group::Leaf(block.clone()),
            Shape::Split { side_by_side, .. } => Group::Items { side_by_side: *side_by_side, items: self.chain(*side_by_side, 1.0) },
        }
    }

    /// The items of a chain of `side_by_side` splits, each with its share of the space.
    fn chain(&self, side_by_side: bool, share: f64) -> Vec<(Group, f64)> {
        match self {
            Shape::Split { side_by_side: s, ratio, before, after } if *s == side_by_side => {
                let mut items = before.chain(side_by_side, share * ratio);
                items.extend(after.chain(side_by_side, share * (1.0 - ratio)));
                items
            }
            other => vec![(other.group(), share)],
        }
    }

    /// Whether the two place the same blocks the same way, whatever their sizes.
    pub fn same(&self, other: &Shape) -> bool {
        fn strip(g: Group) -> Group {
            match g {
                Group::Leaf(b) => Group::Leaf(b),
                Group::Items { side_by_side, items } => Group::Items { side_by_side, items: items.into_iter().map(|(g, _)| (strip(g), 0.0)).collect() },
            }
        }
        strip(self.group()) == strip(other.group())
    }

    /// The moves that build this shape in the space its first block has,
    /// each beside a block already placed.
    pub fn moves(&self) -> Vec<Move> {
        let mut moves = Vec::new();
        self.place(&mut moves);
        moves
    }

    fn place(&self, moves: &mut Vec<Move>) {
        if let Shape::Split { side_by_side, ratio, before, after } = self {
            moves.push(Move { block: after.first().to_owned(), anchor: before.first().to_owned(), side_by_side: *side_by_side, ratio: ratio.clamp(0.05, 0.95) });
            before.place(moves);
            after.place(moves);
        }
    }
}

/// A Rex layout node (`session.view`), keeping the blocks `keep` accepts.
pub fn from_rex(node: &Value, keep: &impl Fn(&str) -> bool) -> Option<Shape> {
    if let Some(block) = node["block_id"].as_str() {
        return keep(block).then(|| Shape::Leaf(block.to_owned()));
    }
    let split = &node["split"];
    let before = from_rex(&split["before"], keep);
    let after = from_rex(&split["after"], keep);
    match (before, after) {
        (Some(before), Some(after)) => Some(Shape::Split {
            side_by_side: split["direction"] != "vertical",
            ratio: split["ratio"].as_f64().unwrap_or(0.5),
            before: Box::new(before),
            after: Box::new(after),
        }),
        (one, None) | (None, one) => one,
    }
}

/// A herdr layout node: terminal panes whose address `block_of` knows.
/// Mod panels and dead terminals have no place in Rex. A stack shows one
/// child at a time; in Rex its terminals sit one above the other.
pub fn from_herdr(node: &Value, block_of: &impl Fn(&str) -> Option<String>) -> Option<Shape> {
    let kind = node["type"].as_str().unwrap_or_default();
    if kind == "block" {
        return block_of(node["content"]["terminal"].as_str()?).map(Shape::Leaf);
    }
    let items: Vec<(Shape, f64)> = node["children"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|child| Some((from_herdr(child, block_of)?, child["size"]["weight"].as_f64().filter(|w| *w > 0.0).unwrap_or(1.0))))
        .collect();
    let side_by_side = kind == "row";
    let mut items = items.into_iter().rev();
    let (mut shape, mut weight) = items.next()?;
    for (before, w) in items {
        shape = Shape::Split { side_by_side, ratio: w / (w + weight), before: Box::new(before), after: Box::new(shape) };
        weight += w;
    }
    Some(shape)
}

/// Every terminal address in a herdr layout node.
pub fn addresses(node: &Value) -> Vec<String> {
    let mut found: Vec<String> = node["content"]["terminal"].as_str().map(str::to_owned).into_iter().collect();
    for child in node["children"].as_array().into_iter().flatten() {
        found.extend(addresses(child));
    }
    found
}

/// The ID part of a Rex ID, as herdr IDs use it: `block:01a1-…` is `01a1…`.
pub fn hex(id: &str) -> String {
    id.split_once(':').map_or(id, |(_, rest)| rest).replace('-', "")
}

/// A herdr tab root (`id` is the tab's) for a Rex shape.
pub fn to_herdr(shape: &Shape, id: &str, address_of: &impl Fn(&str) -> String) -> Value {
    let children = match shape.group() {
        Group::Items { side_by_side: true, items } => items.iter().map(|(g, share)| node(g, *share, 1, address_of)).collect(),
        group => vec![node(&group, 1.0, 1, address_of)],
    };
    json!({"id": id, "type": "row", "children": children})
}

fn node(group: &Group, share: f64, depth: usize, address_of: &impl Fn(&str) -> String) -> Value {
    let size = json!({"weight": share});
    match group {
        Group::Leaf(block) => json!({"id": format!("p{}", hex(block)), "type": "block", "content": {"terminal": address_of(block)}, "size": size}),
        Group::Items { side_by_side, items } => {
            let first = items.first().map(|(g, _)| first_leaf(g)).unwrap_or_default();
            let total: f64 = items.iter().map(|(_, s)| s).sum();
            json!({
                "id": format!("s{depth}{}", hex(first)),
                "type": if *side_by_side { "row" } else { "column" },
                "children": items.iter().map(|(g, s)| node(g, s / total.max(f64::EPSILON), depth + 1, address_of)).collect::<Vec<_>>(),
                "size": size,
            })
        }
    }
}

fn first_leaf(group: &Group) -> &str {
    match group {
        Group::Leaf(block) => block,
        Group::Items { items, .. } => items.first().map(|(g, _)| first_leaf(g)).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: &str) -> Value {
        json!({"block_id": id})
    }

    fn split(direction: &str, ratio: f64, before: Value, after: Value) -> Value {
        json!({"split": {"direction": direction, "ratio": ratio, "before": before, "after": after}})
    }

    #[test]
    fn a_rex_layout_and_a_herdr_tab_compare_as_one_shape() {
        let terminals = |b: &str| b != "onboarding";
        // (a | b) | c, with Rex's onboarding block above c.
        let rex = split("horizontal", 0.66, split("horizontal", 0.5, leaf("a"), leaf("b")), split("vertical", 0.3, leaf("onboarding"), leaf("c")));
        let shape = from_rex(&rex, &terminals).unwrap();
        assert_eq!(shape.leaves(), ["a", "b", "c"]);

        let address = |b: &str| format!("t-{b}");
        let tab = to_herdr(&shape, "tb1", &address);
        assert_eq!(tab["type"], "row");
        assert_eq!(tab["children"].as_array().unwrap().len(), 3, "one row of three, not nested pairs");
        assert_eq!(tab["children"][2]["content"]["terminal"], "t-c");
        let weight = tab["children"][0]["size"]["weight"].as_f64().unwrap();
        assert!((weight - 0.33).abs() < 0.01);

        let block_of = |a: &str| a.strip_prefix("t-").map(str::to_owned);
        let back = from_herdr(&tab, &block_of).unwrap();
        assert!(back.same(&shape));
        assert_ne!(back, shape, "herdr nests to the right; still the same layout");

        // A mod panel and a dead terminal leave the shape alone.
        let mut with_extras = tab.clone();
        with_extras["children"].as_array_mut().unwrap().push(json!({"id": "m", "type": "block", "content": {"context": "files"}}));
        with_extras["children"].as_array_mut().unwrap().push(json!({"id": "d", "type": "block", "content": {"terminal": "gone"}}));
        assert!(from_herdr(&with_extras, &block_of).unwrap().same(&shape));
        assert_eq!(addresses(&with_extras), ["t-a", "t-b", "t-c", "gone"]);

        let column = json!({"type": "row", "children": [{"type": "column", "children": [
            {"type": "block", "content": {"terminal": "t-a"}}, {"type": "block", "content": {"terminal": "t-b"}}]}]});
        assert!(!from_herdr(&column, &block_of).unwrap().same(&shape));
    }

    #[test]
    fn moves_build_a_shape_from_its_first_block() {
        let tab = json!({"type": "row", "children": [
            {"type": "block", "content": {"terminal": "a"}, "size": {"weight": 2.0}},
            {"type": "column", "children": [{"type": "block", "content": {"terminal": "b"}}, {"type": "block", "content": {"terminal": "c"}}]},
        ]});
        let shape = from_herdr(&tab, &|a: &str| Some(a.to_owned())).unwrap();
        let moves = shape.moves();
        assert_eq!(moves.len(), 2);
        assert_eq!((moves[0].block.as_str(), moves[0].anchor.as_str(), moves[0].side_by_side), ("b", "a", true));
        assert!((moves[0].ratio - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!((moves[1].block.as_str(), moves[1].anchor.as_str(), moves[1].side_by_side), ("c", "b", false));
        assert!(Shape::Leaf("a".into()).moves().is_empty());
        assert_eq!(hex("block:01a1-93-0d"), "01a1930d");
    }
}
