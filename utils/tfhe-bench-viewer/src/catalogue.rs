//! The bench paths that came back, as a tree.
//!
//! Built from the fetched ids, so a level only ever holds segments that lead
//! somewhere: a path with no results is not in here, and therefore cannot be
//! picked. Pure data; the menus that walk it live in `app`.

#[derive(Default)]
pub struct Node {
    pub segment: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn root() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: &str) {
        let mut node = self;
        for segment in path.split("::") {
            let index = match node.children.iter().position(|c| c.segment == segment) {
                Some(index) => index,
                None => {
                    node.children.push(Node {
                        segment: segment.to_string(),
                        children: Vec::new(),
                    });
                    node.children.len() - 1
                }
            };
            node = &mut node.children[index];
        }
    }

    pub fn sort(&mut self) {
        self.children.sort_by(|a, b| a.segment.cmp(&b.segment));
        for child in &mut self.children {
            child.sort();
        }
    }

    pub fn child(&self, segment: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.segment == segment)
    }

    /// The node a path leads to, if the tree holds it. An empty path is the
    /// node itself, not a child with no name.
    pub fn find(&self, path: &str) -> Option<&Node> {
        if path.is_empty() {
            return Some(self);
        }

        let mut node = self;
        for segment in path.split("::") {
            node = node.child(segment)?;
        }
        Some(node)
    }

    /// A node with no children is a benchmark rather than a family of them.
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

/// Appends a segment to a path, with no leading `::` when there is nothing to
/// lead.
pub fn join(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}::{segment}")
    }
}
