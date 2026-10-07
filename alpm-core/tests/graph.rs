// unit tests for alpm_core::graph
use alpm_core::graph::{Graph, State};

#[test]
fn new_is_calloc() {
	let g = Graph::new('x');
	assert_eq!(
		(g.parent, g.iterator, g.state),
		(None, 0, State::Unprocessed)
	);
	assert!(g.children.is_empty());
}

#[test]
fn next_child_walks_once() {
	let mut g = Graph::new(());
	g.children = vec![3, 1];
	assert_eq!(g.next_child(), Some(3));
	assert_eq!(g.next_child(), Some(1));
	assert_eq!(g.next_child(), None);
	assert_eq!(g.iterator, 2);
}
