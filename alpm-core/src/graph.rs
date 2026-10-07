// port of lib/libalpm/graph.c: the vertex _alpm_sortbydeps walks.
//
// vertices live in one Vec owned by the caller, parent/children are
// positions in it instead of pointers. _alpm_graph_free is Drop. the off_t
// weight field is left out: nothing upstream reads or writes it.

// enum _alpm_graph_vertex_state
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
	#[default]
	Unprocessed,
	Processing,
	Processed,
}

// alpm_graph_t. iterator is the position in children of the next child
// to visit (the C keeps a list node, NULL once past the end)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph<T> {
	pub data: T,
	pub parent: Option<usize>,
	pub children: Vec<usize>,
	pub iterator: usize,
	pub state: State,
}

impl<T> Graph<T> {
	// _alpm_graph_new (calloc) with data set
	pub fn new(data: T) -> Self {
		Graph {
			data,
			parent: None,
			children: Vec::new(),
			iterator: 0,
			state: State::Unprocessed,
		}
	}

	// the child the iterator points at, advancing it
	pub fn next_child(&mut self) -> Option<usize> {
		let c = *self.children.get(self.iterator)?;
		self.iterator += 1;
		Some(c)
	}
}
