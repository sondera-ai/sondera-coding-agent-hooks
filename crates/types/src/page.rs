//! The result window every paged store read returns.
//!
//! Deliberately free of wire vocabulary: there is no page *token* here, because
//! a token is an AIP-122 encoding of an offset and belongs at the service edge.
//! Stores take an `offset`/`limit` pair on their domain query types and hand
//! back a [`Page`]; whoever serves the RPC mints the next token from
//! `offset + items.len()` against [`Page::total`].

/// One window of results plus the total number of matches behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The items in this window.
    pub items: Vec<T>,
    /// How many items matched in total, across every window.
    pub total: usize,
}

impl<T> Page<T> {
    /// Build a page from its items and the total match count.
    pub fn new(items: Vec<T>, total: usize) -> Self {
        Self { items, total }
    }

    /// Take the window `[offset, offset + limit)` out of `all`, recording the
    /// full length as the total.
    ///
    /// The whole matching set is already in memory on every read this store
    /// surface serves — the projections are folds over a run's events, not SQL
    /// aggregates — so slicing here keeps the offset/limit arithmetic in exactly
    /// one place rather than once per list method.
    pub fn slice(all: Vec<T>, offset: usize, limit: usize) -> Self {
        let total = all.len();
        Self {
            items: all.into_iter().skip(offset).take(limit).collect(),
            total,
        }
    }
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_keeps_the_total_behind_a_partial_window() {
        let page = Page::slice(vec![1, 2, 3, 4, 5], 2, 2);
        assert_eq!(page.items, vec![3, 4]);
        assert_eq!(page.total, 5);
    }

    #[test]
    fn an_offset_past_the_end_yields_an_empty_window_not_an_error() {
        let page = Page::slice(vec![1, 2, 3], 10, 2);
        assert!(page.items.is_empty());
        assert_eq!(page.total, 3);
    }
}
