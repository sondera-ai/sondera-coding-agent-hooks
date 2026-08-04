//! Provider-agnostic message content blocks.
//!
//! Coding-agent transcripts encode a message's body either as a plain string or
//! as a list of typed blocks (text, thinking, tool use, …). [`ContentBlocks`]
//! normalizes both shapes into a `Vec<ContentBlock>` so hook transcript parsers
//! can iterate uniformly. Moved here from the former `sondera-common` crate.

use serde::Deserialize;

/// A single typed block within a message's content.
///
/// Only the text-bearing variants are modeled explicitly; every other block
/// kind (tool use, tool result, images, …) deserializes into [`ContentBlock::Other`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Assistant or user text.
    Text { text: String },
    /// Assistant reasoning ("thinking") text.
    Thinking { thinking: String },
    /// Any other block kind, retained positionally but not interpreted.
    #[serde(other)]
    Other,
}

/// A message body: an ordered list of [`ContentBlock`]s.
///
/// Deserializes from either a plain string (wrapped as a single
/// [`ContentBlock::Text`]) or a JSON array of blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(from = "ContentBlocksRepr")]
pub struct ContentBlocks(pub Vec<ContentBlock>);

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ContentBlocksRepr {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl From<ContentBlocksRepr> for ContentBlocks {
    fn from(value: ContentBlocksRepr) -> Self {
        match value {
            ContentBlocksRepr::Text(text) => Self(vec![ContentBlock::Text { text }]),
            ContentBlocksRepr::Blocks(blocks) => Self(blocks),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_plain_string_as_single_text_block() {
        let blocks: ContentBlocks = serde_json::from_str(r#""hello""#).unwrap();
        assert_eq!(
            blocks.0,
            vec![ContentBlock::Text {
                text: "hello".into()
            }]
        );
    }

    #[test]
    fn deserializes_typed_block_array() {
        let blocks: ContentBlocks = serde_json::from_str(
            r#"[{"type":"text","text":"hi"},{"type":"thinking","thinking":"hmm"},{"type":"tool_use","id":"x"}]"#,
        )
        .unwrap();
        assert_eq!(
            blocks.0,
            vec![
                ContentBlock::Text { text: "hi".into() },
                ContentBlock::Thinking {
                    thinking: "hmm".into()
                },
                ContentBlock::Other,
            ]
        );
    }

    #[test]
    fn defaults_to_empty() {
        assert_eq!(ContentBlocks::default().0, Vec::new());
    }
}
