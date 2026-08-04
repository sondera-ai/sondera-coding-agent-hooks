//! Sondera terminal theme.
//!
//! Five semantic tones under a "color encodes meaning, never decoration" rule,
//! over the three background tiers a terminal cell — which has exactly one
//! background — can actually keep distinct.
//!
//! Every style in this crate is built from here. A literal [`Color`] anywhere
//! else is a bug: it will not degrade on a 256-color terminal and it will not
//! honour `NO_COLOR`.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding};

/// A palette entry: the brand RGB plus a hand-picked xterm-256 fallback.
///
/// The indices are tuned to preserve *separation and ordering* between the
/// surface tiers rather than to be the nearest numerical match — three tiers
/// that collapse to one index are worse than three approximate ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Swatch {
    pub rgb: [u8; 3],
    pub idx: u8,
}

impl Swatch {
    const fn new(rgb: [u8; 3], idx: u8) -> Self {
        Self { rgb, idx }
    }
}

/// The five semantic tones, with the same meanings as the web design system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Electric green — allow, success, healthy.
    Allow,
    /// Amber — escalate, warning, monitor.
    Warn,
    /// Blue — observe, info, neutral data.
    Info,
    /// Coral — deny, destructive, error.
    Deny,
    /// Violet — numeric emphasis, rare states.
    Rare,
    /// No tone: ordinary body content.
    Neutral,
}

impl Tone {
    /// The leading glyph that carries the tone when color cannot.
    ///
    /// Always rendered alongside the color: it is the accessibility floor for
    /// monochrome, 256-color, and colorblind readers, and the reason Sondera
    /// retired the colored left-accent bar product-wide.
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::Allow => "●",
            Self::Warn => "▲",
            Self::Info => "◆",
            Self::Deny => "■",
            Self::Rare => "◇",
            Self::Neutral => "·",
        }
    }
}

/// One step of the brand mark's four-tone ramp, deepest to palest.
///
/// These are brand constants, identical in both appearances — what changes
/// between a light and a dark ground is *which* steps the mark uses, not what
/// the steps are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrandTone {
    Deep,
    Mid,
    Electric,
    Pale,
}

/// The brand mark's ramp, deepest to palest. Indexed by [`BrandTone`], whose
/// variants are declared in the same order.
///
/// `Electric` is the same hex as [`Theme::electric`]; it is repeated here
/// because the mark's ramp is a brand artifact that happens to overlap the
/// semantic palette, not a slice of it.
const BRAND_RAMP: [Swatch; 4] = [
    Swatch::new([0x2c, 0x58, 0x44], 23),
    Swatch::new([0x56, 0x93, 0x78], 66),
    Swatch::new([0x81, 0xdd, 0xb4], 115),
    Swatch::new([0xaa, 0xd8, 0xc4], 151),
];

/// Light or dark. Dark is the Sondera default; light is a re-tuned companion
/// rather than an inversion, so both hue sets are spelled out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appearance {
    Dark,
    Light,
}

/// How much color the terminal can render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// 24-bit: brand hexes render exactly and tone tints are available.
    TrueColor,
    /// 256 indexed: hexes are approximated and tints collapse to the panel
    /// background, so tone rides on foreground + glyph alone.
    Ansi256,
    /// `NO_COLOR` is set — everything falls back to modifiers.
    None,
}

/// The resolved palette for one appearance at one color depth.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub appearance: Appearance,
    pub depth: Depth,

    /// Page background, painted edge to edge so the dark surface does not
    /// depend on the user's terminal background.
    pub canvas: Swatch,
    /// Default background for bordered regions.
    pub panel: Swatch,
    /// The one recessed surface: code blocks and raw payloads.
    pub well: Swatch,

    /// Internal dividers. Quiet by design.
    pub hairline: Swatch,
    /// Default panel border.
    pub border: Swatch,
    /// Focused panel border.
    pub border_strong: Swatch,

    pub fg: Swatch,
    pub fg_muted: Swatch,
    pub fg_subtle: Swatch,

    pub electric: Swatch,
    pub amber: Swatch,
    pub blue: Swatch,
    pub coral: Swatch,
    pub violet: Swatch,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark(Depth::TrueColor)
    }
}

impl Theme {
    /// The dark palette — Sondera's default.
    pub const fn dark(depth: Depth) -> Self {
        Self {
            appearance: Appearance::Dark,
            depth,
            canvas: Swatch::new([0x0e, 0x0f, 0x12], 233),
            panel: Swatch::new([0x1a, 0x1d, 0x21], 234),
            well: Swatch::new([0x0a, 0x0b, 0x0d], 232),
            hairline: Swatch::new([0x22, 0x25, 0x2a], 235),
            border: Swatch::new([0x2e, 0x31, 0x37], 236),
            border_strong: Swatch::new([0x56, 0x93, 0x78], 66),
            fg: Swatch::new([0xe1, 0xe2, 0xe4], 254),
            fg_muted: Swatch::new([0x94, 0x9b, 0xa4], 247),
            fg_subtle: Swatch::new([0x6b, 0x6f, 0x75], 242),
            electric: Swatch::new([0x81, 0xdd, 0xb4], 115),
            amber: Swatch::new([0xff, 0xc8, 0x22], 220),
            blue: Swatch::new([0x89, 0xab, 0xe3], 110),
            coral: Swatch::new([0xf2, 0x82, 0x7f], 210),
            violet: Swatch::new([0xc9, 0xa0, 0xdc], 182),
        }
    }

    /// The light palette. Accents are re-saturated and deepened rather than
    /// reused: a dark-mode accent hex is illegible on white.
    pub const fn light(depth: Depth) -> Self {
        Self {
            appearance: Appearance::Light,
            depth,
            canvas: Swatch::new([0xee, 0xf1, 0xf5], 255),
            panel: Swatch::new([0xff, 0xff, 0xff], 231),
            well: Swatch::new([0xe7, 0xeb, 0xf1], 253),
            hairline: Swatch::new([0xe6, 0xe9, 0xef], 252),
            border: Swatch::new([0xd3, 0xd9, 0xe1], 250),
            border_strong: Swatch::new([0x56, 0x93, 0x78], 66),
            fg: Swatch::new([0x10, 0x13, 0x1a], 233),
            fg_muted: Swatch::new([0x4d, 0x57, 0x65], 240),
            fg_subtle: Swatch::new([0x6c, 0x76, 0x86], 243),
            electric: Swatch::new([0x56, 0x93, 0x78], 66),
            amber: Swatch::new([0xa9, 0x70, 0x0b], 130),
            blue: Swatch::new([0x3a, 0x6b, 0xb0], 61),
            coral: Swatch::new([0xd6, 0x45, 0x3d], 167),
            violet: Swatch::new([0x8a, 0x55, 0xc2], 97),
        }
    }

    /// Pick a theme from the environment.
    ///
    /// Honours `NO_COLOR`, then `COLORTERM=truecolor|24bit`. Terminals do not
    /// report their background color, so appearance comes from `SONDERA_THEME`
    /// and defaults to dark.
    pub fn detect() -> Self {
        let depth = if std::env::var_os("NO_COLOR").is_some() {
            Depth::None
        } else {
            match std::env::var("COLORTERM").as_deref() {
                Ok("truecolor" | "24bit") => Depth::TrueColor,
                _ => Depth::Ansi256,
            }
        };
        match std::env::var("SONDERA_THEME").as_deref() {
            Ok("light") => Self::light(depth),
            _ => Self::dark(depth),
        }
    }

    /// Flip between light and dark, keeping the detected color depth.
    pub fn toggled(self) -> Self {
        match self.appearance {
            Appearance::Dark => Self::light(self.depth),
            Appearance::Light => Self::dark(self.depth),
        }
    }

    /// Resolve a swatch at this theme's color depth.
    pub fn color(&self, swatch: Swatch) -> Color {
        match self.depth {
            Depth::TrueColor => Color::Rgb(swatch.rgb[0], swatch.rgb[1], swatch.rgb[2]),
            Depth::Ansi256 => Color::Indexed(swatch.idx),
            Depth::None => Color::Reset,
        }
    }

    /// The swatch behind a tone. `Neutral` resolves to muted foreground.
    pub const fn tone_swatch(&self, tone: Tone) -> Swatch {
        match tone {
            Tone::Allow => self.electric,
            Tone::Warn => self.amber,
            Tone::Info => self.blue,
            Tone::Deny => self.coral,
            Tone::Rare => self.violet,
            Tone::Neutral => self.fg_muted,
        }
    }

    /// Foreground color for a tone.
    pub fn tone(&self, tone: Tone) -> Color {
        self.color(self.tone_swatch(tone))
    }

    /// A brand-ramp step, resolved at this theme's color depth.
    pub fn brand(&self, tone: BrandTone) -> Color {
        self.color(BRAND_RAMP[tone as usize])
    }

    /// The tinted background that carries a tone on a chip or row.
    ///
    /// Below truecolor there is no headroom for a 12% tint, so this returns the
    /// panel background and the tone must ride on foreground + glyph.
    pub fn tone_tint(&self, tone: Tone) -> Color {
        match self.depth {
            Depth::TrueColor => {
                let t = self.tone_swatch(tone).rgb;
                let base = self.panel.rgb;
                Color::Rgb(
                    mix(t[0], base[0], 12),
                    mix(t[1], base[1], 12),
                    mix(t[2], base[2], 12),
                )
            }
            Depth::Ansi256 => Color::Indexed(self.panel.idx),
            Depth::None => Color::Reset,
        }
    }

    // ---------------------------------------------------------------- styles

    /// Primary body text.
    pub fn body(&self) -> Style {
        Style::new().fg(self.color(self.fg))
    }

    /// Secondary text: labels, descriptions, inactive rows.
    pub fn muted(&self) -> Style {
        Style::new().fg(self.color(self.fg_muted))
    }

    /// Tertiary text: timestamps, ids, counts.
    pub fn subtle(&self) -> Style {
        Style::new().fg(self.color(self.fg_subtle))
    }

    /// Numeric emphasis. The terminal is already monospace, so "type as
    /// identity" here means alignment — right-align these.
    pub fn metric(&self) -> Style {
        Style::new()
            .fg(self.color(self.violet))
            .add_modifier(Modifier::BOLD)
    }

    /// Section eyebrow: the stand-in for uppercase Monument Extended.
    ///
    /// Terminals cannot letter-space, and faking tracking by inserting spaces
    /// between characters breaks search, copy/paste, and screen readers — so
    /// this is uppercase + bold + brand green and nothing else.
    pub fn eyebrow_style(&self) -> Style {
        Style::new()
            .fg(self.color(self.electric))
            .add_modifier(Modifier::BOLD)
    }

    /// Selection. Reversed video is the terminal's `shadow-neu`: an
    /// unmistakable "this is the live row" that survives every color depth.
    pub fn selected(&self) -> Style {
        Style::new().add_modifier(Modifier::REVERSED)
    }

    /// A tone-carrying row or chip: tinted background, tone foreground.
    pub fn tone_row(&self, tone: Tone) -> Style {
        Style::new().fg(self.tone(tone)).bg(self.tone_tint(tone))
    }

    // ------------------------------------------------------------ components

    /// A structural panel: flat fill, plain single border, uppercase eyebrow.
    ///
    /// Plain borders only — heavy, double, and rounded borders are decoration,
    /// and Sondera keeps chrome quiet so the data can be loud.
    pub fn panel<'a>(&self, eyebrow: &str) -> Block<'a> {
        Block::bordered()
            .border_type(BorderType::Plain)
            .border_style(Style::new().fg(self.color(self.border)))
            .style(Style::new().bg(self.color(self.panel)))
            .padding(Padding::horizontal(1))
            .title(Line::from(Span::styled(
                eyebrow.to_uppercase(),
                self.eyebrow_style(),
            )))
    }

    /// [`Theme::panel`], focused. Same geometry — focus must never resize a
    /// panel or the whole layout jumps as the user tabs.
    pub fn panel_focused<'a>(&self, eyebrow: &str) -> Block<'a> {
        self.panel(eyebrow)
            .border_style(Style::new().fg(self.color(self.border_strong)))
    }

    /// [`Theme::panel`], focused or not.
    pub fn panel_for<'a>(&self, eyebrow: &str, focused: bool) -> Block<'a> {
        if focused {
            self.panel_focused(eyebrow)
        } else {
            self.panel(eyebrow)
        }
    }

    /// An uppercase section eyebrow as a standalone line.
    pub fn eyebrow(&self, text: &str) -> Line<'static> {
        Line::from(Span::styled(text.to_uppercase(), self.eyebrow_style()))
    }

    /// A tone chip: leading glyph + uppercase label on a tint. Use for
    /// verdicts, severities, and statuses.
    pub fn chip(&self, tone: Tone, label: &str) -> Span<'static> {
        Span::styled(
            format!(" {} {} ", tone.glyph(), label.to_uppercase()),
            self.tone_row(tone).add_modifier(Modifier::BOLD),
        )
    }

    /// A key/value line for dense metadata: muted key, body value.
    pub fn field(&self, key: &str, value: &str) -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("{key:<9} "), self.subtle()),
            Span::styled(value.to_string(), self.body()),
        ])
    }

    /// A footer hint line of `<key> action` pairs.
    pub fn keyhints(&self, hints: &[(&str, &str)]) -> Line<'static> {
        let mut spans = Vec::with_capacity(hints.len() * 3);
        for (key, action) in hints {
            spans.push(Span::styled(format!("<{key}>"), self.eyebrow_style()));
            spans.push(Span::styled(format!(" {action}"), self.subtle()));
            spans.push(Span::styled("   ", self.subtle()));
        }
        Line::from(spans)
    }
}

/// Blend `pct`% of `top` into `base`.
const fn mix(top: u8, base: u8, pct: u8) -> u8 {
    ((top as u16 * pct as u16 + base as u16 * (100 - pct) as u16) / 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecolor_resolves_to_brand_hex() {
        let theme = Theme::dark(Depth::TrueColor);
        assert_eq!(theme.tone(Tone::Allow), Color::Rgb(0x81, 0xdd, 0xb4));
    }

    #[test]
    fn ansi256_resolves_to_indexed_fallback() {
        let theme = Theme::dark(Depth::Ansi256);
        assert_eq!(theme.tone(Tone::Deny), Color::Indexed(210));
    }

    #[test]
    fn no_color_resolves_everything_to_reset() {
        let theme = Theme::dark(Depth::None);
        assert_eq!(theme.tone(Tone::Deny), Color::Reset);
        assert_eq!(theme.color(theme.panel), Color::Reset);
    }

    #[test]
    fn surface_tiers_stay_distinct_on_256_color() {
        for theme in [Theme::dark(Depth::Ansi256), Theme::light(Depth::Ansi256)] {
            let tiers = [theme.canvas.idx, theme.panel.idx, theme.well.idx];
            assert_eq!(
                tiers.len(),
                tiers.iter().collect::<std::collections::HashSet<_>>().len(),
                "surface tiers collapsed into one 256-color index",
            );
        }
    }

    #[test]
    fn tone_tint_falls_back_to_panel_without_truecolor() {
        let theme = Theme::dark(Depth::Ansi256);
        assert_eq!(theme.tone_tint(Tone::Warn), Color::Indexed(theme.panel.idx));
    }

    #[test]
    fn every_tone_has_a_distinct_glyph() {
        let glyphs = [
            Tone::Allow.glyph(),
            Tone::Warn.glyph(),
            Tone::Info.glyph(),
            Tone::Deny.glyph(),
            Tone::Rare.glyph(),
        ];
        assert_eq!(
            glyphs.len(),
            glyphs
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
        );
    }

    #[test]
    fn toggling_preserves_color_depth() {
        let theme = Theme::dark(Depth::Ansi256).toggled();
        assert_eq!(theme.appearance, Appearance::Light);
        assert_eq!(theme.depth, Depth::Ansi256);
    }
}
