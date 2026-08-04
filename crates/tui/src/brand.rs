//! The Sondera mark, generated per render and rendered in half blocks.
//!
//! The brand system builds the mark from circular modules on a 4 × 4 grid,
//! where adjacent modules fuse through concave fillets and a seven-rung
//! "sliding scale" runs from fully fused to fully discrete. Only part of that
//! reaches a terminal:
//!
//! - **The grid survives exactly.** Four by four, eleven modules, five vacant.
//! - **Curvature does not.** A subpixel is square.
//! - **The ladder does not.** Expressing whether two modules are joined needs a
//!   gap between them that can be filled, which costs a second subpixel of
//!   pitch. At one subpixel per cell every rung renders identically, so what
//!   this module draws is bare occupancy — visually the most-discrete rung, at
//!   eleven components, above the system's four-component floor for a primary
//!   format.
//!
//! # This module extends the brand system rather than applying it
//!
//! The Figma board contains exactly **one** mark, with one fixed per-cell tone
//! map. Everything here that generates a *different* occupancy is a deliberate
//! extension, made so the header can show a new mark on every load, refresh,
//! and (rate-limited) stream event.
//!
//! The extension is kept as small as the requirement allows. Generated marks
//! reuse the system's stated invariant (exactly five vacant cells), the
//! canonical mark's own tone proportion, and its topology — the sampler's two
//! predicates, `balanced` and `connected`, carry the reasoning for each.

use crate::theme::{Appearance, BrandTone, Depth, Theme};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use std::time::{Duration, Instant};

/// Grid width and height, in cells.
const SIDE: u8 = 4;
/// Cells in the grid.
const CELLS: usize = (SIDE * SIDE) as usize;
/// Modules in a mark. Fixed: the system states five vacant cells of sixteen.
const MODULES: usize = 11;
/// Vacant cells in a mark.
const VACANT: usize = CELLS - MODULES;

/// The one mark the Figma board contains. Bit `row * 4 + col`.
///
/// ```text
/// . X X X
/// X . X .
/// X X X X
/// . X . X
/// ```
///
/// Identical in all seven rungs of the ladder, in the construction diagram, and
/// in both lockups. Kept as the reference the generator is measured against and
/// as the fallback when sampling somehow cannot find a layout.
const CANONICAL: u16 = 0xAF5E;

/// The tones a mark's eleven modules are drawn from, in the exact proportion
/// the canonical mark uses: four electric, three pale, four mid.
///
/// Shuffling this rather than picking each cell independently is what keeps a
/// generated mark's colour balance identical to the one the brand drew, instead
/// of merely similar on average. The canonical per-cell map this proportion is
/// taken from lives in the tests, which assert the two still agree.
const TONE_POOL: [BrandTone; MODULES] = [
    BrandTone::Electric,
    BrandTone::Electric,
    BrandTone::Electric,
    BrandTone::Electric,
    BrandTone::Pale,
    BrandTone::Pale,
    BrandTone::Pale,
    BrandTone::Mid,
    BrandTone::Mid,
    BrandTone::Mid,
    BrandTone::Mid,
];

/// One animation frame. Above ~20 fps a terminal animation spends redraws
/// nobody can see; below ~10 fps motion reads as stepping rather than moving.
pub const FRAME: Duration = Duration::from_millis(60);

/// Shortest gap between full assemblies. A live feed would otherwise restart a
/// ~660 ms animation every few milliseconds and never resolve, so a busy
/// console degrades to one pulse per event plus an occasional new mark.
const COOLDOWN: Duration = Duration::from_secs(2);

/// How long a single module stays lit when an event arrives.
const PULSE_FRAMES: u8 = 3;

/// Draws allowed before falling back to [`CANONICAL`]. Acceptance is 804 of
/// 4368, so five or six draws is typical and sixty-four fails with probability
/// about two in a million.
const SAMPLE_ATTEMPTS: usize = 64;

/// Seed used when the clock is unavailable. Arbitrary, and only ever reached if
/// `SystemTime` is before the epoch.
const FALLBACK_SEED: u64 = 0x50_4E_44_52_41_00_00_01;

/// Whether `occupancy` holds a module at `cell`.
const fn holds(occupancy: u16, cell: u8) -> bool {
    occupancy & (1 << cell) != 0
}

/// Orthogonal in-bounds neighbours of each cell, as a mask.
const NEIGHBOURS: [u16; CELLS] = {
    let (side, mut table, mut cell) = (SIDE as usize, [0u16; CELLS], 0usize);
    while cell < CELLS {
        let (row, col) = (cell / side, cell % side);
        if row > 0 {
            table[cell] |= 1 << (cell - side);
        }
        if row + 1 < side {
            table[cell] |= 1 << (cell + side);
        }
        if col > 0 {
            table[cell] |= 1 << (cell - 1);
        }
        if col + 1 < side {
            table[cell] |= 1 << (cell + 1);
        }
        cell += 1;
    }
    table
};

/// Every cell orthogonally adjacent to any cell in `mask`.
fn grow(mask: u16) -> u16 {
    (0..CELLS)
        .filter(|&cell| holds(mask, cell as u8))
        .fold(0, |out, cell| out | NEIGHBOURS[cell])
}

/// The cells of `mask`, low bit first.
fn cells(mask: u16) -> impl Iterator<Item = u8> {
    (0..CELLS as u8).filter(move |&cell| holds(mask, cell))
}

/// Whether every row and every column keeps at least two modules.
///
/// Uniform draws otherwise produce marks with a blank row or column, which read
/// as a broken grid rather than as a mark. This is what keeps a generated mark
/// occupying its frame the way the canonical one does.
fn balanced(occupancy: u16) -> bool {
    (0..SIDE).all(|i| {
        let row = (0..SIDE).filter(|c| holds(occupancy, i * SIDE + c)).count();
        let col = (0..SIDE).filter(|r| holds(occupancy, r * SIDE + i)).count();
        row >= 2 && col >= 2
    })
}

/// Whether every module is orthogonally reachable from every other.
///
/// Required by the *animation*, not by the brand: the assembly floods outward
/// from one module, and a disconnected layout would grow one cluster and then
/// have the rest appear from nowhere — the scatter the flood exists to avoid.
/// The canonical mark is connected, so this also keeps generated marks in its
/// character.
fn connected(occupancy: u16) -> bool {
    let Some(start) = cells(occupancy).next() else {
        return false;
    };
    let mut seen: u16 = 1 << start;
    loop {
        let next = grow(seen) & occupancy & !seen;
        if next == 0 {
            return seen == occupancy;
        }
        seen |= next;
    }
}

/// What a seed determines. Grouped so a mark is never constructed with
/// placeholder values that a later call overwrites.
///
/// Occupancy is not stored: it is `tint[cell].is_some()`, and keeping a second
/// copy only creates something for the two to disagree about.
struct Drawn {
    tint: [Option<BrandTone>; CELLS],
    order: [u8; MODULES],
}

impl Drawn {
    fn sample(rng: &mut SplitMix64) -> Self {
        let occupancy = sample_occupancy(rng);
        Self {
            tint: sample_tint(occupancy, rng),
            order: flood_order(occupancy, rng),
        }
    }
}

/// Draw a fresh occupancy: five vacant cells, balanced, and connected.
///
/// Rejection sampling. 804 of the 4368 five-vacant layouts pass both
/// predicates, so a draw succeeds about one time in five.
fn sample_occupancy(rng: &mut SplitMix64) -> u16 {
    for _ in 0..SAMPLE_ATTEMPTS {
        let mut vacant: u16 = 0;
        while (vacant.count_ones() as usize) < VACANT {
            vacant |= 1 << rng.below(CELLS);
        }
        let occupancy = !vacant;
        if balanced(occupancy) && connected(occupancy) {
            return occupancy;
        }
    }
    CANONICAL
}

/// Assign a tone to every module by shuffling [`TONE_POOL`].
fn sample_tint(occupancy: u16, rng: &mut SplitMix64) -> [Option<BrandTone>; CELLS] {
    let mut pool = TONE_POOL;
    rng.shuffle(&mut pool);
    let mut tint = [None; CELLS];
    let mut taken = 0;
    for (cell, slot) in tint.iter_mut().enumerate() {
        if holds(occupancy, cell as u8) {
            *slot = Some(pool[taken]);
            taken += 1;
        }
    }
    tint
}

/// Assembly order: a breadth-first flood from a random module, with ties inside
/// a layer shuffled.
///
/// The mark grows outward from one point rather than flickering on at random,
/// which is the system's own "structure and spacing create order" — it reads as
/// construction rather than noise. [`connected`] guarantees the flood reaches
/// every module; the trailing sweep is a belt on that brace.
fn flood_order(occupancy: u16, rng: &mut SplitMix64) -> [u8; MODULES] {
    let start = cells(occupancy)
        .nth(rng.below(MODULES))
        .unwrap_or_else(|| cells(CANONICAL).next().unwrap_or(0));

    let mut order = [0u8; MODULES];
    order[0] = start;
    let mut written = 1usize;
    let mut seen: u16 = 1 << start;
    let mut frontier = seen;

    while written < MODULES {
        let next = grow(frontier) & occupancy & !seen;
        if next == 0 {
            break;
        }
        seen |= next;

        let mut layer = [0u8; MODULES];
        let mut count = 0usize;
        for cell in cells(next) {
            layer[count] = cell;
            count += 1;
        }
        rng.shuffle(&mut layer[..count]);
        order[written..written + count].copy_from_slice(&layer[..count]);
        written += count;
        frontier = next;
    }

    // `sample_occupancy` only ever returns a connected layout, so the flood
    // always reaches all eleven. Asserted rather than papered over with a
    // fallback sweep: a short order would silently render vacant cells.
    debug_assert_eq!(written, MODULES, "flood did not reach every module");
    order
}

/// Two lines of four characters, each covering one grid cell above another.
///
/// A terminal cell is roughly 1 : 2, so half of one is roughly square: this is
/// the 4 × 4 grid at native resolution, unscaled and undistorted.
fn half_blocks(mut cell: impl FnMut(usize, usize) -> Span<'static>) -> Vec<Line<'static>> {
    (0..2)
        .map(|row| {
            let spans: Vec<Span<'static>> = (0..SIDE as usize)
                .map(|col| {
                    let upper = row * 2 * SIDE as usize + col;
                    cell(upper, upper + SIDE as usize)
                })
                .collect();
            Line::from(spans)
        })
        .collect()
}

/// The tone an arriving event lights a module with: whichever ramp step has the
/// most contrast against this appearance's panel.
const fn pulse_tone(appearance: Appearance) -> BrandTone {
    match appearance {
        Appearance::Dark => BrandTone::Pale,
        Appearance::Light => BrandTone::Deep,
    }
}

/// SplitMix64. Inline because the workspace carries no `rand` and a handful of
/// bits per render does not justify the dependency.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n`. `n` must be non-zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Fisher-Yates, in place.
    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            slice.swap(i, self.below(i + 1));
        }
    }
}

/// What the mark is doing this frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Fully drawn. The timer in the event loop is disarmed here.
    Resolved,
    /// Assembling: the first `shown` modules of the order have arrived.
    Assembling { shown: u8 },
    /// A single module is lit for `frames` more frames. The module is resolved
    /// from `key` at render time rather than stored, so toggling the theme
    /// mid-pulse re-picks a module that is still visible against the new panel.
    Pulsing { key: u64, frames: u8 },
}

/// A generated Sondera mark, and its assembly animation.
pub struct Mark {
    seed: u64,
    /// Occupancy, tones, and assembly order for the mark currently on screen.
    drawn: Drawn,
    phase: Phase,
    /// Whether this mark animates at all. Fixed at construction.
    motion: bool,
    /// When the last full assembly began, for [`COOLDOWN`].
    last_assembly: Option<Instant>,
}

impl Mark {
    /// A mark with an explicit seed and motion setting. Tests use this; the
    /// application uses [`Mark::detect`].
    pub fn new(seed: u64, motion: bool) -> Self {
        let mut rng = SplitMix64(seed);
        Self {
            drawn: Drawn::sample(&mut rng),
            seed: rng.next(),
            phase: Phase::Resolved,
            motion,
            last_assembly: None,
        }
    }

    /// A mark seeded from the clock, animating unless the environment says not
    /// to.
    ///
    /// Motion is suppressed by `NO_MOTION` or `SONDERA_NO_MOTION`, when stdout
    /// is not a terminal, and at [`Depth::None`] — where every swatch resolves
    /// to `Color::Reset` and there is nothing for an assembly to move through.
    pub fn detect(theme: &Theme) -> Self {
        use std::io::IsTerminal as _;

        let motion = std::env::var_os("NO_MOTION").is_none()
            && std::env::var_os("SONDERA_NO_MOTION").is_none()
            && theme.depth != Depth::None
            && std::io::stdout().is_terminal();

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(FALLBACK_SEED, |since| {
                u64::from(since.subsec_nanos()) ^ since.as_secs()
            });

        let mut mark = Self::new(seed, motion);
        // The first screen is a load like any other.
        mark.begin(Instant::now());
        mark
    }

    /// Draw a new mark — occupancy, tones, and assembly order — and advance the
    /// seed so the next one differs.
    fn regenerate(&mut self) {
        let mut rng = SplitMix64(self.seed);
        self.drawn = Drawn::sample(&mut rng);
        self.seed = rng.next();
    }

    /// Generate a new mark and assemble it: screen load, or the refresh key.
    ///
    /// Unconditional — a keypress is a direct request and is never rate
    /// limited. Under suppressed motion the new mark appears at once instead of
    /// assembling.
    pub fn assemble(&mut self, now: Instant) {
        self.regenerate();
        self.begin(now);
    }

    /// Start the assembly animation for the mark already drawn.
    fn begin(&mut self, now: Instant) {
        self.last_assembly = Some(now);
        self.phase = if self.motion {
            // One, not zero: at zero the mark is blank for a frame, which reads
            // as the header flickering out rather than as the mark growing.
            Phase::Assembling { shown: 1 }
        } else {
            Phase::Resolved
        };
    }

    /// A stream event arrived.
    ///
    /// Always pulses one module. Also draws a new mark, but at most once every
    /// two seconds and never over an animation already running: a quiet console
    /// gets a new mark per event, a busy one gets the pulse.
    pub fn on_event(&mut self, key: u64, now: Instant) {
        // An animation already running wins: it is the more informative one.
        if !self.motion || self.phase != Phase::Resolved {
            return;
        }
        let due = self
            .last_assembly
            .is_none_or(|last| now.duration_since(last) >= COOLDOWN);
        if due {
            self.assemble(now);
        } else {
            self.phase = Phase::Pulsing {
                key,
                frames: PULSE_FRAMES,
            };
        }
    }

    /// Whether a frame timer should be armed. False at rest, which is what
    /// keeps an idle TUI from redrawing.
    pub fn is_animating(&self) -> bool {
        self.phase != Phase::Resolved
    }

    /// Step one frame.
    pub fn advance(&mut self) {
        self.phase = match self.phase {
            Phase::Assembling { shown } if (shown as usize) + 1 < MODULES => {
                Phase::Assembling { shown: shown + 1 }
            }
            Phase::Pulsing { key, frames } if frames > 1 => Phase::Pulsing {
                key,
                frames: frames - 1,
            },
            _ => Phase::Resolved,
        };
    }

    /// The resting tone the header actually paints for `cell`.
    ///
    /// This deliberately is not "apply the brand map for this appearance". The
    /// Figma lockups sit on pure black and pure white; the header sits on
    /// `theme.panel` — `#1a1d21` or `#ffffff` — and that gap moves the contrast
    /// far enough to change which ramp steps are usable. At one subpixel per
    /// cell an unusable step is not a dim module, it is a *missing* one, and
    /// the mark reads as a different mark.
    ///
    /// - **Dark**: the tones as drawn, which are the brand's *light*-ground
    ///   set. Rotating to the dark-ground set would bring in `#2C5844` at
    ///   2.08:1 against `#1a1d21` and blank roughly three modules; the
    ///   light-ground set is all ≥ 4.70:1 here, because our dark panel is not
    ///   black.
    /// - **Light**: flat. Three-tone is unachievable on white — only two ramp
    ///   steps clear 3:1, and no rotation of a four-step ramp yields three
    ///   white-safe tones.
    fn resting(&self, theme: &Theme, cell: usize) -> Option<BrandTone> {
        match theme.appearance {
            Appearance::Dark => self.drawn.tint[cell],
            Appearance::Light => self.drawn.tint[cell].map(|_| BrandTone::Mid),
        }
    }

    /// Which module a pulse lights, for this theme.
    ///
    /// Restricted to modules whose resting tone differs from the pulse tone —
    /// otherwise roughly a quarter of pulses on the dark theme would repaint a
    /// module in the colour it already was, and be invisible.
    fn pulse_target(&self, theme: &Theme, key: u64) -> Option<u8> {
        let hot = pulse_tone(theme.appearance);
        let eligible = || {
            self.drawn
                .order
                .iter()
                .copied()
                .filter(|&cell| self.resting(theme, cell as usize) != Some(hot))
        };
        let count = eligible().count();
        (count > 0)
            .then(|| eligible().nth((key % count as u64) as usize))
            .flatten()
    }

    /// The mark as two lines of four characters.
    ///
    /// Every character is `▀` with the upper grid cell as foreground and the
    /// lower as background, so one glyph covers all four fill combinations. A
    /// terminal cell is roughly 1 : 2, so half of one is roughly square: this is
    /// the 4 × 4 grid at native resolution, unscaled and undistorted.
    pub fn lines(&self, theme: &Theme) -> Vec<Line<'static>> {
        if theme.depth == Depth::None {
            return self.monochrome_lines();
        }

        let ground = theme.color(theme.panel);
        let lit = self.lit();
        let pulsing = match self.phase {
            Phase::Pulsing { key, .. } => self.pulse_target(theme, key),
            _ => None,
        };

        let color = |cell: usize| -> Color {
            if pulsing == Some(cell as u8) {
                return theme.brand(pulse_tone(theme.appearance));
            }
            if !holds(lit, cell as u8) {
                return ground;
            }
            self.resting(theme, cell)
                .map_or(ground, |tone| theme.brand(tone))
        };

        half_blocks(|upper, lower| {
            Span::styled("▀", Style::new().fg(color(upper)).bg(color(lower)))
        })
    }

    /// `NO_COLOR`: every swatch resolves to `Color::Reset`, so occupancy cannot
    /// ride on foreground against background. Carry it on the glyph instead.
    fn monochrome_lines(&self) -> Vec<Line<'static>> {
        let lit = self.lit();
        half_blocks(|upper, lower| {
            Span::raw(
                match (holds(lit, upper as u8), holds(lit, lower as u8)) {
                    (true, true) => "█",
                    (true, false) => "▀",
                    (false, true) => "▄",
                    (false, false) => " ",
                }
                .to_string(),
            )
        })
    }

    /// The modules currently drawn — a prefix of the order mid-assembly, all of
    /// them otherwise.
    fn lit(&self) -> u16 {
        let shown = match self.phase {
            Phase::Assembling { shown } => shown as usize,
            _ => MODULES,
        };
        self.drawn.order[..shown]
            .iter()
            .fold(0, |mask, &cell| mask | 1 << cell)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// The four-step ramp, deepest to palest, and one step along it. The header
    /// renders only the light-ground map, so this exists purely to cross-check
    /// the tint table below against the dark lockup.
    const RAMP: [BrandTone; 4] = [
        BrandTone::Deep,
        BrandTone::Mid,
        BrandTone::Electric,
        BrandTone::Pale,
    ];

    fn rotated(tone: BrandTone) -> BrandTone {
        let step = RAMP.iter().position(|&r| r == tone).unwrap();
        RAMP[(step + 1) % RAMP.len()]
    }

    /// The canonical mark's resting tone per cell **on a light ground**, `None`
    /// where vacant.
    ///
    /// Normative, verified cell by cell across every rung and both lockups. The
    /// dark-ground map is this one with every entry rotated one step along the
    /// ramp — which is *not* what the header uses on the dark theme; see
    /// `Mark::resting`.
    ///
    /// Production does not read this table: a tone at a cell the canonical mark
    /// leaves vacant has no brand meaning, so generated marks shuffle its
    /// *proportion* instead. It is kept as the record those tests measure against.
    const CANONICAL_TINT: [Option<BrandTone>; CELLS] = [
        None,
        Some(BrandTone::Electric),
        Some(BrandTone::Pale),
        Some(BrandTone::Mid),
        Some(BrandTone::Pale),
        None,
        Some(BrandTone::Electric),
        None,
        Some(BrandTone::Mid),
        Some(BrandTone::Electric),
        Some(BrandTone::Mid),
        Some(BrandTone::Pale),
        None,
        Some(BrandTone::Mid),
        None,
        Some(BrandTone::Electric),
    ];

    fn dark() -> Theme {
        Theme::dark(Depth::TrueColor)
    }

    fn light() -> Theme {
        Theme::light(Depth::TrueColor)
    }

    /// WCAG relative luminance.
    fn luminance(rgb: [u8; 3]) -> f64 {
        let channel = |v: u8| {
            let v = f64::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2])
    }

    fn contrast(a: [u8; 3], b: [u8; 3]) -> f64 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    fn rgb(color: Color) -> [u8; 3] {
        match color {
            Color::Rgb(r, g, b) => [r, g, b],
            other => panic!("expected truecolor, got {other:?}"),
        }
    }

    /// A mark pinned to the canonical occupancy and tone map, for the tests that
    /// assert against the brand artifact rather than against the generator.
    /// The occupancy a mark is drawing, recovered from its tone map.
    fn occupancy_of(mark: &Mark) -> u16 {
        cells(u16::MAX)
            .filter(|&cell| mark.drawn.tint[cell as usize].is_some())
            .fold(0, |mask, cell| mask | 1 << cell)
    }

    fn canonical_mark() -> Mark {
        let mut mark = Mark::new(1, true);
        mark.drawn.tint = CANONICAL_TINT;
        mark.drawn.order = flood_order(CANONICAL, &mut SplitMix64(1));
        mark
    }

    // ── the brand artifact ──────────────────────────────────────────────────

    #[test]
    fn the_canonical_mark_is_eleven_modules_and_five_vacancies() {
        assert_eq!(CANONICAL.count_ones() as usize, MODULES);
        assert_eq!(CANONICAL.count_zeros() as usize, VACANT);
    }

    #[test]
    fn the_canonical_mark_matches_the_figma_grid() {
        let rows: Vec<String> = (0..SIDE)
            .map(|row| {
                (0..SIDE)
                    .map(|col| {
                        if holds(CANONICAL, row * SIDE + col) {
                            'X'
                        } else {
                            '.'
                        }
                    })
                    .collect()
            })
            .collect();
        assert_eq!(rows, [".XXX", "X.X.", "XXXX", ".X.X"]);
    }

    #[test]
    fn the_canonical_mark_satisfies_both_generator_predicates() {
        // The generator is only legitimate if the mark the brand actually drew
        // is one of the marks it can produce.
        assert!(balanced(CANONICAL));
        assert!(connected(CANONICAL));
    }

    #[test]
    fn canonical_tint_is_defined_exactly_where_a_module_sits() {
        for (cell, tint) in CANONICAL_TINT.iter().enumerate() {
            assert_eq!(
                tint.is_some(),
                holds(CANONICAL, cell as u8),
                "cell {cell} tint and occupancy disagree"
            );
        }
    }

    #[test]
    fn the_tone_pool_matches_the_canonical_marks_proportion() {
        let count = |tones: &[BrandTone]| {
            tones.iter().fold(HashMap::new(), |mut acc, tone| {
                *acc.entry(*tone).or_insert(0usize) += 1;
                acc
            })
        };
        let drawn: Vec<BrandTone> = CANONICAL_TINT.iter().flatten().copied().collect();
        assert_eq!(count(&drawn), count(&TONE_POOL));
    }

    #[test]
    fn the_dark_ground_map_is_the_light_one_rotated_once() {
        // The relationship the brand system defines. Asserted even though the
        // header does not use the dark-ground map, because it is the normative
        // artifact for the mark at size.
        let rotated: Vec<Option<BrandTone>> =
            CANONICAL_TINT.iter().map(|t| t.map(rotated)).collect();
        let expected = [
            None,
            Some(BrandTone::Pale),
            Some(BrandTone::Deep),
            Some(BrandTone::Electric),
            Some(BrandTone::Deep),
            None,
            Some(BrandTone::Pale),
            None,
            Some(BrandTone::Electric),
            Some(BrandTone::Pale),
            Some(BrandTone::Electric),
            Some(BrandTone::Deep),
            None,
            Some(BrandTone::Electric),
            None,
            Some(BrandTone::Pale),
        ];
        assert_eq!(rotated, expected);
    }

    // ── the generator ───────────────────────────────────────────────────────

    #[test]
    fn every_generated_mark_keeps_the_systems_invariants() {
        for seed in 0..2_000u64 {
            let mark = Mark::new(seed, true);
            assert_eq!(
                occupancy_of(&mark).count_ones() as usize,
                MODULES,
                "seed {seed} produced the wrong module count",
            );
            assert!(
                balanced(occupancy_of(&mark)),
                "seed {seed} left a row or column more than half vacant",
            );
            assert!(
                connected(occupancy_of(&mark)),
                "seed {seed} is disconnected"
            );
        }
    }

    #[test]
    fn every_generated_mark_keeps_the_canonical_tone_proportion() {
        for seed in 0..500u64 {
            let mark = Mark::new(seed, true);
            let mut drawn: Vec<BrandTone> = mark.drawn.tint.iter().flatten().copied().collect();
            let mut pool = TONE_POOL.to_vec();
            drawn.sort_unstable();
            pool.sort_unstable();
            assert_eq!(drawn, pool, "seed {seed} drifted off the tone proportion");
            for (cell, tint) in mark.drawn.tint.iter().enumerate() {
                assert_eq!(tint.is_some(), holds(occupancy_of(&mark), cell as u8));
            }
        }
    }

    #[test]
    fn the_generator_actually_generates() {
        let shapes: HashSet<u16> = (0..500u64)
            .map(|s| occupancy_of(&Mark::new(s, true)))
            .collect();
        // 804 layouts pass both predicates; 500 seeds should reach a good share
        // of them. A generator stuck on one mark is the bug this catches.
        assert!(
            shapes.len() > 200,
            "500 seeds produced only {} distinct marks",
            shapes.len(),
        );
    }

    #[test]
    fn a_new_mark_is_drawn_on_every_assembly() {
        let mut mark = Mark::new(1, true);
        let mut seen = HashSet::from([(occupancy_of(&mark), mark.drawn.order)]);
        for _ in 0..50 {
            mark.assemble(Instant::now());
            seen.insert((occupancy_of(&mark), mark.drawn.order));
        }
        assert!(seen.len() > 40, "assemblies repeated themselves");
    }

    // ── colour ──────────────────────────────────────────────────────────────

    /// The assertion that would have caught the trap [`Mark::resting`]
    /// describes. If anyone "corrects" the dark theme to the brand's
    /// dark-ground map, modules drop to 2.08:1 and this fails.
    #[test]
    fn every_rendered_tone_is_legible_against_its_own_panel() {
        for theme in [dark(), light()] {
            let panel = theme.panel.rgb;
            for seed in 0..200u64 {
                let mark = Mark::new(seed, true);
                for cell in 0..CELLS {
                    let Some(tone) = mark.resting(&theme, cell) else {
                        continue;
                    };
                    let ratio = contrast(rgb(theme.brand(tone)), panel);
                    assert!(
                        ratio >= 3.0,
                        "{:?} seed {seed} cell {cell} tone {tone:?} is {ratio:.2}:1",
                        theme.appearance,
                    );
                }
            }
            let hot = rgb(theme.brand(pulse_tone(theme.appearance)));
            let ratio = contrast(hot, panel);
            assert!(ratio >= 3.0, "pulse tone is {ratio:.2}:1 against the panel");
        }
    }

    #[test]
    fn the_light_theme_renders_flat_and_the_dark_theme_does_not() {
        let tones = |mark: &Mark, theme: &Theme| {
            (0..CELLS)
                .filter_map(|cell| mark.resting(theme, cell))
                .collect::<HashSet<_>>()
        };
        let mark = canonical_mark();
        assert_eq!(tones(&mark, &light()), HashSet::from([BrandTone::Mid]));
        assert_eq!(
            tones(&mark, &dark()),
            HashSet::from([BrandTone::Mid, BrandTone::Electric, BrandTone::Pale]),
        );
    }

    #[test]
    fn a_pulse_never_repaints_a_module_in_the_colour_it_already_was() {
        for seed in 0..100u64 {
            let mark = Mark::new(seed, true);
            for theme in [dark(), light()] {
                let hot = pulse_tone(theme.appearance);
                for key in 0..16u64 {
                    let target = mark.pulse_target(&theme, key).expect("a pulse target");
                    assert_ne!(mark.resting(&theme, target as usize), Some(hot));
                }
            }
        }
    }

    // ── animation ───────────────────────────────────────────────────────────

    #[test]
    fn assembly_order_is_a_connected_flood_over_every_module() {
        for seed in 0..500u64 {
            let mark = Mark::new(seed, true);
            let unique: HashSet<u8> = mark.drawn.order.iter().copied().collect();
            assert_eq!(unique.len(), MODULES, "seed {seed} repeated a module");
            assert!(
                unique.iter().all(|&cell| holds(occupancy_of(&mark), cell)),
                "seed {seed} lit a vacant cell",
            );
            // Every prefix is orthogonally connected, which is what makes the
            // assembly read as growth rather than as scatter.
            for len in 2..=MODULES {
                let prefix: HashSet<u8> = mark.drawn.order[..len].iter().copied().collect();
                let attached = mark.drawn.order[len - 1];
                assert!(
                    cells(NEIGHBOURS[attached as usize])
                        .any(|n| prefix.contains(&n) && n != attached),
                    "seed {seed}: module {attached} joined the mark detached",
                );
            }
        }
    }

    #[test]
    fn a_resting_mark_arms_no_timer() {
        assert!(!Mark::new(1, true).is_animating());
    }

    #[test]
    fn assembly_runs_for_one_frame_per_module_then_disarms() {
        let mut mark = Mark::new(1, true);
        mark.assemble(Instant::now());
        let mut frames = 0;
        while mark.is_animating() {
            mark.advance();
            frames += 1;
            assert!(frames <= MODULES, "assembly did not terminate");
        }
        // One module is already on screen when the assembly starts, so the
        // remaining ten arrive one per frame.
        assert_eq!(frames, MODULES - 1);
    }

    #[test]
    fn suppressed_motion_resolves_instantly_but_still_draws_a_new_mark() {
        let mut mark = Mark::new(1, false);
        let before = occupancy_of(&mark);
        let mut changed = false;
        for _ in 0..20 {
            mark.assemble(Instant::now());
            assert!(!mark.is_animating());
            changed |= occupancy_of(&mark) != before;
        }
        assert!(changed, "the mark never changed with motion suppressed");
    }

    #[test]
    fn a_burst_of_events_produces_at_most_one_assembly() {
        let mut mark = Mark::new(1, true);
        let now = Instant::now();
        mark.assemble(now);
        while mark.is_animating() {
            mark.advance();
        }

        let mut assemblies = 0;
        for key in 0..100u64 {
            mark.on_event(key, now);
            if matches!(mark.phase, Phase::Assembling { .. }) {
                assemblies += 1;
            }
            while mark.is_animating() {
                mark.advance();
            }
        }
        assert_eq!(assemblies, 0, "the cooldown did not hold");
    }

    #[test]
    fn an_event_after_the_cooldown_draws_a_new_mark() {
        let mut mark = Mark::new(1, true);
        let now = Instant::now();
        mark.assemble(now);
        while mark.is_animating() {
            mark.advance();
        }
        let before = occupancy_of(&mark);
        mark.on_event(0, now + COOLDOWN);
        assert!(matches!(mark.phase, Phase::Assembling { .. }));
        assert_ne!(before, occupancy_of(&mark));
    }

    // ── rendering ───────────────────────────────────────────────────────────

    #[test]
    fn the_mark_renders_two_lines_of_four_cells() {
        for theme in [dark(), light(), Theme::dark(Depth::Ansi256)] {
            let lines = Mark::new(1, true).lines(&theme);
            assert_eq!(lines.len(), 2);
            for line in &lines {
                assert_eq!(line.spans.len(), SIDE as usize);
                assert!(line.spans.iter().all(|s| s.content == "▀"));
            }
        }
    }

    #[test]
    fn no_color_carries_occupancy_on_the_glyph() {
        let text: Vec<String> = canonical_mark()
            .lines(&Theme::dark(Depth::None))
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect();
        // Grid rows 0 over 1, then 2 over 3:
        //   . X X X  over  X . X .  ->  ▄ ▀ █ ▀
        //   X X X X  over  . X . X  ->  ▀ █ ▀ █
        assert_eq!(text, vec!["▄▀█▀".to_string(), "▀█▀█".to_string()]);
    }

    #[test]
    fn a_mid_assembly_frame_draws_fewer_modules_than_a_resolved_one() {
        let theme = dark();
        let ground = theme.color(theme.panel);
        let painted = |mark: &Mark| {
            mark.lines(&theme)
                .iter()
                .flat_map(|l| l.spans.clone())
                .filter(|s| s.style.fg != Some(ground))
                .count()
        };

        let mut mark = Mark::new(1, true);
        let resolved = painted(&mark);
        mark.assemble(Instant::now());
        mark.advance();
        assert!(painted(&mark) < resolved);
    }
}
