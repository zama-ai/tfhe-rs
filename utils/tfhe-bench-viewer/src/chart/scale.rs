//! An axis: the range it covers, how a value maps into it, and where its
//! gridlines go.

/// Built by one of two constructors depending on what the axis carries, then
/// read the same way.
pub struct Scale {
    pub low: f64,
    pub high: f64,
    log: bool,
}

impl Scale {
    /// A linear axis over the values as they are, padded but never snapped:
    /// rounding seconds since the epoch to a "nice" step would only move the
    /// dates to less readable ones.
    pub fn span(values: impl Iterator<Item = f64>) -> Option<Self> {
        let (mut low, mut high) = (f64::MAX, f64::MIN);
        for value in values {
            low = low.min(value);
            high = high.max(value);
        }
        if low > high {
            return None;
        }

        // Half an hour on each side of a single run, so its marker is not
        // pinned to the frame.
        let pad = ((high - low) * 0.02).max(1_800.0);
        Some(Self {
            low: low - pad,
            high: high + pad,
            log: false,
        })
    }

    /// `None` when there is nothing to draw. A log scale leaves out anything
    /// that is not strictly positive rather than pretending to place it.
    pub fn over(values: impl Iterator<Item = f64>, log: bool) -> Option<Self> {
        let (mut low, mut high) = (f64::MAX, f64::MIN);
        for value in values {
            if log && value <= 0.0 {
                continue;
            }
            low = low.min(value);
            high = high.max(value);
        }
        if low > high {
            return None;
        }

        if log {
            let (low, high) = (low.log10().floor(), high.log10().ceil());
            // A single decade of span would put every point on one gridline.
            return Some(if high - low < 1.0 {
                Self {
                    low: low - 0.5,
                    high: high + 0.5,
                    log,
                }
            } else {
                Self { low, high, log }
            });
        }

        // A flat series still needs a range to sit in the middle of.
        if high - low < f64::EPSILON * high.abs().max(1.0) {
            let pad = high.abs().max(1.0) * 0.1;
            return Some(Self {
                low: low - pad,
                high: high + pad,
                log,
            });
        }

        // Snapped out to round steps, so the gridlines carry readable numbers.
        let step = nice_step((high - low) / 4.0);
        Some(Self {
            low: (low / step).floor() * step,
            high: (high / step).ceil() * step,
            log,
        })
    }

    /// Where a value sits in the range, from 0 at the bottom to 1 at the top.
    pub fn fraction(&self, value: f64) -> f32 {
        let value = if self.log { value.log10() } else { value };
        ((value - self.low) / (self.high - self.low)) as f32
    }

    /// Ticks at even fractions of the range, for an axis whose values have no
    /// round numbers to snap to.
    pub fn even_ticks(&self, count: usize) -> Vec<f64> {
        let step = (self.high - self.low) / count as f64;
        (0..=count)
            .map(|index| self.low + step * index as f64)
            .collect()
    }

    pub fn ticks(&self) -> Vec<f64> {
        let mut ticks = Vec::new();
        if self.log {
            let mut decade = self.low.ceil();
            while decade <= self.high + 1e-9 {
                ticks.push(10f64.powf(decade));
                decade += 1.0;
            }
        } else {
            let step = nice_step((self.high - self.low) / 4.0);
            let mut tick = (self.low / step).ceil() * step;
            while tick <= self.high + step * 1e-9 {
                ticks.push(tick);
                tick += step;
            }
        }
        ticks
    }
}

/// The 1, 2, 5, 10 ladder: the steps a reader can do arithmetic on.
fn nice_step(rough: f64) -> f64 {
    if rough <= 0.0 || !rough.is_finite() {
        return 1.0;
    }
    let magnitude = 10f64.powf(rough.log10().floor());
    let normalized = rough / magnitude;
    let step = if normalized <= 1.0 {
        1.0
    } else if normalized <= 2.0 {
        2.0
    } else if normalized <= 5.0 {
        5.0
    } else {
        10.0
    };
    step * magnitude
}
