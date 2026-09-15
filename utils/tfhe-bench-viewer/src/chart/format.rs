//! Turning the two kinds of number a plot carries into something readable: a
//! duration or a rate on one axis, a date on the other.

use benchmark_spec::BenchmarkMetric;

pub fn value(value: f64, metric: BenchmarkMetric) -> String {
    match metric {
        BenchmarkMetric::Throughput => {
            for (scale, unit) in [(1e6, "M.ops/s"), (1e3, "k.ops/s")] {
                if value.abs() >= scale {
                    return format!("{:.3} {unit}", value / scale);
                }
            }
            format!("{value:.3} ops/s")
        }
        _ => {
            for (scale, unit) in [(1e9, "s"), (1e6, "ms"), (1e3, "µs")] {
                if value.abs() >= scale {
                    return format!("{:.3} {unit}", value / scale);
                }
            }
            format!("{value:.3} ns")
        }
    }
}

/// Seconds since the epoch, as a date. Written out rather than pulled from a
/// calendar crate: four ticks do not need a timezone database.
pub fn date(at: f64, date_only: bool) -> String {
    let seconds = at as i64;
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);

    if date_only {
        format!("{year:04}-{month:02}-{day:02}")
    } else {
        format!(
            "{year:04}-{month:02}-{day:02} {:02}:{:02}",
            time / 3600,
            (time % 3600) / 60,
        )
    }
}

/// Howard Hinnant's `civil_from_days`, the standard days-to-date conversion.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    (year + i64::from(month <= 2), month, day)
}
