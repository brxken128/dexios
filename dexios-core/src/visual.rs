//! This module offers visual functionality within `dexios-core`.
//!
//! It isn't rather populated, nor does `dexios` itself use it, but the option is always there.
//!
//! This can be enabled with the `visual` feature, and you will notice a blue spinner on encryption and decryption - useful for knowing that something is still happening.

#[cfg(feature = "visual")]
use indicatif::{ProgressBar, ProgressStyle};

#[cfg(feature = "visual")]
#[must_use]
/// This creates a visual spinner, which can be enabled with the `visual` feature.
///
/// The spinner is used for both encrypting and decrypting, provided the feature is enabled.
pub fn create_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan}"));

    pb
}
