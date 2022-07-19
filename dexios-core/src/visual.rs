#[cfg(feature = "visual")]
use indicatif::{ProgressBar, ProgressStyle};

#[cfg(feature = "visual")]
pub fn create_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.cyan}"));

    pb
}
