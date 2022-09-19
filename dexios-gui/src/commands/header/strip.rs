use std::cell::RefCell;
use std::fs::OpenOptions;

use crate::states::HeaderStrip;
use crate::ui_ok;
use crate::utils::message_box;

pub fn execute(strip: &HeaderStrip) {
    let params = strip.clone();
    let _ = std::thread::spawn(move || {
        let input_file = RefCell::new(
            ui_ok!(OpenOptions::new()
                .read(true)
                .write(true)
                .open(params.input_path), "Unable to open the input file")
        );

        let req = domain::header::strip::Request {
            handle: &input_file,
        };

        ui_ok!(
            domain::header::strip::execute(req),
            "There was an error while stripping the header"
        );

        message_box("Header Strip successful!");
    })
    .join();
}
