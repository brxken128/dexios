use crate::states::Encrypt;
use crate::ui_ok;
use crate::utils::message_box;
use core::header::HEADER_VERSION;
use domain::storage::Storage;

pub fn execute(encrypt: &Encrypt) {
    let params = encrypt.clone();
    let _ = std::thread::spawn(move || {
        let stor = std::sync::Arc::new(domain::storage::FileStorage);
        let input_file = ui_ok!(
            stor.read_file(params.input_path.clone()),
            "Unable to read the input file."
        );
        let output_file = ui_ok!(
            stor.create_file(params.output_path.clone())
                .or_else(|_| stor.write_file(params.output_path.clone())),
            "Unable to create the output file."
        );

        let raw_key = ui_ok!(
            params.key.get_value_for_encrypting(&params),
            "Unable to get your key."
        );

        let req = domain::encrypt::Request {
            reader: ui_ok!(
                input_file.try_reader(),
                "Unable to get a reader for the input file"
            ),
            writer: ui_ok!(
                output_file.try_writer(),
                "Unable to get a writer for the output file"
            ),
            header_writer: None, // need to add a checkbox and enabled_ui for this
            raw_key,
            header_type: core::header::HeaderType {
                version: HEADER_VERSION,
                mode: core::primitives::Mode::StreamMode,
                algorithm: params.algorithm,
            },
            hashing_algorithm: params.hash_algorithm,
        };
        ui_ok!(
            domain::encrypt::execute(req),
            "There was an error while encrypting your file"
        );

        ui_ok!(
            stor.flush_file(&output_file),
            "Unable to flush the output file"
        );

        message_box("Encryption successful!");
    })
    .join();
}
