use crate::states::Decrypt;
use crate::ui_ok;
use crate::utils::message_box;
use domain::storage::Storage;

pub fn execute(decrypt: &Decrypt) {
    let params = decrypt.clone();
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
            params.key.get_value_for_decrypting(&params),
            "Unable to get your key."
        );

        let req = domain::decrypt::Request {
            reader: ui_ok!(
                input_file.try_reader(),
                "Unable to get a reader for the input file"
            ),
            writer: ui_ok!(
                output_file.try_writer(),
                "Unable to get a writer for the output file"
            ),
            header_reader: None, // need to add a checkbox and enabled_ui for this
            raw_key,
            on_decrypted_header: None,
        };
        ui_ok!(
            domain::decrypt::execute(req),
            "There was an error while decrypting your file"
        );

        message_box("Decryption successful!");
    })
    .join();
}
