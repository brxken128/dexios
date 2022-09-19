use crate::states::HeaderDump;
use crate::ui_ok;
use crate::utils::message_box;
use domain::storage::Storage;

pub fn execute(dump: &HeaderDump) {
    let params = dump.clone();
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

        let req = domain::header::dump::Request {
            reader: ui_ok!(
                input_file.try_reader(),
                "Unable to get a reader for the input file"
            ),
            writer: ui_ok!(
                output_file.try_writer(),
                "Unable to get a writer for the output file"
            ),
        };

        ui_ok!(
            domain::header::dump::execute(req),
            "There was an error while dumping the header"
        );

        message_box("Header Dump successful!");
    })
    .join();
}
