use std::io::Read;

use dexios_core::header::HEADER_VERSION;
use dexios_core::primitives::Algorithm;
use dexios_core::protected::Protected;
use domain::storage::Storage;
use domain::utils::gen_passphrase;
use eframe::egui;

fn main() {
    let mut options = eframe::NativeOptions::default();
    options.resizable = false;
    eframe::run_native(
        "DEXIOS",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    );
}

struct MyApp {
    aead: Algorithm, // aead needs renaming to algorithm
    input_path: String,
    output_path: String,
    key: Key,
    keyfile_path: String,
    password: String,
    password_validation: String,
    autogenerated_passphrase: String,
    // incomplete
}

#[derive(PartialEq)]
enum Key {
    Keyfile,
    AutoGenerate,
    Password,
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Keyfile => write!(f, "Keyfile"),
            Key::Password => write!(f, "Password"),
            Key::AutoGenerate => write!(f, "Auto Generate"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    PasswordsDontMatch,
    EmptyKey,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            PasswordsDontMatch => f.write_str("The passwords provided don't match"),
            EmptyKey => f.write_str("The provided key is empty"),
        }
    }
}

impl std::error::Error for Error {}

impl Key {
    pub fn get_value(&self, values: &MyApp) -> Result<Protected<Vec<u8>>, Error> {
        match self {
            Key::Password => {
                if values.password == values.password_validation {
                    Ok(Protected::new(values.password.clone().into_bytes()))
                } else {
                    Err(Error::PasswordsDontMatch)
                }
            }
            Key::AutoGenerate => Ok(Protected::new(
                values.autogenerated_passphrase.clone().into_bytes(),
            )),
            Key::Keyfile => {
                let mut reader = std::fs::File::open(values.keyfile_path.clone()).unwrap();
                let mut secret = Vec::new();
                reader.read_to_end(&mut secret).unwrap();
                Ok(Protected::new(secret))
            }
        }
    }
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            aead: Algorithm::XChaCha20Poly1305,
            input_path: "".to_owned(),
            output_path: "".to_owned(),
            key: Key::Password,
            keyfile_path: "".to_owned(),
            password: "".to_owned(),
            password_validation: "".to_owned(),
            autogenerated_passphrase: "".to_owned(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Encrypt a File");
            ui.horizontal(|ui| {
                ui.label("Algorithm: ");
                egui::ComboBox::from_id_source("aead")
                    .selected_text(format!("{}", self.aead))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.aead,
                            Algorithm::XChaCha20Poly1305,
                            "XChaCha20-Poly1305",
                        );
                        ui.selectable_value(&mut self.aead, Algorithm::Aes256Gcm, "AES-256-GCM");
                    });
            });

            ui.horizontal(|ui| {
                ui.label("Input File: ");
                ui.add(
                    egui::TextEdit::singleline(&mut self.input_path)
                        .hint_text("Path to the input file"),
                );
                if ui.button("Select File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.input_path = path.as_path().display().to_string();
                        self.output_path = self.input_path.clone() + ".dx";
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.label("Output File: ");
                ui.add(
                    egui::TextEdit::singleline(&mut self.output_path)
                        .hint_text("Path to the output file"),
                );
                if ui.button("Select File").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.output_path = path.as_path().display().to_string();
                    }
                }
            });

            ui.separator();

            ui.horizontal(|ui| {
                ui.radio_value(&mut self.key, Key::Password, "Password");
                ui.radio_value(&mut self.key, Key::Keyfile, "Keyfile");
                if ui
                    .radio_value(&mut self.key, Key::AutoGenerate, "Auto Generate")
                    .clicked()
                {
                    self.autogenerated_passphrase = gen_passphrase().expose().to_string();
                };
            });

            ui.add_enabled_ui(self.key == Key::Password, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Password: ");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .hint_text("Password: ")
                            .password(true),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password_validation)
                            .hint_text("Password (for validation): ")
                            .password(true),
                    );
                });
            });

            ui.add_enabled_ui(self.key == Key::Keyfile, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Keyfile: ");

                    ui.add(
                        egui::TextEdit::singleline(&mut self.keyfile_path)
                            .hint_text("Path to the keyfile"),
                    );
                    if ui.button("Select File").clicked() {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.keyfile_path = path.as_path().display().to_string();
                        }
                    }
                });
            });

            ui.add_enabled_ui(self.key == Key::AutoGenerate, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Auto-generated passphrase: ");
                    ui.add(
                        egui::TextEdit::singleline(
                            &mut self.autogenerated_passphrase,
                            // add a "copy" button (maybe with arboard)
                        )
                        .interactive(false),
                    );
                });
            });

            if ui.button("Encrypt File").clicked() {
                // encrypty stuff, move to separate function
                let stor = std::sync::Arc::new(domain::storage::FileStorage);

                let input_file = stor.read_file(self.input_path.clone()).unwrap();
                let output_file = stor
                    .create_file(self.output_path.clone())
                    .or_else(|_| stor.write_file(self.output_path.clone()))
                    .unwrap();

                let raw_key = self.key.get_value(&self).unwrap();

                let req = domain::encrypt::Request {
                    reader: input_file.try_reader().unwrap(),
                    writer: output_file.try_writer().unwrap(),
                    header_writer: None, // need to add a checkbox and enabled_ui for this
                    raw_key,
                    header_type: dexios_core::header::HeaderType {
                        version: HEADER_VERSION,
                        mode: dexios_core::primitives::Mode::StreamMode,
                        algorithm: self.aead,
                    },
                    hashing_algorithm: dexios_core::header::HashingAlgorithm::Blake3Balloon(5),
                };
                domain::encrypt::execute(req).unwrap();
            }
        });
    }
}
