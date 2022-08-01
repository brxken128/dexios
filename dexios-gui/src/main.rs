use dexios_core::primitives::Algorithm;
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
    aead: Algorithm,
    input_path: String,
    output_path: String,
    key: Key,
    keyfile_path: String,
    password: String,
    password_validation: String,
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
                ui.radio_value(&mut self.key, Key::AutoGenerate, "Auto Generate");
            });

            ui.add_enabled_ui(self.key == Key::Password, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Password: ");
                    ui.add(egui::TextEdit::singleline(&mut self.password).hint_text("Password: "));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password_validation)
                            .hint_text("Password (for validation): "),
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

            if ui.button("Encrypt File").clicked() {
                // encrypty stuff
            }
        });
    }
}
