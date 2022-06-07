use crate::crypto::primitives::Algorithm;

pub const ALGORITHMS: [Algorithm; 3] = [
    Algorithm::XChaCha20Poly1305,
    Algorithm::Aes256Gcm,
    Algorithm::DeoxysII256,
];

pub mod header;
pub mod parameters;
pub mod protected;
pub mod states;
pub mod structs;
