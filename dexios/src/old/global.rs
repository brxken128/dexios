pub mod parameters;
pub mod states;
pub mod structs;

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        println!("[i] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        println!("[!] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! success {
    ($($arg:tt)*) => {
        println!("[+] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        println!("[-] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! question {
    ($($arg:tt)*) => {
        print!("[?] {}", format!($($arg)*));

    }
}
