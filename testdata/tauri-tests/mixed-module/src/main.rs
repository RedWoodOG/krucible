mod commands;
use commands::{save_file, read_file};

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![save_file, read_file])
        .run(tauri::generate_context!())
        .expect("error");
}
