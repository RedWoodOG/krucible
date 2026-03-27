// Test 2: pub fn functions with NO #[tauri::command] annotation
// Expected: pub fn must NOT be treated as Tauri commands
//           zero false positives from unannotated public functions

use tauri::Manager;

// Annotated — IS a command
#[tauri::command]
pub fn real_command() -> String {
    "from backend".to_string()
}

// Public but NOT a command — must not be flagged as command
pub fn get_config() -> String {
    "config".to_string()
}

// Public but NOT a command
pub fn set_theme(theme: String) {
    println!("theme: {}", theme);
}

// Public but NOT a command
pub fn fetch_settings() -> Vec<String> {
    vec!["setting1".into(), "setting2".into()]
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![real_command])
        .run(tauri::generate_context!())
        .expect("error");
}
