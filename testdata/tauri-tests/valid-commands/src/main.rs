// Test 1: Valid Tauri app — all commands properly annotated and wired
// Expected behavior:
//   #[tauri::command] functions → detected as commands, NOT flagged as dead code
//   pub fn without annotation  → NOT treated as a command
//   Private helper             → NOT treated as a command

use std::fs;

// Correctly annotated command — IS a command
#[tauri::command]
pub fn get_user(id: String) -> String {
    format!("user_{}", id)
}

// Correctly annotated command — IS a command, has real implementation
#[tauri::command]
pub fn read_config(path: String) -> Result<String, String> {
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

// Correctly annotated command — IS a command
#[tauri::command]
pub fn write_config(path: String, content: String) -> Result<(), String> {
    fs::write(&path, content).map_err(|e| e.to_string())
}

// Public helper — NOT a command. Should not be treated as one.
pub fn get_app_dir() -> String {
    "/home/user/.config/myapp".to_string()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_user, read_config, write_config])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
