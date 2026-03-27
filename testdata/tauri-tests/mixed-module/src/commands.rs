// Test 3: Tauri commands inside a submodule
// Expected: #[tauri::command] detected even inside module structure

// Correctly annotated command in submodule
#[tauri::command]
pub fn save_file(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| e.to_string())
}

// Correctly annotated command in submodule
#[tauri::command]
pub fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

// Helper pub fn — NOT a command, must be ignored
pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

// Private helper — not a command
fn validate_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/')
}
