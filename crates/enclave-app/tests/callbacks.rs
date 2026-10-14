//! Every callback the UI declares is connected in `shell.rs`. Slint lets an
//! unconnected callback compile and do nothing, which is how buttons go dead.

#[test]
fn every_ui_callback_is_connected() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let ui = std::fs::read_to_string(format!("{dir}/ui/app.slint")).unwrap_or_default();
    let main = std::fs::read_to_string(format!("{dir}/src/shell.rs")).unwrap_or_default();
    assert!(!ui.is_empty() && !main.is_empty());
    let mut missing = Vec::new();
    // Callbacks of the window itself: four-space indent inside AppWindow.
    let window = ui
        .split("export component AppWindow")
        .nth(1)
        .unwrap_or_default();
    assert!(!window.is_empty());
    for line in window.lines() {
        let Some(rest) = line.strip_prefix("    callback ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let rust = format!("on_{}(", name.replace('-', "_"));
        if !main.contains(&rust) {
            missing.push(name);
        }
    }
    assert!(missing.is_empty(), "callbacks not connected: {missing:?}");
}
