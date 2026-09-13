use std::path::Path;

fn check_tree(path: &Path) {
    for entry in std::fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            check_tree(&path);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let count = std::fs::read_to_string(&path).unwrap().lines().count();
            assert!(
                count <= 300,
                "{} has {count} lines (maximum 300)",
                path.display()
            );
        }
    }
}

#[test]
fn every_owned_rust_file_is_at_most_300_lines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for directory in ["src", "tests", "examples"] {
        check_tree(&root.join(directory));
    }
}
