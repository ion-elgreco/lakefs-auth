fn main() {
    // Embedded migrations must be re-read when a file changes.
    println!("cargo:rerun-if-changed=migrations");
}
