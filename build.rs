extern crate build;

// FIXME https://github.com/retep998/winapi-rs/pull/319
fn main() {
    build::link("ncrypt", true)
}
