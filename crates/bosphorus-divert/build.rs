//! Stage the WinDivert runtime files (`WinDivert.dll`, `WinDivert64.sys`) so
//! that any binary in the workspace can load them:
//!
//!   * `<target>/<profile>/`        — next to `bosphorus.exe`
//!   * `<target>/<profile>/deps/`   — next to test / example binaries
//!
//! `windivert-sys` itself only copies these into its own `OUT_DIR`, which is
//! enough for the linker but not for `LoadLibrary` at run time.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=WINDIVERT_PATH");

    let Ok(src) = env::var("WINDIVERT_PATH") else {
        println!("cargo:warning=WINDIVERT_PATH not set; WinDivert.dll/.sys not staged");
        return;
    };
    let src = PathBuf::from(src);

    // OUT_DIR = <target>/<profile>/build/<pkg>-<hash>/out  ->  ancestors[3] = <target>/<profile>
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let Some(profile_dir) = out_dir.ancestors().nth(3) else {
        println!(
            "cargo:warning=cannot derive target dir from OUT_DIR={}",
            out_dir.display()
        );
        return;
    };
    let deps_dir = profile_dir.join("deps");
    let _ = fs::create_dir_all(&deps_dir);

    for name in ["WinDivert.dll", "WinDivert64.sys"] {
        let from = src.join(name);
        if let Err(e) = fs::copy(&from, profile_dir.join(name)) {
            println!("cargo:warning=could not stage {name} from {}: {e}", from.display());
        }
        // best-effort: lets `cargo test` / `cargo run --example` load the dll
        let _ = fs::copy(&from, deps_dir.join(name));
    }
}
