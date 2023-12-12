use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET")?;

    // Cortex-M33 is compatible with Cortex-M4 and its DSP extension instruction UMAAL.
    let cortex_m4 = target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main");
    if cortex_m4 {
        println!("cargo:rustc-cfg=cortex_m4");
    }

    Ok(())
}
