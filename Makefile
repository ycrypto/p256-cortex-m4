build:
	cargo build --target thumbv7em-none-eabi

doc:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --target thumbv7em-none-eabi --all-features --open

pc-doc:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --target x86_64-unknown-linux-gnu --all-features --open
