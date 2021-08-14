#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#[cfg(all(cortex_m4, feature = "bindgen"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
#[cfg(all(cortex_m4, not(feature = "bindgen")))]
include!("bindings.rs");
