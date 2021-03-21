#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#[cfg(cortex_m4)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
