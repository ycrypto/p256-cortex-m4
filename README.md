<h1 align="center">p256-cortex-m4</h1>
<div align="center">
 <strong>
   Fast NIST P256 signatures for Cortex-M4 microcontrollers
 </strong>
</div>

<br />

<div align="center">
  <!-- Crates version -->
  <a href="https://crates.io/crates/p256-cortex-m4">
    <img src="https://img.shields.io/crates/v/p256-cortex-m4.svg?style=flat-square"
    alt="Crates.io version" />
  </a>
  <!-- Downloads -->
  <a href="https://crates.io/crates/p256-cortex-m4">
    <img src="https://img.shields.io/crates/d/p256-cortex-m4.svg?style=flat-square"
      alt="Download" />
  </a>
  <!-- API docs -->
  <a href="https://docs.rs/p256-cortex-m4">
    <img src="https://img.shields.io/badge/docs-release-blue.svg?style=flat-square"
      alt="latest release API docs" />
  </a>
  <!-- API docs -->
  <a href="https://ycrypto.github.io/p256-cortex-m4">
    <img src="https://img.shields.io/badge/docs-main-blue.svg?style=flat-square"
      alt="main branch API docs" />
  </a>
</div>


## What is this?

Idiomatic, misuse-resistant bindings for the glorious and ultra-fast
[P256-Cortex-M4][p256-cortex-m4] ECDH and ECDSA implementation.

[p256-cortex-m4]: https://github.com/Emill/P256-Cortex-M4


## Building / Usage

On platforms other than Cortex-M4 and Cortex-M33, the implementation from `p256`
is re-used, with the same (simplified) API.

If this fallback is not desired, deactivate the `non-cortex-m4-fallback` feature.


#### License

<sup>P256-Cortex-M4 is licensed under [MIT][mit], as are these bindings.</sup>

[mit]: https://github.com/Emill/P256-Cortex-M4/blob/master/LICENSE.txt
