#!/usr/bin/env bash

# Copyright Materialize, Inc. All rights reserved.
#
# Use of this software is governed by the Business Source License
# included in the LICENSE file at the root of this repository.
#
# As of the Change Date specified in that file, in accordance with
# the Business Source License, use of this software will be governed
# by the Apache License, Version 2.0.
#
# doc — renders API documentation.

set -euo pipefail

crate=$(basename $(pwd))

# Create a nice homepage for the docs. It's awful that we have to copy the
# HTML template like this, but the upstream issue [0] that would resolve this is
# now five years old and doesn't look close to resolution.
# [0]: https://github.com/rust-lang/cargo/issues/739
cat > target/thumbv7em-none-eabi/doc/index.html <<EOF
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>$crate</title>
    <link rel="stylesheet" type="text/css" href="normalize.css">
    <link rel="stylesheet" type="text/css" href="rustdoc.css" id="mainThemeStyle">
    <link rel="stylesheet" type="text/css" href="dark.css">
    <link rel="stylesheet" type="text/css" href="light.css" id="themeStyle">
    <script src="storage.js"></script>
    <noscript>
        <link rel="stylesheet" href="noscript.css">
    </noscript>
    <link rel="shortcut icon" href="favicon.ico">
    <style type="text/css">
        #crate-search {
            background-image: url("down-arrow.svg");
        }
    </style>
</head>

<body class="rustdoc mod">
    <!--[if lte IE 8]><div class="warning">This old browser is unsupported and will most likely display funky things.</div><![endif]-->
    <nav class="sidebar">
        <div class="sidebar-menu">&#9776;</div>
        <a href='index.html'><div class='logo-container'><img src='rust-logo.png' alt='logo'></div></a>
        <p class='location'>Home</p>
        <div class="sidebar-elems">
        </div>
    </nav>
    <div class="theme-picker">
        <button id="theme-picker" aria-label="Pick another theme!"><img src="brush.svg" width="18" alt="Pick another theme!"></button>
        <div id="theme-choices"></div>
    </div>
    <script src="theme.js"></script>
    <nav class="sub">
        <form class="search-form js-only">
            <div class="search-container">
                <div>
                    <select id="crate-search">
                        <option value="All crates">All crates</option>
                    </select>
                    <input class="search-input" name="search" autocomplete="off" spellcheck="false" placeholder="Click or press ‘S’ to search, ‘?’ for more options…" type="search">
                </div>
                <a id="settings-menu" href="settings.html"><img src="wheel.svg" width="18" alt="Change settings"></a>
            </div>
        </form>
    </nav>
    <section id="main" class="content">
        <h1 class='fqn'>
            <span class='in-band'>$crate documentation</span>
        </h1>
        <p>This is the home of $crate's internal API documentation.</p>
    </section>
    <section id="search" class="content hidden"></section>
    <section class="footer"></section>
    <script>
        window.rootPath = "./";
        window.currentCrate = "$crate";
    </script>
    <script src="aliases.js"></script>
    <script src="main.js"></script>
    <script defer src="search-index.js"></script>
</body>

</html>
EOF

# Make the logo link to the nice homepage we just created. Otherwise it just
# links to the root of whatever crate you happen to be looking at.
cat >> target/thumbv7em-none-eabi/doc/main.js <<EOF
;
var el = document.querySelector("img[alt=logo]").closest("a");
if (el.href != "index.html") {
    el.href = "../index.html";
}
EOF

