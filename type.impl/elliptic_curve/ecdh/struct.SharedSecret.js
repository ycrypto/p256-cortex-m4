(function() {var type_impls = {
"p256":[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#160\">source</a><a href=\"#impl-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.extract\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#192-194\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html#tymethod.extract\" class=\"fn\">extract</a>&lt;D&gt;(&amp;self, salt: <a class=\"enum\" href=\"https://doc.rust-lang.org/1.76.0/core/option/enum.Option.html\" title=\"enum core::option::Option\">Option</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.u8.html\">u8</a>]&gt;) -&gt; <a class=\"struct\" href=\"hkdf/struct.Hkdf.html\" title=\"struct hkdf::Hkdf\">Hkdf</a>&lt;D, <a class=\"struct\" href=\"hmac/simple/struct.SimpleHmac.html\" title=\"struct hmac::simple::SimpleHmac\">SimpleHmac</a>&lt;D&gt;&gt;<div class=\"where\">where\n    D: <a class=\"trait\" href=\"crypto_common/trait.BlockSizeUser.html\" title=\"trait crypto_common::BlockSizeUser\">BlockSizeUser</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"digest/digest/trait.Digest.html\" title=\"trait digest::digest::Digest\">Digest</a>,</div></h4></section></summary><div class=\"docblock\"><p>Use <a href=\"https://en.wikipedia.org/wiki/HKDF\">HKDF</a> (HMAC-based Extract-and-Expand Key Derivation Function) to\nextract entropy from this shared secret.</p>\n<p>This method can be used to transform the shared secret into uniformly\nrandom values which are suitable as key material.</p>\n<p>The <code>D</code> type parameter is a cryptographic digest function.\n<code>sha2::Sha256</code> is a common choice for use with HKDF.</p>\n<p>The <code>salt</code> parameter can be used to supply additional randomness.\nSome examples include:</p>\n<ul>\n<li>randomly generated (but authenticated) string</li>\n<li>fixed application-specific value</li>\n<li>previous shared secret used for rekeying (as in TLS 1.3 and Noise)</li>\n</ul>\n<p>After initializing HKDF, use <a href=\"hkdf/struct.Hkdf.html#method.expand\" title=\"method hkdf::Hkdf::expand\"><code>Hkdf::expand</code></a> to obtain output key\nmaterial.</p>\n</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.raw_secret_bytes\" class=\"method\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#213\">source</a><h4 class=\"code-header\">pub fn <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html#tymethod.raw_secret_bytes\" class=\"fn\">raw_secret_bytes</a>(\n    &amp;self\n) -&gt; &amp;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.u8.html\">u8</a>, &lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.FieldBytesSize\" title=\"type elliptic_curve::Curve::FieldBytesSize\">FieldBytesSize</a>&gt;</h4></section></summary><div class=\"docblock\"><p>This value contains the raw serialized x-coordinate of the elliptic curve\npoint computed from a Diffie-Hellman exchange, serialized as bytes.</p>\n<p>When in doubt, use <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html#method.extract\" title=\"method elliptic_curve::ecdh::SharedSecret::extract\"><code>SharedSecret::extract</code></a> instead.</p>\n<h5 id=\"-warning-not-uniformly-random-\"><a href=\"#-warning-not-uniformly-random-\">⚠️ WARNING: NOT UNIFORMLY RANDOM! ⚠️</a></h5>\n<p>This value is not uniformly random and should not be used directly\nas a cryptographic key for anything which requires that property\n(e.g. symmetric ciphers).</p>\n<p>Instead, the resulting value should be used as input to a Key Derivation\nFunction (KDF) or cryptographic hash function to produce a symmetric key.\nThe <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html#method.extract\" title=\"method elliptic_curve::ecdh::SharedSecret::extract\"><code>SharedSecret::extract</code></a> function will do this for you.</p>\n</div></details></div></details>",0,"p256::ecdh::SharedSecret"],["<section id=\"impl-ZeroizeOnDrop-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#230\">source</a><a href=\"#impl-ZeroizeOnDrop-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"zeroize/trait.ZeroizeOnDrop.html\" title=\"trait zeroize::ZeroizeOnDrop\">ZeroizeOnDrop</a> for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section>","ZeroizeOnDrop","p256::ecdh::SharedSecret"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-From%3CGenericArray%3Cu8,+%3CC+as+Curve%3E::FieldBytesSize%3E%3E-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#218\">source</a><a href=\"#impl-From%3CGenericArray%3Cu8,+%3CC+as+Curve%3E::FieldBytesSize%3E%3E-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.From.html\" title=\"trait core::convert::From\">From</a>&lt;<a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.u8.html\">u8</a>, &lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.FieldBytesSize\" title=\"type elliptic_curve::Curve::FieldBytesSize\">FieldBytesSize</a>&gt;&gt; for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.from\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#225\">source</a><a href=\"#method.from\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/convert/trait.From.html#tymethod.from\" class=\"fn\">from</a>(\n    secret_bytes: <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.u8.html\">u8</a>, &lt;C as <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt;::<a class=\"associatedtype\" href=\"elliptic_curve/trait.Curve.html#associatedtype.FieldBytesSize\" title=\"type elliptic_curve::Curve::FieldBytesSize\">FieldBytesSize</a>&gt;\n) -&gt; <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;</h4></section></summary><div class=\"docblock\"><p>NOTE: this impl is intended to be used by curve implementations to\ninstantiate a <a href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\"><code>SharedSecret</code></a> value from their respective\n<a href=\"elliptic_curve/point/type.AffinePoint.html\" title=\"type elliptic_curve::point::AffinePoint\"><code>AffinePoint</code></a> type.</p>\n<p>Curve implementations should provide the field element representing\nthe affine x-coordinate as <code>secret_bytes</code>.</p>\n</div></details></div></details>","From<GenericArray<u8, <C as Curve>::FieldBytesSize>>","p256::ecdh::SharedSecret"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Drop-for-SharedSecret%3CC%3E\" class=\"impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#232\">source</a><a href=\"#impl-Drop-for-SharedSecret%3CC%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"elliptic_curve/ecdh/struct.SharedSecret.html\" title=\"struct elliptic_curve::ecdh::SharedSecret\">SharedSecret</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.drop\" class=\"method trait-impl\"><a class=\"src rightside\" href=\"src/elliptic_curve/ecdh.rs.html#233\">source</a><a href=\"#method.drop\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/1.76.0/core/ops/drop/trait.Drop.html#tymethod.drop\" class=\"fn\">drop</a>(&amp;mut self)</h4></section></summary><div class='docblock'>Executes the destructor for this type. <a href=\"https://doc.rust-lang.org/1.76.0/core/ops/drop/trait.Drop.html#tymethod.drop\">Read more</a></div></details></div></details>","Drop","p256::ecdh::SharedSecret"]]
};if (window.register_type_impls) {window.register_type_impls(type_impls);} else {window.pending_type_impls = type_impls;}})()