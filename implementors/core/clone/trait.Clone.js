(function() {var implementors = {};
implementors["block_buffer"] = [{"text":"impl&lt;BlockSize:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"block_buffer/struct.BlockBuffer.html\" title=\"struct block_buffer::BlockBuffer\">BlockBuffer</a>&lt;BlockSize&gt;","synthetic":false,"types":["block_buffer::BlockBuffer"]}];
implementors["crypto_bigint"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Limb.html\" title=\"struct crypto_bigint::Limb\">Limb</a>","synthetic":false,"types":["crypto_bigint::limb::Limb"]},{"text":"impl&lt;const LIMBS:&nbsp;usize&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_bigint/struct.UInt.html\" title=\"struct crypto_bigint::UInt\">UInt</a>&lt;LIMBS&gt;","synthetic":false,"types":["crypto_bigint::uint::UInt"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Checked.html\" title=\"struct crypto_bigint::Checked\">Checked</a>&lt;T&gt;","synthetic":false,"types":["crypto_bigint::checked::Checked"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;T&gt;","synthetic":false,"types":["crypto_bigint::wrapping::Wrapping"]}];
implementors["crypto_mac"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_mac/struct.MacError.html\" title=\"struct crypto_mac::MacError\">MacError</a>","synthetic":false,"types":["crypto_mac::errors::MacError"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_mac/struct.InvalidKeyLength.html\" title=\"struct crypto_mac::InvalidKeyLength\">InvalidKeyLength</a>","synthetic":false,"types":["crypto_mac::errors::InvalidKeyLength"]},{"text":"impl&lt;M:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"crypto_mac/trait.Mac.html\" title=\"trait crypto_mac::Mac\">Mac</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"crypto_mac/struct.Output.html\" title=\"struct crypto_mac::Output\">Output</a>&lt;M&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;M::<a class=\"type\" href=\"crypto_mac/trait.Mac.html#associatedtype.OutputSize\" title=\"type crypto_mac::Mac::OutputSize\">OutputSize</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["crypto_mac::Output"]}];
implementors["der"] = [{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.Any.html\" title=\"struct der::asn1::Any\">Any</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::any::Any"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.BitString.html\" title=\"struct der::asn1::BitString\">BitString</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::bit_string::BitString"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.ContextSpecific.html\" title=\"struct der::asn1::ContextSpecific\">ContextSpecific</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::context_specific::ContextSpecific"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.GeneralizedTime.html\" title=\"struct der::asn1::GeneralizedTime\">GeneralizedTime</a>","synthetic":false,"types":["der::asn1::generalized_time::GeneralizedTime"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.Ia5String.html\" title=\"struct der::asn1::Ia5String\">Ia5String</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::ia5_string::Ia5String"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.UIntBytes.html\" title=\"struct der::asn1::UIntBytes\">UIntBytes</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::integer::bigint::UIntBytes"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.Null.html\" title=\"struct der::asn1::Null\">Null</a>","synthetic":false,"types":["der::asn1::null::Null"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.OctetString.html\" title=\"struct der::asn1::OctetString\">OctetString</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::octet_string::OctetString"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.PrintableString.html\" title=\"struct der::asn1::PrintableString\">PrintableString</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::printable_string::PrintableString"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.Sequence.html\" title=\"struct der::asn1::Sequence\">Sequence</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::sequence::Sequence"]},{"text":"impl&lt;'a, T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.SetOfRef.html\" title=\"struct der::asn1::SetOfRef\">SetOfRef</a>&lt;'a, T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"der/trait.Decodable.html\" title=\"trait der::Decodable\">Decodable</a>&lt;'a&gt; + <a class=\"trait\" href=\"der/trait.Encodable.html\" title=\"trait der::Encodable\">Encodable</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/cmp/trait.Ord.html\" title=\"trait core::cmp::Ord\">Ord</a>,&nbsp;</span>","synthetic":false,"types":["der::asn1::set_of::SetOfRef"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.UtcTime.html\" title=\"struct der::asn1::UtcTime\">UtcTime</a>","synthetic":false,"types":["der::asn1::utc_time::UtcTime"]},{"text":"impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/asn1/struct.Utf8String.html\" title=\"struct der::asn1::Utf8String\">Utf8String</a>&lt;'a&gt;","synthetic":false,"types":["der::asn1::utf8_string::Utf8String"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/struct.Error.html\" title=\"struct der::Error\">Error</a>","synthetic":false,"types":["der::error::Error"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"der/enum.ErrorKind.html\" title=\"enum der::ErrorKind\">ErrorKind</a>","synthetic":false,"types":["der::error::ErrorKind"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/struct.Header.html\" title=\"struct der::Header\">Header</a>","synthetic":false,"types":["der::header::Header"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/struct.Length.html\" title=\"struct der::Length\">Length</a>","synthetic":false,"types":["der::length::Length"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"der/enum.Class.html\" title=\"enum der::Class\">Class</a>","synthetic":false,"types":["der::tag::class::Class"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"der/struct.TagNumber.html\" title=\"struct der::TagNumber\">TagNumber</a>","synthetic":false,"types":["der::tag::number::TagNumber"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"der/enum.Tag.html\" title=\"enum der::Tag\">Tag</a>","synthetic":false,"types":["der::tag::Tag"]}];
implementors["digest"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"digest/struct.InvalidOutputSize.html\" title=\"struct digest::InvalidOutputSize\">InvalidOutputSize</a>","synthetic":false,"types":["digest::errors::InvalidOutputSize"]}];
implementors["ecdsa"] = [{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"ecdsa/struct.SigningKey.html\" title=\"struct ecdsa::SigningKey\">SigningKey</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;: <a class=\"trait\" href=\"ecdsa/hazmat/trait.FromDigest.html\" title=\"trait ecdsa::hazmat::FromDigest\">FromDigest</a>&lt;C&gt; + <a class=\"trait\" href=\"elliptic_curve/ops/trait.Invert.html\" title=\"trait elliptic_curve::ops::Invert\">Invert</a>&lt;Output = <a class=\"type\" href=\"elliptic_curve/scalar/type.Scalar.html\" title=\"type elliptic_curve::scalar::Scalar\">Scalar</a>&lt;C&gt;&gt; + <a class=\"trait\" href=\"ecdsa/hazmat/trait.SignPrimitive.html\" title=\"trait ecdsa::hazmat::SignPrimitive\">SignPrimitive</a>&lt;C&gt; + <a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":["ecdsa::sign::SigningKey"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"ecdsa/struct.VerifyingKey.html\" title=\"struct ecdsa::VerifyingKey\">VerifyingKey</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/arithmetic/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::arithmetic::ProjectiveArithmetic\">ProjectiveArithmetic</a>,&nbsp;</span>","synthetic":false,"types":["ecdsa::verify::VerifyingKey"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"ecdsa/trait.Curve.html\" title=\"trait ecdsa::Curve\">Curve</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"ecdsa/struct.Signature.html\" title=\"struct ecdsa::Signature\">Signature</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"ecdsa/type.SignatureSize.html\" title=\"type ecdsa::SignatureSize\">SignatureSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":["ecdsa::Signature"]}];
implementors["elliptic_curve"] = [{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/sec1/struct.EncodedPoint.html\" title=\"struct elliptic_curve::sec1::EncodedPoint\">EncodedPoint</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/sec1/type.UntaggedPointSize.html\" title=\"type elliptic_curve::sec1::UntaggedPointSize\">UntaggedPointSize</a>&lt;C&gt;: <a class=\"trait\" href=\"elliptic_curve/ops/trait.Add.html\" title=\"trait elliptic_curve::ops::Add\">Add</a>&lt;<a class=\"type\" href=\"elliptic_curve/consts/type.U1.html\" title=\"type elliptic_curve::consts::U1\">U1</a>&gt; + <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;<a class=\"type\" href=\"elliptic_curve/sec1/type.UncompressedPointSize.html\" title=\"type elliptic_curve::sec1::UncompressedPointSize\">UncompressedPointSize</a>&lt;C&gt;: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":["elliptic_curve::sec1::EncodedPoint"]},{"text":"impl&lt;'a, C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"elliptic_curve/sec1/enum.Coordinates.html\" title=\"enum elliptic_curve::sec1::Coordinates\">Coordinates</a>&lt;'a, C&gt;","synthetic":false,"types":["elliptic_curve::sec1::Coordinates"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"elliptic_curve/sec1/enum.Tag.html\" title=\"enum elliptic_curve::sec1::Tag\">Tag</a>","synthetic":false,"types":["elliptic_curve::sec1::Tag"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/struct.Error.html\" title=\"struct elliptic_curve::Error\">Error</a>","synthetic":false,"types":["elliptic_curve::error::Error"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/struct.ScalarBytes.html\" title=\"struct elliptic_curve::ScalarBytes\">ScalarBytes</a>&lt;C&gt;","synthetic":false,"types":["elliptic_curve::scalar::bytes::ScalarBytes"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::ProjectiveArithmetic\">ProjectiveArithmetic</a>,&nbsp;</span>","synthetic":false,"types":["elliptic_curve::scalar::non_zero::NonZeroScalar"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/struct.PublicKey.html\" title=\"struct elliptic_curve::PublicKey\">PublicKey</a>&lt;C&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;C: <a class=\"trait\" href=\"elliptic_curve/weierstrass/trait.Curve.html\" title=\"trait elliptic_curve::weierstrass::Curve\">Curve</a> + <a class=\"trait\" href=\"elliptic_curve/trait.ProjectiveArithmetic.html\" title=\"trait elliptic_curve::ProjectiveArithmetic\">ProjectiveArithmetic</a>,&nbsp;</span>","synthetic":false,"types":["elliptic_curve::public_key::PublicKey"]},{"text":"impl&lt;C:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"elliptic_curve/struct.SecretKey.html\" title=\"struct elliptic_curve::SecretKey\">SecretKey</a>&lt;C&gt;","synthetic":false,"types":["elliptic_curve::secret_key::SecretKey"]}];
implementors["generic_array"] = [{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"generic_array/struct.GenericArray.html\" title=\"struct generic_array::GenericArray\">GenericArray</a>&lt;T, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;T&gt;,&nbsp;</span>","synthetic":false,"types":["generic_array::GenericArray"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, N&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"generic_array/iter/struct.GenericArrayIter.html\" title=\"struct generic_array::iter::GenericArrayIter\">GenericArrayIter</a>&lt;T, N&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;N: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;T&gt;,&nbsp;</span>","synthetic":false,"types":["generic_array::iter::GenericArrayIter"]}];
implementors["hmac"] = [{"text":"impl&lt;D&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"hmac/struct.Hmac.html\" title=\"struct hmac::Hmac\">Hmac</a>&lt;D&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;D: <a class=\"trait\" href=\"digest/trait.Update.html\" title=\"trait digest::Update\">Update</a> + <a class=\"trait\" href=\"digest/trait.BlockInput.html\" title=\"trait digest::BlockInput\">BlockInput</a> + <a class=\"trait\" href=\"digest/fixed/trait.FixedOutput.html\" title=\"trait digest::fixed::FixedOutput\">FixedOutput</a> + <a class=\"trait\" href=\"digest/trait.Reset.html\" title=\"trait digest::Reset\">Reset</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,<br>&nbsp;&nbsp;&nbsp;&nbsp;D::<a class=\"type\" href=\"digest/trait.BlockInput.html#associatedtype.BlockSize\" title=\"type digest::BlockInput::BlockSize\">BlockSize</a>: <a class=\"trait\" href=\"generic_array/trait.ArrayLength.html\" title=\"trait generic_array::ArrayLength\">ArrayLength</a>&lt;u8&gt;,&nbsp;</span>","synthetic":false,"types":["hmac::Hmac"]}];
implementors["p256"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256/struct.AffinePoint.html\" title=\"struct p256::AffinePoint\">AffinePoint</a>","synthetic":false,"types":["p256::arithmetic::affine::AffinePoint"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256/struct.ProjectivePoint.html\" title=\"struct p256::ProjectivePoint\">ProjectivePoint</a>","synthetic":false,"types":["p256::arithmetic::projective::ProjectivePoint"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>","synthetic":false,"types":["p256::arithmetic::scalar::Scalar"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256/struct.NistP256.html\" title=\"struct p256::NistP256\">NistP256</a>","synthetic":false,"types":["p256::NistP256"]}];
implementors["p256_cortex_m4"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.Error.html\" title=\"struct p256_cortex_m4::Error\">Error</a>","synthetic":false,"types":["p256_cortex_m4::Error"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.SecretKey.html\" title=\"struct p256_cortex_m4::SecretKey\">SecretKey</a>","synthetic":false,"types":["p256_cortex_m4::cortex_m4::SecretKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.PublicKey.html\" title=\"struct p256_cortex_m4::PublicKey\">PublicKey</a>","synthetic":false,"types":["p256_cortex_m4::cortex_m4::PublicKey"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.Keypair.html\" title=\"struct p256_cortex_m4::Keypair\">Keypair</a>","synthetic":false,"types":["p256_cortex_m4::cortex_m4::Keypair"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.Signature.html\" title=\"struct p256_cortex_m4::Signature\">Signature</a>","synthetic":false,"types":["p256_cortex_m4::cortex_m4::Signature"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4/struct.SharedSecret.html\" title=\"struct p256_cortex_m4::SharedSecret\">SharedSecret</a>","synthetic":false,"types":["p256_cortex_m4::cortex_m4::SharedSecret"]}];
implementors["p256_cortex_m4_sys"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4_sys/struct.max_align_t.html\" title=\"struct p256_cortex_m4_sys::max_align_t\">max_align_t</a>","synthetic":false,"types":["p256_cortex_m4_sys::max_align_t"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"p256_cortex_m4_sys/struct.SignPrecomp.html\" title=\"struct p256_cortex_m4_sys::SignPrecomp\">SignPrecomp</a>","synthetic":false,"types":["p256_cortex_m4_sys::SignPrecomp"]}];
implementors["rand_core"] = [{"text":"impl&lt;R:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"rand_core/block/trait.BlockRngCore.html\" title=\"trait rand_core::block::BlockRngCore\">BlockRngCore</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"rand_core/block/struct.BlockRng.html\" title=\"struct rand_core::block::BlockRng\">BlockRng</a>&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R::<a class=\"type\" href=\"rand_core/block/trait.BlockRngCore.html#associatedtype.Results\" title=\"type rand_core::block::BlockRngCore::Results\">Results</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["rand_core::block::BlockRng"]},{"text":"impl&lt;R:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"rand_core/block/trait.BlockRngCore.html\" title=\"trait rand_core::block::BlockRngCore\">BlockRngCore</a> + ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"rand_core/block/struct.BlockRng64.html\" title=\"struct rand_core::block::BlockRng64\">BlockRng64</a>&lt;R&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;R::<a class=\"type\" href=\"rand_core/block/trait.BlockRngCore.html#associatedtype.Results\" title=\"type rand_core::block::BlockRngCore::Results\">Results</a>: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,&nbsp;</span>","synthetic":false,"types":["rand_core::block::BlockRng64"]}];
implementors["sha2"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha256.html\" title=\"struct sha2::Sha256\">Sha256</a>","synthetic":false,"types":["sha2::sha256::Sha256"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha224.html\" title=\"struct sha2::Sha224\">Sha224</a>","synthetic":false,"types":["sha2::sha256::Sha224"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha512.html\" title=\"struct sha2::Sha512\">Sha512</a>","synthetic":false,"types":["sha2::sha512::Sha512"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha384.html\" title=\"struct sha2::Sha384\">Sha384</a>","synthetic":false,"types":["sha2::sha512::Sha384"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha512Trunc256.html\" title=\"struct sha2::Sha512Trunc256\">Sha512Trunc256</a>","synthetic":false,"types":["sha2::sha512::Sha512Trunc256"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"sha2/struct.Sha512Trunc224.html\" title=\"struct sha2::Sha512Trunc224\">Sha512Trunc224</a>","synthetic":false,"types":["sha2::sha512::Sha512Trunc224"]}];
implementors["subtle"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subtle/struct.Choice.html\" title=\"struct subtle::Choice\">Choice</a>","synthetic":false,"types":["subtle::Choice"]},{"text":"impl&lt;T:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"subtle/struct.CtOption.html\" title=\"struct subtle::CtOption\">CtOption</a>&lt;T&gt;","synthetic":false,"types":["subtle::CtOption"]}];
implementors["typenum"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/bit/struct.B0.html\" title=\"struct typenum::bit::B0\">B0</a>","synthetic":false,"types":["typenum::bit::B0"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/bit/struct.B1.html\" title=\"struct typenum::bit::B1\">B1</a>","synthetic":false,"types":["typenum::bit::B1"]},{"text":"impl&lt;U:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;","synthetic":false,"types":["typenum::int::PInt"]},{"text":"impl&lt;U:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;","synthetic":false,"types":["typenum::int::NInt"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>","synthetic":false,"types":["typenum::int::Z0"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/uint/struct.UTerm.html\" title=\"struct typenum::uint::UTerm\">UTerm</a>","synthetic":false,"types":["typenum::uint::UTerm"]},{"text":"impl&lt;U:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, B:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/uint/struct.UInt.html\" title=\"struct typenum::uint::UInt\">UInt</a>&lt;U, B&gt;","synthetic":false,"types":["typenum::uint::UInt"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>","synthetic":false,"types":["typenum::array::ATerm"]},{"text":"impl&lt;V:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>, A:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;","synthetic":false,"types":["typenum::array::TArr"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/struct.Greater.html\" title=\"struct typenum::Greater\">Greater</a>","synthetic":false,"types":["typenum::Greater"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/struct.Less.html\" title=\"struct typenum::Less\">Less</a>","synthetic":false,"types":["typenum::Less"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"typenum/struct.Equal.html\" title=\"struct typenum::Equal\">Equal</a>","synthetic":false,"types":["typenum::Equal"]}];
implementors["zeroize"] = [{"text":"impl&lt;Z:&nbsp;<a class=\"trait\" href=\"zeroize/trait.Zeroize.html\" title=\"trait zeroize::Zeroize\">Zeroize</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.54.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"zeroize/struct.Zeroizing.html\" title=\"struct zeroize::Zeroizing\">Zeroizing</a>&lt;Z&gt;","synthetic":false,"types":["zeroize::Zeroizing"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()