(function() {var implementors = {
"crypto_bigint":[["impl&lt;const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"crypto_bigint/modular/runtime_mod/struct.DynResidue.html\" title=\"struct crypto_bigint::modular::runtime_mod::DynResidue\">DynResidue</a>&lt;LIMBS&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Limb.html\" title=\"struct crypto_bigint::Limb\">Limb</a>&gt;"],["impl&lt;MOD: <a class=\"trait\" href=\"crypto_bigint/modular/constant_mod/trait.ResidueParams.html\" title=\"trait crypto_bigint::modular::constant_mod::ResidueParams\">ResidueParams</a>&lt;LIMBS&gt;, const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for &amp;<a class=\"struct\" href=\"crypto_bigint/modular/constant_mod/struct.Residue.html\" title=\"struct crypto_bigint::modular::constant_mod::Residue\">Residue</a>&lt;MOD, LIMBS&gt;"],["impl&lt;const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for &amp;<a class=\"struct\" href=\"crypto_bigint/modular/runtime_mod/struct.DynResidue.html\" title=\"struct crypto_bigint::modular::runtime_mod::DynResidue\">DynResidue</a>&lt;LIMBS&gt;"],["impl&lt;MOD: <a class=\"trait\" href=\"crypto_bigint/modular/constant_mod/trait.ResidueParams.html\" title=\"trait crypto_bigint::modular::constant_mod::ResidueParams\">ResidueParams</a>&lt;LIMBS&gt;, const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"crypto_bigint/modular/constant_mod/struct.Residue.html\" title=\"struct crypto_bigint::modular::constant_mod::Residue\">Residue</a>&lt;MOD, LIMBS&gt;"],["impl&lt;const LIMBS: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.76.0/core/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"crypto_bigint/struct.Wrapping.html\" title=\"struct crypto_bigint::Wrapping\">Wrapping</a>&lt;<a class=\"struct\" href=\"crypto_bigint/struct.Uint.html\" title=\"struct crypto_bigint::Uint\">Uint</a>&lt;LIMBS&gt;&gt;"]],
"elliptic_curve":[["impl&lt;C&gt; <a class=\"trait\" href=\"elliptic_curve/ops/trait.Neg.html\" title=\"trait elliptic_curve::ops::Neg\">Neg</a> for <a class=\"struct\" href=\"elliptic_curve/scalar/struct.ScalarPrimitive.html\" title=\"struct elliptic_curve::scalar::ScalarPrimitive\">ScalarPrimitive</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"elliptic_curve/ops/trait.Neg.html\" title=\"trait elliptic_curve::ops::Neg\">Neg</a> for &amp;<a class=\"struct\" href=\"elliptic_curve/scalar/struct.ScalarPrimitive.html\" title=\"struct elliptic_curve::scalar::ScalarPrimitive\">ScalarPrimitive</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.Curve.html\" title=\"trait elliptic_curve::Curve\">Curve</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"elliptic_curve/ops/trait.Neg.html\" title=\"trait elliptic_curve::ops::Neg\">Neg</a> for <a class=\"struct\" href=\"elliptic_curve/scalar/struct.NonZeroScalar.html\" title=\"struct elliptic_curve::scalar::NonZeroScalar\">NonZeroScalar</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"elliptic_curve/trait.CurveArithmetic.html\" title=\"trait elliptic_curve::CurveArithmetic\">CurveArithmetic</a>,</div>"]],
"p256":[["impl&lt;'a&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for &amp;'a <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"p256/struct.Scalar.html\" title=\"struct p256::Scalar\">Scalar</a>"]],
"primeorder":[["impl&lt;'a, C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for &amp;'a <a class=\"struct\" href=\"primeorder/struct.ProjectivePoint.html\" title=\"struct primeorder::ProjectivePoint\">ProjectivePoint</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"primeorder/trait.PrimeCurveParams.html\" title=\"trait primeorder::PrimeCurveParams\">PrimeCurveParams</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"primeorder/struct.AffinePoint.html\" title=\"struct primeorder::AffinePoint\">AffinePoint</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"primeorder/trait.PrimeCurveParams.html\" title=\"trait primeorder::PrimeCurveParams\">PrimeCurveParams</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for &amp;<a class=\"struct\" href=\"primeorder/struct.AffinePoint.html\" title=\"struct primeorder::AffinePoint\">AffinePoint</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"primeorder/trait.PrimeCurveParams.html\" title=\"trait primeorder::PrimeCurveParams\">PrimeCurveParams</a>,</div>"],["impl&lt;C&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"primeorder/struct.ProjectivePoint.html\" title=\"struct primeorder::ProjectivePoint\">ProjectivePoint</a>&lt;C&gt;<div class=\"where\">where\n    C: <a class=\"trait\" href=\"primeorder/trait.PrimeCurveParams.html\" title=\"trait primeorder::PrimeCurveParams\">PrimeCurveParams</a>,</div>"]],
"typenum":[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"typenum/int/struct.Z0.html\" title=\"struct typenum::int::Z0\">Z0</a>"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"typenum/int/struct.NInt.html\" title=\"struct typenum::int::NInt\">NInt</a>&lt;U&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"typenum/array/struct.ATerm.html\" title=\"struct typenum::array::ATerm\">ATerm</a>"],["impl&lt;U: <a class=\"trait\" href=\"typenum/marker_traits/trait.Unsigned.html\" title=\"trait typenum::marker_traits::Unsigned\">Unsigned</a> + <a class=\"trait\" href=\"typenum/marker_traits/trait.NonZero.html\" title=\"trait typenum::marker_traits::NonZero\">NonZero</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"typenum/int/struct.PInt.html\" title=\"struct typenum::int::PInt\">PInt</a>&lt;U&gt;"],["impl&lt;V, A&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a> for <a class=\"struct\" href=\"typenum/array/struct.TArr.html\" title=\"struct typenum::array::TArr\">TArr</a>&lt;V, A&gt;<div class=\"where\">where\n    V: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a>,\n    A: <a class=\"trait\" href=\"https://doc.rust-lang.org/1.76.0/core/ops/arith/trait.Neg.html\" title=\"trait core::ops::arith::Neg\">Neg</a>,</div>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()