/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.ed25519;

public class Ed25519 {
    private static final Ed25519Field ed25519field = new Ed25519Field(
                    256, // b
                    Utils.hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
                    new Ed25519LittleEndianEncoding());

    private static final Curve ed25519curve = new Curve(ed25519field,
            Utils.hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
            ed25519field.fromByteArray(Utils.hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))); // I

    // RFC 8032
    private static final Ed25519CurveParameterSpec ED_25519_CURVE_SPEC = new Ed25519CurveParameterSpec(
            ed25519curve,
            "SHA-512", // H
            new Ed25519ScalarOps(), // l
            ed25519curve.createPoint( // B
                    Utils.hexToBytes("5866666666666666666666666666666666666666666666666666666666666666"),
                    true)); // Precompute tables for B

    public static Ed25519CurveParameterSpec getSpec() {
        return ED_25519_CURVE_SPEC;
    }
}
