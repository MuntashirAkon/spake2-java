/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.ed25519;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Parameter specification for Ed25519 curve.
 */
public class Ed25519CurveParameterSpec implements AlgorithmParameterSpec, Serializable {
    public static final String ED_25519 = "Ed25519";

    private static final long serialVersionUID = 8274987108472012L;

    private final Curve curve;
    private final String hashAlgo;
    private final Ed25519ScalarOps sc;
    private final GroupElement B;

    /**
     * @param curve    the curve
     * @param hashAlgo the JCA string for the hash algorithm
     * @param sc       the parameter L represented as Ed25519ScalarOps
     * @param B        the parameter B
     * @throws IllegalArgumentException if hash algorithm is unsupported or length is wrong
     */
    public Ed25519CurveParameterSpec(Curve curve, String hashAlgo, Ed25519ScalarOps sc, GroupElement B) {
        try {
            MessageDigest hash = MessageDigest.getInstance(hashAlgo);
            // EdDSA hash function must produce 2b-bit output
            if (curve.getField().getb() / 4 != hash.getDigestLength())
                throw new IllegalArgumentException("Hash output is not 2b-bit");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm");
        }

        this.curve = curve;
        this.hashAlgo = hashAlgo;
        this.sc = sc;
        this.B = B;
    }

    public String getName() {
        return ED_25519;
    }

    public Curve getCurve() {
        return curve;
    }

    public String getHashAlgorithm() {
        return hashAlgo;
    }

    public Ed25519ScalarOps getScalarOps() {
        return sc;
    }

    /**
     * @return the base (generator)
     */
    public GroupElement getB() {
        return B;
    }

    @Override
    public int hashCode() {
        return hashAlgo.hashCode() ^ curve.hashCode() ^ B.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Ed25519CurveParameterSpec))
            return false;
        Ed25519CurveParameterSpec s = (Ed25519CurveParameterSpec) o;
        return hashAlgo.equals(s.getHashAlgorithm()) &&
                curve.equals(s.getCurve()) &&
                B.equals(s.getB());
    }
}
