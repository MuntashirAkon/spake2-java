/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.ed25519;

import java.io.Serializable;

/**
 * A twisted Edwards curve.
 * Points on the curve satisfy $-x^2 + y^2 = 1 + d x^2y^2$
 */
public class Curve implements Serializable {
    private static final long serialVersionUID = 4578920872509827L;
    private final Ed25519Field f;
    private final FieldElement d;
    private final FieldElement d2;
    private final FieldElement I;

    private final GroupElement zeroP2;
    private final GroupElement zeroP3;
    private final GroupElement zeroP3PrecomputedDouble;
    private final GroupElement zeroPrecomp;

    public Curve(Ed25519Field f, byte[] d, FieldElement I) {
        this.f = f;
        this.d = f.fromByteArray(d);
        this.d2 = this.d.add(this.d);
        this.I = I;

        FieldElement zero = f.ZERO;
        FieldElement one = f.ONE;
        zeroP2 = GroupElement.p2(this, zero, one, one);
        zeroP3 = GroupElement.p3(this, zero, one, one, zero, false);
        zeroP3PrecomputedDouble = GroupElement.p3(this, zero, one, one, zero, true);
        zeroPrecomp = GroupElement.precomp(this, one, one, zero);
    }

    public Ed25519Field getField() {
        return f;
    }

    public FieldElement getD() {
        return d;
    }

    public FieldElement get2D() {
        return d2;
    }

    public FieldElement getI() {
        return I;
    }

    public GroupElement getZero(GroupElement.Representation repr) {
        switch (repr) {
        case P2:
            return zeroP2;
        case P3:
            return zeroP3;
        case P3PrecomputedDouble:
            return zeroP3PrecomputedDouble;
        case PRECOMP:
            return zeroPrecomp;
        default:
            return null;
        }
    }

    public GroupElement createPoint(byte[] P, boolean precompute) {
        return new GroupElement(this, P, precompute);
    }

    public GroupElement fromBytesNegateVarTime(final byte[] s) {
        FieldElement Y = f.fromByteArray(s);
        FieldElement Z = f.ONE;
        FieldElement y2 = Y.square();
        FieldElement dy2 = y2.multiply(d);
        FieldElement u = y2.subtract(Z); // u = y^2-1
        FieldElement v = dy2.add(Z); // v = dy^2+1

        FieldElement v3 = v.square().multiply(v); // v3 = v^3
        FieldElement uv7 = v3.square().multiply(v).multiply(u);  // x = uv^7

        FieldElement X = uv7.pow22523(); // x = (uv^7)^((q-5)/8)
        X = X.multiply(v3).multiply(u); // x = uv^3(uv^7)^((q-5)/8)

        FieldElement vx2 = X.square().multiply(v); // vx^2
        FieldElement check = vx2.subtract(u); // vx^2 - u
        if (check.isNonZero()) {
            check = vx2.add(u);  // vx^2 + u
            if (check.isNonZero()) {
                return null;
            }
            X = X.multiply(I);  // x = iuv^3(uv^7)^((q-5)/8)
        }

        int isNegative = X.isNegative() ? 1 : 0;
        if (isNegative != (s[31] >>> 7)) {
            X = X.negate(); // x = -iuv^3(uv^7)^((q-5)/8)
        }

        FieldElement T = X.multiply(Y);  // t = [-]yiuv^3(uv^7)^((q-5)/8)
        return GroupElement.p3(this, X, Y, Z, T);
    }

    @Override
    public int hashCode() {
        return f.hashCode() ^ d.hashCode() ^ I.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve))
            return false;
        Curve c = (Curve) o;
        return f.equals(c.getField()) &&
               d.equals(c.getD()) &&
               I.equals(c.getI());
    }
}
