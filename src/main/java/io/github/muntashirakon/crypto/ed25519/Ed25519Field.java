/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.ed25519;

import java.io.Serializable;

/**
 * An Ed25519 finite field. Includes several pre-computed values.
 */
public class Ed25519Field implements Serializable {
    private static final long serialVersionUID = 8746587465875676L;

    private static final byte[] B_ZERO = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] B_ONE = Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] B_TWO = Utils.hexToBytes("0200000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] B_FOUR = Utils.hexToBytes("0400000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] B_FIVE = Utils.hexToBytes("0500000000000000000000000000000000000000000000000000000000000000");
    private static final byte[] B_EIGHT = Utils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");

    public final FieldElement ZERO;
    public final FieldElement ONE;
    public final FieldElement TWO;
    public final FieldElement FOUR;
    public final FieldElement FIVE;
    public final FieldElement EIGHT;

    private final int b;
    private final FieldElement q;
    /**
     * q-2
     */
    private final FieldElement qm2;
    /**
     * (q-5) / 8
     */
    private final FieldElement qm5d8;
    private final Ed25519LittleEndianEncoding enc;

    public Ed25519Field(int b, byte[] q, Ed25519LittleEndianEncoding enc) {
        this.b = b;
        this.enc = enc;
        this.enc.setField(this);

        this.q = fromByteArray(q);

        // Set up constants
        ZERO = fromByteArray(B_ZERO);
        ONE = fromByteArray(B_ONE);
        TWO = fromByteArray(B_TWO);
        FOUR = fromByteArray(B_FOUR);
        FIVE = fromByteArray(B_FIVE);
        EIGHT = fromByteArray(B_EIGHT);

        // Precompute values
        qm2 = this.q.subtract(TWO);
        qm5d8 = this.q.subtract(FIVE).divide(EIGHT);
    }

    public FieldElement fromByteArray(byte[] x) {
        return enc.decode(x);
    }

    public int getb() {
        return b;
    }

    public FieldElement getQ() {
        return q;
    }

    public FieldElement getQm2() {
        return qm2;
    }

    public FieldElement getQm5d8() {
        return qm5d8;
    }

    public Ed25519LittleEndianEncoding getEncoding(){
        return enc;
    }

    @Override
    public int hashCode() {
        return q.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Ed25519Field))
            return false;
        Ed25519Field f = (Ed25519Field) obj;
        return b == f.b && q.equals(f.q);
    }
}
