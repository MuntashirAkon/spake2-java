/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.ed25519;

import java.util.Arrays;

/**
 * Class to represent a field element of the finite field $p = 2^{255} - 19$ elements.
 * <p>
 * An element $t$, entries $t[0] \dots t[9]$, represents the integer
 * $t[0]+2^{26} t[1]+2^{51} t[2]+2^{77} t[3]+2^{102} t[4]+\dots+2^{230} t[9]$.
 * Bounds on each $t[i]$ vary depending on context.
 * <p>
 * Reviewed/commented by Bloody Rookie (nemproject@gmx.de)
 */
public class Ed25519FieldElement extends FieldElement {
    /**
     * Variable is package private for encoding.
     */
    protected final int[] t;

    /**
     * Creates a field element.
     *
     * @param f The underlying field, must be the finite field with $p = 2^{255} - 19$ elements
     * @param t The $2^{25.5}$ bit representation of the field element.
     */
    public Ed25519FieldElement(Ed25519Field f, int[] t) {
        super(f);
        if (t.length != 10)
            throw new IllegalArgumentException("Invalid radix-2^51 representation");
        this.t = t;
    }

    private static final byte[] ZERO = new byte[32];

    /**
     * Gets a value indicating whether the field element is non-zero.
     *
     * @return 1 if it is non-zero, 0 otherwise.
     */
    public boolean isNonZero() {
        final byte[] s = toByteArray();
        return Utils.equal(s, ZERO) == 0;
    }

    /**
     * $h = f + g$
     * <p>
     * TODO-CR BR: $h$ is allocated via new, probably not a good idea. Do we need the copying into temp variables if we do that?
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     * </ul>
     *
     * @param val The field element to add.
     * @return The field element this + val.
     */
    public FieldElement add(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] + g[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = f - g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * TODO-CR BR: See above.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * <li>$|g|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{26},1.1*2^{25},1.1*2^{26},1.1*2^{25},$ etc.
     * </ul>
     *
     * @param val The field element to subtract.
     * @return The field element this - val.
     **/
    public FieldElement subtract(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = t[i] - g[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = -f$
     * <p>
     * TODO-CR BR: see above.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.1*2^{25},1.1*2^{24},1.1*2^{25},1.1*2^{24},$ etc.
     * </ul>
     *
     * @return The field element (-1) * this.
     */
    public FieldElement negate() {
        int[] h = new int[10];
        for (int i = 0; i < 10; i++) {
            h[i] = - t[i];
        }
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = f * g$
     * <p>
     * Can overlap $h$ with $f$ or $g$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * <li>$|g|$ bounded by
     * $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by
     * $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * Notes on implementation strategy:
     * <p>
     * Using schoolbook multiplication. Karatsuba would save a little in some
     * cost models.
     * <p>
     * Most multiplications by 2 and 19 are 32-bit precomputations; cheaper than
     * 64-bit postcomputations.
     * <p>
     * There is one remaining multiplication by 19 in the carry chain; one *19
     * precomputation can be merged into this, but the resulting data flow is
     * considerably less clean.
     * <p>
     * There are 12 carries below. 10 of them are 2-way parallelizable and
     * vectorizable. Can get away with 11 carries, but then data flow is much
     * deeper.
     * <p>
     * With tighter constraints on inputs can squeeze carries into int32.
     *
     * @param val The field element to multiply.
     * @return The (reasonably reduced) field element this * val.
     */
    public FieldElement multiply(FieldElement val) {
        int[] g = ((Ed25519FieldElement)val).t;
        long x1;
        long x2;
        long x3;
        long x4;
        long x5;
        long x6;
        long x7;
        long x8;
        long x9;
        long x10;
        long x11;
        long x12;
        long x13;
        long x14;
        long x15;
        long x16;
        long x17;
        long x18;
        long x19;
        long x20;
        long x21;
        long x22;
        long x23;
        long x24;
        long x25;
        long x26;
        long x27;
        long x28;
        long x29;
        long x30;
        long x31;
        long x32;
        long x33;
        long x34;
        long x35;
        long x36;
        long x37;
        long x38;
        long x39;
        long x40;
        long x41;
        long x42;
        long x43;
        long x44;
        long x45;
        long x46;
        long x47;
        long x48;
        long x49;
        long x50;
        long x51;
        long x52;
        long x53;
        long x54;
        long x55;
        long x56;
        long x57;
        long x58;
        long x59;
        long x60;
        long x61;
        long x62;
        long x63;
        long x64;
        long x65;
        long x66;
        long x67;
        long x68;
        long x69;
        long x70;
        long x71;
        long x72;
        long x73;
        long x74;
        long x75;
        long x76;
        long x77;
        long x78;
        long x79;
        long x80;
        long x81;
        long x82;
        long x83;
        long x84;
        long x85;
        long x86;
        long x87;
        long x88;
        long x89;
        long x90;
        long x91;
        long x92;
        long x93;
        long x94;
        long x95;
        long x96;
        long x97;
        long x98;
        long x99;
        long x100;
        long x101;
        long x102;
        int x103;
        long x104;
        long x105;
        long x106;
        long x107;
        long x108;
        long x109;
        long x110;
        long x111;
        long x112;
        long x113;
        long x114;
        int x115;
        long x116;
        long x117;
        int x118;
        long x119;
        long x120;
        int x121;
        long x122;
        long x123;
        int x124;
        long x125;
        long x126;
        int x127;
        long x128;
        long x129;
        int x130;
        long x131;
        long x132;
        int x133;
        long x134;
        long x135;
        int x136;
        long x137;
        long x138;
        int x139;
        long x140;
        long x141;
        int x142;
        int x143;
        int x144;
        byte x145;
        int x146;
        int x147;
        x1 = ((long)(t[9]) * ((g[9]) * (byte) 0x26));
        x2 = ((long)(t[9]) * ((g[8]) * (byte) 0x13));
        x3 = ((long)(t[9]) * ((g[7]) * (byte) 0x26));
        x4 = ((long)(t[9]) * ((g[6]) * (byte) 0x13));
        x5 = ((long)(t[9]) * ((g[5]) * (byte) 0x26));
        x6 = ((long)(t[9]) * ((g[4]) * (byte) 0x13));
        x7 = ((long)(t[9]) * ((g[3]) * (byte) 0x26));
        x8 = ((long)(t[9]) * ((g[2]) * (byte) 0x13));
        x9 = ((long)(t[9]) * ((g[1]) * (byte) 0x26));
        x10 = ((long)(t[8]) * ((g[9]) * (byte) 0x13));
        x11 = ((long)(t[8]) * ((g[8]) * (byte) 0x13));
        x12 = ((long)(t[8]) * ((g[7]) * (byte) 0x13));
        x13 = ((long)(t[8]) * ((g[6]) * (byte) 0x13));
        x14 = ((long)(t[8]) * ((g[5]) * (byte) 0x13));
        x15 = ((long)(t[8]) * ((g[4]) * (byte) 0x13));
        x16 = ((long)(t[8]) * ((g[3]) * (byte) 0x13));
        x17 = ((long)(t[8]) * ((g[2]) * (byte) 0x13));
        x18 = ((long)(t[7]) * ((g[9]) * (byte) 0x26));
        x19 = ((long)(t[7]) * ((g[8]) * (byte) 0x13));
        x20 = ((long)(t[7]) * ((g[7]) * (byte) 0x26));
        x21 = ((long)(t[7]) * ((g[6]) * (byte) 0x13));
        x22 = ((long)(t[7]) * ((g[5]) * (byte) 0x26));
        x23 = ((long)(t[7]) * ((g[4]) * (byte) 0x13));
        x24 = ((long)(t[7]) * ((g[3]) * (byte) 0x26));
        x25 = ((long)(t[6]) * ((g[9]) * (byte) 0x13));
        x26 = ((long)(t[6]) * ((g[8]) * (byte) 0x13));
        x27 = ((long)(t[6]) * ((g[7]) * (byte) 0x13));
        x28 = ((long)(t[6]) * ((g[6]) * (byte) 0x13));
        x29 = ((long)(t[6]) * ((g[5]) * (byte) 0x13));
        x30 = ((long)(t[6]) * ((g[4]) * (byte) 0x13));
        x31 = ((long)(t[5]) * ((g[9]) * (byte) 0x26));
        x32 = ((long)(t[5]) * ((g[8]) * (byte) 0x13));
        x33 = ((long)(t[5]) * ((g[7]) * (byte) 0x26));
        x34 = ((long)(t[5]) * ((g[6]) * (byte) 0x13));
        x35 = ((long)(t[5]) * ((g[5]) * (byte) 0x26));
        x36 = ((long)(t[4]) * ((g[9]) * (byte) 0x13));
        x37 = ((long)(t[4]) * ((g[8]) * (byte) 0x13));
        x38 = ((long)(t[4]) * ((g[7]) * (byte) 0x13));
        x39 = ((long)(t[4]) * ((g[6]) * (byte) 0x13));
        x40 = ((long)(t[3]) * ((g[9]) * (byte) 0x26));
        x41 = ((long)(t[3]) * ((g[8]) * (byte) 0x13));
        x42 = ((long)(t[3]) * ((g[7]) * (byte) 0x26));
        x43 = ((long)(t[2]) * ((g[9]) * (byte) 0x13));
        x44 = ((long)(t[2]) * ((g[8]) * (byte) 0x13));
        x45 = ((long)(t[1]) * ((g[9]) * (byte) 0x26));
        x46 = ((long)(t[9]) * (g[0]));
        x47 = ((long)(t[8]) * (g[1]));
        x48 = ((long)(t[8]) * (g[0]));
        x49 = ((long)(t[7]) * (g[2]));
        x50 = ((long)(t[7]) * ((g[1]) * 0x2));
        x51 = ((long)(t[7]) * (g[0]));
        x52 = ((long)(t[6]) * (g[3]));
        x53 = ((long)(t[6]) * (g[2]));
        x54 = ((long)(t[6]) * (g[1]));
        x55 = ((long)(t[6]) * (g[0]));
        x56 = ((long)(t[5]) * (g[4]));
        x57 = ((long)(t[5]) * ((g[3]) * 0x2));
        x58 = ((long)(t[5]) * (g[2]));
        x59 = ((long)(t[5]) * ((g[1]) * 0x2));
        x60 = ((long)(t[5]) * (g[0]));
        x61 = ((long)(t[4]) * (g[5]));
        x62 = ((long)(t[4]) * (g[4]));
        x63 = ((long)(t[4]) * (g[3]));
        x64 = ((long)(t[4]) * (g[2]));
        x65 = ((long)(t[4]) * (g[1]));
        x66 = ((long)(t[4]) * (g[0]));
        x67 = ((long)(t[3]) * (g[6]));
        x68 = ((long)(t[3]) * ((g[5]) * 0x2));
        x69 = ((long)(t[3]) * (g[4]));
        x70 = ((long)(t[3]) * ((g[3]) * 0x2));
        x71 = ((long)(t[3]) * (g[2]));
        x72 = ((long)(t[3]) * ((g[1]) * 0x2));
        x73 = ((long)(t[3]) * (g[0]));
        x74 = ((long)(t[2]) * (g[7]));
        x75 = ((long)(t[2]) * (g[6]));
        x76 = ((long)(t[2]) * (g[5]));
        x77 = ((long)(t[2]) * (g[4]));
        x78 = ((long)(t[2]) * (g[3]));
        x79 = ((long)(t[2]) * (g[2]));
        x80 = ((long)(t[2]) * (g[1]));
        x81 = ((long)(t[2]) * (g[0]));
        x82 = ((long)(t[1]) * (g[8]));
        x83 = ((long)(t[1]) * ((g[7]) * 0x2));
        x84 = ((long)(t[1]) * (g[6]));
        x85 = ((long)(t[1]) * ((g[5]) * 0x2));
        x86 = ((long)(t[1]) * (g[4]));
        x87 = ((long)(t[1]) * ((g[3]) * 0x2));
        x88 = ((long)(t[1]) * (g[2]));
        x89 = ((long)(t[1]) * ((g[1]) * 0x2));
        x90 = ((long)(t[1]) * (g[0]));
        x91 = ((long)(t[0]) * (g[9]));
        x92 = ((long)(t[0]) * (g[8]));
        x93 = ((long)(t[0]) * (g[7]));
        x94 = ((long)(t[0]) * (g[6]));
        x95 = ((long)(t[0]) * (g[5]));
        x96 = ((long)(t[0]) * (g[4]));
        x97 = ((long)(t[0]) * (g[3]));
        x98 = ((long)(t[0]) * (g[2]));
        x99 = ((long)(t[0]) * (g[1]));
        x100 = ((long)(t[0]) * (g[0]));
        x101 = (x100 + (x45 + (x44 + (x42 + (x39 + (x35 + (x30 + (x24 + (x17 + x9)))))))));
        x102 = (x101 >> 26);
        x103 = (int)(x101 & 0x3ffffff);
        x104 = (x91 + (x82 + (x74 + (x67 + (x61 + (x56 + (x52 + (x49 + (x47 + x46)))))))));
        x105 = (x92 + (x83 + (x75 + (x68 + (x62 + (x57 + (x53 + (x50 + (x48 + x1)))))))));
        x106 = (x93 + (x84 + (x76 + (x69 + (x63 + (x58 + (x54 + (x51 + (x10 + x2)))))))));
        x107 = (x94 + (x85 + (x77 + (x70 + (x64 + (x59 + (x55 + (x18 + (x11 + x3)))))))));
        x108 = (x95 + (x86 + (x78 + (x71 + (x65 + (x60 + (x25 + (x19 + (x12 + x4)))))))));
        x109 = (x96 + (x87 + (x79 + (x72 + (x66 + (x31 + (x26 + (x20 + (x13 + x5)))))))));
        x110 = (x97 + (x88 + (x80 + (x73 + (x36 + (x32 + (x27 + (x21 + (x14 + x6)))))))));
        x111 = (x98 + (x89 + (x81 + (x40 + (x37 + (x33 + (x28 + (x22 + (x15 + x7)))))))));
        x112 = (x99 + (x90 + (x43 + (x41 + (x38 + (x34 + (x29 + (x23 + (x16 + x8)))))))));
        x113 = (x102 + x112);
        x114 = (x113 >> 25);
        x115 = (int)(x113 & 0x1ffffff);
        x116 = (x114 + x111);
        x117 = (x116 >> 26);
        x118 = (int)(x116 & 0x3ffffff);
        x119 = (x117 + x110);
        x120 = (x119 >> 25);
        x121 = (int)(x119 & 0x1ffffff);
        x122 = (x120 + x109);
        x123 = (x122 >> 26);
        x124 = (int)(x122 & 0x3ffffff);
        x125 = (x123 + x108);
        x126 = (x125 >> 25);
        x127 = (int)(x125 & 0x1ffffff);
        x128 = (x126 + x107);
        x129 = (x128 >> 26);
        x130 = (int)(x128 & 0x3ffffff);
        x131 = (x129 + x106);
        x132 = (x131 >> 25);
        x133 = (int)(x131 & 0x1ffffff);
        x134 = (x132 + x105);
        x135 = (x134 >> 26);
        x136 = (int)(x134 & 0x3ffffff);
        x137 = (x135 + x104);
        x138 = (x137 >> 25);
        x139 = (int)(x137 & 0x1ffffff);
        x140 = (x138 * (byte) 0x13);
        x141 = (x103 + x140);
        x142 = (int)(x141 >> 26);
        x143 = (int)(x141 & 0x3ffffff);
        x144 = (x142 + x115);
        x145 = (byte)(x144 >> 25);
        x146 = (x144 & 0x1ffffff);
        x147 = (x145 + x118);
        int[] out1 = new int[10];
        out1[0] = x143;
        out1[1] = x146;
        out1[2] = x147;
        out1[3] = x121;
        out1[4] = x124;
        out1[5] = x127;
        out1[6] = x130;
        out1[7] = x133;
        out1[8] = x136;
        out1[9] = x139;
        return new Ed25519FieldElement(f, out1);
    }

    /**
     * $h = f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * See {@link #multiply(FieldElement)} for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element.
     */
    public FieldElement square() {
        int f0 = t[0];
        int f1 = t[1];
        int f2 = t[2];
        int f3 = t[3];
        int f4 = t[4];
        int f5 = t[5];
        int f6 = t[6];
        int f7 = t[7];
        int f8 = t[8];
        int f9 = t[9];
        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5; /* 1.959375*2^30 */
        int f6_19 = 19 * f6; /* 1.959375*2^30 */
        int f7_38 = 38 * f7; /* 1.959375*2^30 */
        int f8_19 = 19 * f8; /* 1.959375*2^30 */
        int f9_38 = 38 * f9; /* 1.959375*2^30 */
        long f0f0    = f0   * (long) f0;
        long f0f1_2  = f0_2 * (long) f1;
        long f0f2_2  = f0_2 * (long) f2;
        long f0f3_2  = f0_2 * (long) f3;
        long f0f4_2  = f0_2 * (long) f4;
        long f0f5_2  = f0_2 * (long) f5;
        long f0f6_2  = f0_2 * (long) f6;
        long f0f7_2  = f0_2 * (long) f7;
        long f0f8_2  = f0_2 * (long) f8;
        long f0f9_2  = f0_2 * (long) f9;
        long f1f1_2  = f1_2 * (long) f1;
        long f1f2_2  = f1_2 * (long) f2;
        long f1f3_4  = f1_2 * (long) f3_2;
        long f1f4_2  = f1_2 * (long) f4;
        long f1f5_4  = f1_2 * (long) f5_2;
        long f1f6_2  = f1_2 * (long) f6;
        long f1f7_4  = f1_2 * (long) f7_2;
        long f1f8_2  = f1_2 * (long) f8;
        long f1f9_76 = f1_2 * (long) f9_38;
        long f2f2    = f2   * (long) f2;
        long f2f3_2  = f2_2 * (long) f3;
        long f2f4_2  = f2_2 * (long) f4;
        long f2f5_2  = f2_2 * (long) f5;
        long f2f6_2  = f2_2 * (long) f6;
        long f2f7_2  = f2_2 * (long) f7;
        long f2f8_38 = f2_2 * (long) f8_19;
        long f2f9_38 = f2   * (long) f9_38;
        long f3f3_2  = f3_2 * (long) f3;
        long f3f4_2  = f3_2 * (long) f4;
        long f3f5_4  = f3_2 * (long) f5_2;
        long f3f6_2  = f3_2 * (long) f6;
        long f3f7_76 = f3_2 * (long) f7_38;
        long f3f8_38 = f3_2 * (long) f8_19;
        long f3f9_76 = f3_2 * (long) f9_38;
        long f4f4    = f4   * (long) f4;
        long f4f5_2  = f4_2 * (long) f5;
        long f4f6_38 = f4_2 * (long) f6_19;
        long f4f7_38 = f4   * (long) f7_38;
        long f4f8_38 = f4_2 * (long) f8_19;
        long f4f9_38 = f4   * (long) f9_38;
        long f5f5_38 = f5   * (long) f5_38;
        long f5f6_38 = f5_2 * (long) f6_19;
        long f5f7_76 = f5_2 * (long) f7_38;
        long f5f8_38 = f5_2 * (long) f8_19;
        long f5f9_76 = f5_2 * (long) f9_38;
        long f6f6_19 = f6   * (long) f6_19;
        long f6f7_38 = f6   * (long) f7_38;
        long f6f8_38 = f6_2 * (long) f8_19;
        long f6f9_38 = f6   * (long) f9_38;
        long f7f7_38 = f7   * (long) f7_38;
        long f7f8_38 = f7_2 * (long) f8_19;
        long f7f9_76 = f7_2 * (long) f9_38;
        long f8f8_19 = f8   * (long) f8_19;
        long f8f9_38 = f8   * (long) f9_38;
        long f9f9_38 = f9   * (long) f9_38;

        /**
         * Same procedure as in multiply, but this time we have a higher symmetry leading to less summands.
         * e.g. f1f9_76 really stands for f1 * 2^26 * f9 * 2^230 + f9 * 2^230 + f1 * 2^26 congruent 2 * 2 * 19 * f1 * f9  2^0 modulo p.
         */
        long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
        long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
        long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new Ed25519FieldElement(f, h);
    }

    /**
     * $h = 2 * f * f$
     * <p>
     * Can overlap $h$ with $f$.
     * <p>
     * Preconditions:
     * </p><ul>
     * <li>$|f|$ bounded by $1.65*2^{26},1.65*2^{25},1.65*2^{26},1.65*2^{25},$ etc.
     * </ul><p>
     * Postconditions:
     * </p><ul>
     * <li>$|h|$ bounded by $1.01*2^{25},1.01*2^{24},1.01*2^{25},1.01*2^{24},$ etc.
     * </ul><p>
     * See {@link #multiply(FieldElement)} for discussion
     * of implementation strategy.
     *
     * @return The (reasonably reduced) square of this field element times 2.
     */
    public FieldElement squareAndDouble() {
        int f0 = t[0];
        int f1 = t[1];
        int f2 = t[2];
        int f3 = t[3];
        int f4 = t[4];
        int f5 = t[5];
        int f6 = t[6];
        int f7 = t[7];
        int f8 = t[8];
        int f9 = t[9];
        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5; /* 1.959375*2^30 */
        int f6_19 = 19 * f6; /* 1.959375*2^30 */
        int f7_38 = 38 * f7; /* 1.959375*2^30 */
        int f8_19 = 19 * f8; /* 1.959375*2^30 */
        int f9_38 = 38 * f9; /* 1.959375*2^30 */
        long f0f0    = f0   * (long) f0;
        long f0f1_2  = f0_2 * (long) f1;
        long f0f2_2  = f0_2 * (long) f2;
        long f0f3_2  = f0_2 * (long) f3;
        long f0f4_2  = f0_2 * (long) f4;
        long f0f5_2  = f0_2 * (long) f5;
        long f0f6_2  = f0_2 * (long) f6;
        long f0f7_2  = f0_2 * (long) f7;
        long f0f8_2  = f0_2 * (long) f8;
        long f0f9_2  = f0_2 * (long) f9;
        long f1f1_2  = f1_2 * (long) f1;
        long f1f2_2  = f1_2 * (long) f2;
        long f1f3_4  = f1_2 * (long) f3_2;
        long f1f4_2  = f1_2 * (long) f4;
        long f1f5_4  = f1_2 * (long) f5_2;
        long f1f6_2  = f1_2 * (long) f6;
        long f1f7_4  = f1_2 * (long) f7_2;
        long f1f8_2  = f1_2 * (long) f8;
        long f1f9_76 = f1_2 * (long) f9_38;
        long f2f2    = f2   * (long) f2;
        long f2f3_2  = f2_2 * (long) f3;
        long f2f4_2  = f2_2 * (long) f4;
        long f2f5_2  = f2_2 * (long) f5;
        long f2f6_2  = f2_2 * (long) f6;
        long f2f7_2  = f2_2 * (long) f7;
        long f2f8_38 = f2_2 * (long) f8_19;
        long f2f9_38 = f2   * (long) f9_38;
        long f3f3_2  = f3_2 * (long) f3;
        long f3f4_2  = f3_2 * (long) f4;
        long f3f5_4  = f3_2 * (long) f5_2;
        long f3f6_2  = f3_2 * (long) f6;
        long f3f7_76 = f3_2 * (long) f7_38;
        long f3f8_38 = f3_2 * (long) f8_19;
        long f3f9_76 = f3_2 * (long) f9_38;
        long f4f4    = f4   * (long) f4;
        long f4f5_2  = f4_2 * (long) f5;
        long f4f6_38 = f4_2 * (long) f6_19;
        long f4f7_38 = f4   * (long) f7_38;
        long f4f8_38 = f4_2 * (long) f8_19;
        long f4f9_38 = f4   * (long) f9_38;
        long f5f5_38 = f5   * (long) f5_38;
        long f5f6_38 = f5_2 * (long) f6_19;
        long f5f7_76 = f5_2 * (long) f7_38;
        long f5f8_38 = f5_2 * (long) f8_19;
        long f5f9_76 = f5_2 * (long) f9_38;
        long f6f6_19 = f6   * (long) f6_19;
        long f6f7_38 = f6   * (long) f7_38;
        long f6f8_38 = f6_2 * (long) f8_19;
        long f6f9_38 = f6   * (long) f9_38;
        long f7f7_38 = f7   * (long) f7_38;
        long f7f8_38 = f7_2 * (long) f8_19;
        long f7f9_76 = f7_2 * (long) f9_38;
        long f8f8_19 = f8   * (long) f8_19;
        long f8f9_38 = f8   * (long) f9_38;
        long f9f9_38 = f9   * (long) f9_38;
        long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
        long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
        long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;

        h0 += h0;
        h1 += h1;
        h2 += h2;
        h3 += h3;
        h4 += h4;
        h5 += h5;
        h6 += h6;
        h7 += h7;
        h8 += h8;
        h9 += h9;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

        carry1 = (h1 + (long) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
        carry5 = (h5 + (long) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

        carry2 = (h2 + (long) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
        carry6 = (h6 + (long) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

        carry3 = (h3 + (long) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
        carry7 = (h7 + (long) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

        carry4 = (h4 + (long) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
        carry8 = (h8 + (long) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

        carry9 = (h9 + (long) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

        carry0 = (h0 + (long) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

        int[] h = new int[10];
        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        return new Ed25519FieldElement(f, h);
    }

    /**
     * Invert this field element.
     * <p>
     * The inverse is found via Fermat's little theorem:<br>
     * $a^p \cong a \mod p$ and therefore $a^{(p-2)} \cong a^{-1} \mod p$
     *
     * @return The inverse of this field element.
     */
    public FieldElement invert() {
        FieldElement t0, t1, t2, t3;

        // 2 == 2 * 1
        t0 = square();

        // 4 == 2 * 2
        t1 = t0.square();

        // 8 == 2 * 4
        t1 = t1.square();

        // 9 == 8 + 1
        t1 = multiply(t1);

        // 11 == 9 + 2
        t0 = t0.multiply(t1);

        // 22 == 2 * 11
        t2 = t0.square();

        // 31 == 22 + 9
        t1 = t1.multiply(t2);

        // 2^6 - 2^1
        t2 = t1.square();

        // 2^10 - 2^5
        for (int i = 1; i < 5; ++i) {
            t2 = t2.square();
        }

        // 2^10 - 2^0
        t1 = t2.multiply(t1);

        // 2^11 - 2^1
        t2 = t1.square();

        // 2^20 - 2^10
        for (int i = 1; i < 10; ++i) {
            t2 = t2.square();
        }

        // 2^20 - 2^0
        t2 = t2.multiply(t1);

        // 2^21 - 2^1
        t3 = t2.square();

        // 2^40 - 2^20
        for (int i = 1; i < 20; ++i) {
            t3 = t3.square();
        }

        // 2^40 - 2^0
        t2 = t3.multiply(t2);

        // 2^41 - 2^1
        t2 = t2.square();

        // 2^50 - 2^10
        for (int i = 1; i < 10; ++i) {
            t2 = t2.square();
        }

        // 2^50 - 2^0
        t1 = t2.multiply(t1);

        // 2^51 - 2^1
        t2 = t1.square();

        // 2^100 - 2^50
        for (int i = 1; i < 50; ++i) {
            t2 = t2.square();
        }

        // 2^100 - 2^0
        t2 = t2.multiply(t1);

        // 2^101 - 2^1
        t3 = t2.square();

        // 2^200 - 2^100
        for (int i = 1; i < 100; ++i) {
            t3 = t3.square();
        }

        // 2^200 - 2^0
        t2 = t3.multiply(t2);

        // 2^201 - 2^1
        t2 = t2.square();

        // 2^250 - 2^50
        for (int i = 1; i < 50; ++i) {
            t2 = t2.square();
        }

        // 2^250 - 2^0
        t1 = t2.multiply(t1);

        // 2^251 - 2^1
        t1 = t1.square();

        // 2^255 - 2^5
        for (int i = 1; i < 5; ++i) {
            t1 = t1.square();
        }

        // 2^255 - 21
        return t1.multiply(t0);
    }

    /**
     * Gets this field element to the power of $(2^{252} - 3)$.
     * This is a helper function for calculating the square root.
     * <p>
     * TODO-CR BR: I think it makes sense to have a sqrt function.
     *
     * @return This field element to the power of $(2^{252} - 3)$.
     */
    public FieldElement pow22523() {
        FieldElement t0, t1, t2;

        // 2 == 2 * 1
        t0 = square();

        // 4 == 2 * 2
        t1 = t0.square();

        // 8 == 2 * 4
        t1 = t1.square();

        // z9 = z1*z8
        t1 = multiply(t1);

        // 11 == 9 + 2
        t0 = t0.multiply(t1);

        // 22 == 2 * 11
        t0 = t0.square();

        // 31 == 22 + 9
        t0 = t1.multiply(t0);

        // 2^6 - 2^1
        t1 = t0.square();

        // 2^10 - 2^5
        for (int i = 1; i < 5; ++i) {
            t1 = t1.square();
        }

        // 2^10 - 2^0
        t0 = t1.multiply(t0);

        // 2^11 - 2^1
        t1 = t0.square();

        // 2^20 - 2^10
        for (int i = 1; i < 10; ++i) {
            t1 = t1.square();
        }

        // 2^20 - 2^0
        t1 = t1.multiply(t0);

        // 2^21 - 2^1
        t2 = t1.square();

        // 2^40 - 2^20
        for (int i = 1; i < 20; ++i) {
            t2 = t2.square();
        }

        // 2^40 - 2^0
        t1 = t2.multiply(t1);

        // 2^41 - 2^1
        t1 = t1.square();

        // 2^50 - 2^10
        for (int i = 1; i < 10; ++i) {
            t1 = t1.square();
        }

        // 2^50 - 2^0
        t0 = t1.multiply(t0);

        // 2^51 - 2^1
        t1 = t0.square();

        // 2^100 - 2^50
        for (int i = 1; i < 50; ++i) {
            t1 = t1.square();
        }

        // 2^100 - 2^0
        t1 = t1.multiply(t0);

        // 2^101 - 2^1
        t2 = t1.square();

        // 2^200 - 2^100
        for (int i = 1; i < 100; ++i) {
            t2 = t2.square();
        }

        // 2^200 - 2^0
        t1 = t2.multiply(t1);

        // 2^201 - 2^1
        t1 = t1.square();

        // 2^250 - 2^50
        for (int i = 1; i < 50; ++i) {
            t1 = t1.square();
        }

        // 2^250 - 2^0
        t0 = t1.multiply(t0);

        // 2^251 - 2^1
        t0 = t0.square();

        // 2^252 - 2^2
        t0 = t0.square();

        // 2^252 - 3
        return multiply(t0);
    }

    /**
     * Constant-time conditional move. Well, actually it is a conditional copy.
     * Logic is inspired by the SUPERCOP implementation at:
     *   https://github.com/floodyberry/supercop/blob/master/crypto_sign/ed25519/ref10/fe_cmov.c
     *
     * @param val the other field element.
     * @param b must be 0 or 1, otherwise results are undefined.
     * @return a copy of this if $b == 0$, or a copy of val if $b == 1$.
     */
    @Override
    public FieldElement cmov(FieldElement val, int b) {
        Ed25519FieldElement that = (Ed25519FieldElement) val;
        b = -b;
        int[] result = new int[10];
        for (int i = 0; i < 10; i++) {
            result[i] = this.t[i];
            int x = this.t[i] ^ that.t[i];
            x &= b;
            result[i] ^= x;
        }
        return new Ed25519FieldElement(this.f, result);
    }

    @Override
    public FieldElement carry() {
        int x1;
        int x2;
        int x3;
        int x4;
        int x5;
        int x6;
        int x7;
        int x8;
        int x9;
        int x10;
        int x11;
        int x12;
        int x13;
        int x14;
        int x15;
        int x16;
        int x17;
        int x18;
        int x19;
        int x20;
        int x21;
        int x22;
        x1 = (this.t[0]);
        x2 = ((x1 >>> 26) + (this.t[1]));
        x3 = ((x2 >>> 25) + (this.t[2]));
        x4 = ((x3 >>> 26) + (this.t[3]));
        x5 = ((x4 >>> 25) + (this.t[4]));
        x6 = ((x5 >>> 26) + (this.t[5]));
        x7 = ((x6 >>> 25) + (this.t[6]));
        x8 = ((x7 >>> 26) + (this.t[7]));
        x9 = ((x8 >>> 25) + (this.t[8]));
        x10 = ((x9 >>> 26) + (this.t[9]));
        x11 = ((x1 & 0x3ffffff) + ((x10 >> 25) * (byte) 0x13));
        x12 = ((byte)(x11 >>> 26) + (x2 & 0x1ffffff));
        x13 = (x11 & 0x3ffffff);
        x14 = (x12 & 0x1ffffff);
        x15 = ((byte)(x12 >>> 25) + (x3 & 0x3ffffff));
        x16 = (x4 & 0x1ffffff);
        x17 = (x5 & 0x3ffffff);
        x18 = (x6 & 0x1ffffff);
        x19 = (x7 & 0x3ffffff);
        x20 = (x8 & 0x1ffffff);
        x21 = (x9 & 0x3ffffff);
        x22 = (x10 & 0x1ffffff);
        int[] out1 = new int[10];
        out1[0] = x13;
        out1[1] = x14;
        out1[2] = x15;
        out1[3] = x16;
        out1[4] = x17;
        out1[5] = x18;
        out1[6] = x19;
        out1[7] = x20;
        out1[8] = x21;
        out1[9] = x22;
        return new Ed25519FieldElement(this.f, out1);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(t);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Ed25519FieldElement))
            return false;
        Ed25519FieldElement fe = (Ed25519FieldElement) obj;
        return 1==Utils.equal(toByteArray(), fe.toByteArray());
    }

    @Override
    public String toString() {
//        return "[Ed25519FieldElement val="+Utils.bytesToHex(toByteArray())+"]";
        StringBuilder sb = new StringBuilder();
        for (int i : t) sb.append(i & 0xFFFF_FFFFL).append(" ");
        return sb.toString();
    }
}
