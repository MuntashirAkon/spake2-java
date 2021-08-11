/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.spake2;

import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import io.github.muntashirakon.crypto.ed25519.Curve;
import io.github.muntashirakon.crypto.ed25519.Ed25519;
import io.github.muntashirakon.crypto.ed25519.Ed25519CurveParameterSpec;
import io.github.muntashirakon.crypto.ed25519.Ed25519Field;
import io.github.muntashirakon.crypto.ed25519.FieldElement;
import io.github.muntashirakon.crypto.ed25519.GroupElement;
import io.github.muntashirakon.crypto.ed25519.Utils;

import static org.junit.Assert.*;

public class Spake25519Test {
    private static final byte[] B_EIGHT = Utils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");

    // Based on http://ed25519.cr.yp.to/python/ed25519.py
    private static GroupElement ed25519Edwards(GroupElement P, GroupElement Q) {
        Curve curve = P.getCurve();
        Ed25519Field field = curve.getField();
        FieldElement x1 = P.getX();
        FieldElement y1 = P.getY();
        FieldElement x2 = Q.getX();
        FieldElement y2 = Q.getY();
        FieldElement dx1x2y1y2 = curve.getD().multiply(x1).multiply(x2).multiply(y1).multiply(y2);
        FieldElement x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(dx1x2y1y2.addOne().invert());  // (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
        FieldElement y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(field.ONE.subtract(dx1x2y1y2).invert()); // (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
        return GroupElement.p3(curve, x3, y3, field.ZERO, field.ZERO);
    }

    private static GroupElement ed25519ScalarMultiply(GroupElement P, BigInteger e) {
        GroupElement Q = P.getCurve().getZero(GroupElement.Representation.P3);
        Q = ed25519Edwards(Q, Q);
        Q = ed25519Edwards(Q, P);

        int len = e.bitLength() - 2;
        for (int c = len; c >= 0; --c) {
            Q = ed25519Edwards(Q, Q);
            if (e.testBit(c)) Q = ed25519Edwards(Q, P);
        }
        return Q;
    }

    static GroupElement[] precomputeTable(String seed) {
        GroupElement[] t = new GroupElement[15];
        byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        byte[] v = Spake2Context.getHash("SHA-256", seedBytes);
        Ed25519CurveParameterSpec spec = Ed25519.getSpec();
        GroupElement P = spec.getCurve().createPoint(v, true);
        Curve curve = P.getCurve();
        for (int i = 1; i < 16; ++i) {
            // (i >>> 3 & 1) * (1 << 192)
            BigInteger t1 = BigInteger.valueOf((i >>> 3 & 1)).multiply(BigInteger.ONE.shiftLeft(192));
            // (i >>> 2 & 1) * (1 << 128)
            BigInteger t2 = BigInteger.valueOf((i >>> 2 & 1)).multiply(BigInteger.ONE.shiftLeft(128));
            // (i >>> 1 & 1) * (1 <<  64)
            BigInteger t3 = BigInteger.valueOf((i >>> 1 & 1)).multiply(BigInteger.ONE.shiftLeft(64));
            // (i & 1)
            BigInteger t4 = BigInteger.ZERO.add(BigInteger.valueOf(i & 1));
            // k is the sum of all the above
            BigInteger k = BigInteger.ZERO.add(t1).add(t2).add(t3).add(t4);

            GroupElement ge = ed25519ScalarMultiply(P, k);
            FieldElement x = ge.getX();
            FieldElement y = ge.getY();

            FieldElement ypx = y.add(x);
            FieldElement ymx = y.subtract(x);
            FieldElement xy2d = x.multiply(y).multiply(curve.get2D());

            t[i - 1] = GroupElement.precomp(curve, ypx, ymx, xy2d);
        }
        return t;
    }

    private static byte[] printPrecompTable(GroupElement[] groupElements, String name) {
        byte[] table = new byte[groupElements.length * 3 * 32];
        for (int i = 0; i < groupElements.length; ++i) {
            System.arraycopy(groupElements[i].getX().toByteArray(), 0, table, i * 96, 32);
            System.arraycopy(groupElements[i].getY().toByteArray(), 0, table, i * 96 + 32, 32);
            System.arraycopy(groupElements[i].getZ().toByteArray(), 0, table, i * 96 + 64, 32);
        }
        System.out.printf("    private static final int[] %s = new int[] {", name);
        for (int i = 0; i < table.length; ++i) {
            if (i % 15 == 0) System.out.printf("%n            ");
            System.out.printf(" 0x%02X,", table[i]);
        }
        System.out.println("\n    };");
        return table;
    }

    @Test
    public void scalarTestCmov() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(Utils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar zero = new Spake2Context.Scalar();
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 0).getBytes()));
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 1).getBytes()));
        assertEquals("0500000000000000040000000400000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 5).getBytes()));
        assertEquals("0100000010000000100000001000000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 0x11).getBytes()));
        assertEquals("2100000010000000100000001000000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 0x31).getBytes()));
        assertEquals("6100000010000000500000005000000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 0x71).getBytes()));
        assertEquals("e900000018000000d0000000d800000000000000000000000000000000000000",
                Utils.bytesToHex(scalar.cmov(zero, 0xF9).getBytes()));
    }

    @Test
    public void scalarTestCmov2() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(Utils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar base = new Spake2Context.Scalar();
        base.copy(scalar.cmov(base, 0));
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 1));
        assertEquals("0100000000000000000000000000000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 5));
        assertEquals("0500000000000000040000000400000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x11));
        assertEquals("0500000010000000140000001400000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x31));
        assertEquals("2500000010000000140000001400000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0x71));
        assertEquals("6500000010000000540000005400000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
        base.copy(scalar.cmov(base, 0xF9));
        assertEquals("ed00000018000000d4000000dc00000000000000000000000000000000000000",
                Utils.bytesToHex(base.getBytes()));
    }

    @Test
    public void scalarTestDbl() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(Utils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar eight = new Spake2Context.Scalar(B_EIGHT);
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                Utils.bytesToHex(scalar.dbl().getBytes()));
        assertEquals("1000000000000000000000000000000000000000000000000000000000000000",
                Utils.bytesToHex(eight.dbl().getBytes()));
        scalar.copy(scalar.dbl());
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                Utils.bytesToHex(scalar.getBytes()));
    }

    @Test
    public void scalarTestAdd() {
        Spake2Context.Scalar scalar = new Spake2Context.Scalar(Utils.hexToBytes(
                "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"));
        Spake2Context.Scalar eight = new Spake2Context.Scalar(B_EIGHT);
        assertEquals("f5d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
                Utils.bytesToHex(eight.add(scalar).getBytes()));
        assertEquals("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020",
                Utils.bytesToHex(scalar.add(scalar).getBytes()));
    }

    @Test
    public void checkIfGeneratedValuesAreSameForN() {
        GroupElement[] ge = precomputeTable("edwards25519 point generation seed (N)");
        assertArrayEquals(ge, Spake2Context.SPAKE_N_SMALL_PRECOMP);
    }

    @Test
    public void checkIfGeneratedValuesAreSameForM() {
        GroupElement[] ge = precomputeTable("edwards25519 point generation seed (M)");
        assertArrayEquals(ge, Spake2Context.SPAKE_M_SMALL_PRECOMP);
    }

    @Test
    public void spake2() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            assertTrue(spake2.run());
            if (!spake2.key_matches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
        }
    }

    @Test
    public void oldAlice() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceDisablePasswordScalarHack = true;
            assertTrue(spake2.run());
            if (!spake2.key_matches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
        }
    }

    @Test
    public void oldBob() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.bobDisablePasswordScalarHack = true;
            assertTrue(spake2.run());
            if (!spake2.key_matches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
        }
    }

    @Test
    public void wrongPassword() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.bobPassword = "wrong password";
        assertTrue(spake2.run());
        assertFalse(spake2.key_matches());
    }

    @Test
    public void wrongNames() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.aliceNames.second = "charlie";
        spake2.bobNames.second = "charlie";
        assertTrue(spake2.run());
        assertFalse(spake2.key_matches());
    }

    @Test
    public void corruptMessages() {
        for (int i = 0; i < 8 * Spake2Context.MAX_MSG_SIZE; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceCorruptMsgBit = i;
            assertFalse(spake2.run() && spake2.key_matches());
        }
    }

    // Based on https://android.googlesource.com/platform/external/boringssl/+/f9e0b0e17fabac35627f18f94a8954c3857784ac/src/crypto/curve25519/spake25519_test.cc
    private static class SPAKE2Run {
        private final Pair<String, String> aliceNames = new Pair<>("alice", "bob");
        private final Pair<String, String> bobNames = new Pair<>("bob", "alice");
        private final String alicePassword = "password";
        private String bobPassword = "password";
        private boolean aliceDisablePasswordScalarHack = false;
        private boolean bobDisablePasswordScalarHack = false;
        private int aliceCorruptMsgBit = -1;
        private boolean keyMatches = false;

        private boolean run() {
            Spake2Context alice = new Spake2Context(
                    Spake2Role.Alice,
                    aliceNames.first.getBytes(StandardCharsets.UTF_8),
                    aliceNames.second.getBytes(StandardCharsets.UTF_8));
            Spake2Context bob = new Spake2Context(
                    Spake2Role.Bob,
                    bobNames.first.getBytes(StandardCharsets.UTF_8),
                    bobNames.second.getBytes(StandardCharsets.UTF_8));

            if (aliceDisablePasswordScalarHack) {
                alice.setDisablePasswordScalarHack(true);
            }
            if (bobDisablePasswordScalarHack) {
                bob.setDisablePasswordScalarHack(true);
            }

            byte[] aliceMsg;
            byte[] bobMsg;

            try {
                aliceMsg = alice.generateMessage(alicePassword.getBytes(StandardCharsets.UTF_8));
                bobMsg = bob.generateMessage(bobPassword.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                return false;
            }

            if (aliceCorruptMsgBit >= 0 && aliceCorruptMsgBit < (8 * aliceMsg.length)) {
                aliceMsg[aliceCorruptMsgBit / 8] ^= 1 << (aliceCorruptMsgBit & 7);
            }

            byte[] aliceKey;
            byte[] bobKey;
            try {
                aliceKey = alice.processMessage(bobMsg);
                bobKey = bob.processMessage(aliceMsg);
            } catch (Exception e) {
                return false;
            }

            keyMatches = Arrays.equals(aliceKey, bobKey);

            return true;
        }

        boolean key_matches() {
            return keyMatches;
        }
    }

    private static class Pair<S, T> {
        private S first;
        private T second;

        public Pair(S first, T second) {
            this.first = first;
            this.second = second;
        }
    }
}