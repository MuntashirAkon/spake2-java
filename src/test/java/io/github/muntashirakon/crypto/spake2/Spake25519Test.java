/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.spake2;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import io.github.muntashirakon.crypto.ed25519.Utils;

import static org.junit.Assert.*;

public class Spake25519Test {
    private static final byte[] B_EIGHT = Utils.hexToBytes("0800000000000000000000000000000000000000000000000000000000000000");

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