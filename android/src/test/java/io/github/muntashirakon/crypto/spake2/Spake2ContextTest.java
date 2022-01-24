/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.spake2;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.*;

public class Spake2ContextTest {
    @Test
    public void spake2() {
        for (int i = 0; i < 20; i++) {
            System.out.println("========");
            SPAKE2Run spake2 = new SPAKE2Run();
            assertTrue(spake2.run());
            assertTrue(spake2.keyMatches());
        }
    }

    @Test
    public void oldAlice() {
        for (int i = 0; i < 20; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceDisablePasswordScalarHack = true;
            assertTrue(spake2.run());
            if (!spake2.keyMatches()) {
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
            if (!spake2.keyMatches()) {
                System.out.printf("Iteration %d: Keys didn't match.\n", i);
            }
        }
    }

    @Test
    public void wrongPassword() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.bobPassword = "wrong password".getBytes(StandardCharsets.UTF_8);
        assertTrue(spake2.run());
        assertFalse(spake2.keyMatches());
    }

    @Test
    public void wrongNames() {
        SPAKE2Run spake2 = new SPAKE2Run();
        spake2.aliceNames.second = "charlie";
        spake2.bobNames.second = "charlie";
        assertTrue(spake2.run());
        assertFalse(spake2.keyMatches());
    }

    @Test
    public void corruptMessages() {
        for (int i = 0; i < 8 * Spake2Context.MAX_MSG_SIZE; i++) {
            SPAKE2Run spake2 = new SPAKE2Run();
            spake2.aliceCorruptMsgBit = i;
            assertFalse(spake2.run() && spake2.keyMatches());
        }
    }

    // Based on https://android.googlesource.com/platform/external/boringssl/+/f9e0b0e17fabac35627f18f94a8954c3857784ac/src/crypto/curve25519/spake25519_test.cc
    private static class SPAKE2Run {
        private final Pair<String, String> aliceNames = new Pair<>("adb pair client\u0000", "adb pair server\u0000");
        private final Pair<String, String> bobNames = new Pair<>("adb pair server\u0000", "adb pair client\u0000");
        private final byte[] alicePassword = Utils.hexToBytes("353932373831E63DD959651C211600F3B6561D0B9D90AF09D0A4A453EE2059A480CC7C5A94D4D48933F9FFF5FE43317D52FA7BFF8F8BC4F3488B8007330FEC7C7EDC91C20E5D");
        private byte[] bobPassword = alicePassword;
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

//            if (aliceDisablePasswordScalarHack) {
//                alice.setDisablePasswordScalarHack(true);
//            }
//            if (bobDisablePasswordScalarHack) {
//                bob.setDisablePasswordScalarHack(true);
//            }

            byte[] aliceMsg;
            byte[] bobMsg;

            try {
                aliceMsg = alice.generateMessage(alicePassword);
                bobMsg = bob.generateMessage(bobPassword);
            } catch (Exception e) {
                return false;
            }

            System.out.printf("ALICE_MSG: %s%n", Utils.bytesToHex(aliceMsg));
            System.out.printf("BOB_MSG: %s%n", Utils.bytesToHex(bobMsg));

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

            System.out.printf("ALICE_KEY: %s%n", Utils.bytesToHex(aliceKey));
            System.out.printf("BOB_KEY: %s%n", Utils.bytesToHex(bobKey));

            keyMatches = Arrays.equals(aliceKey, bobKey);

            return true;
        }

        boolean keyMatches() {
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