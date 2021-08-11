/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.spake2;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.security.auth.Destroyable;

import io.github.muntashirakon.crypto.ed25519.Curve;
import io.github.muntashirakon.crypto.ed25519.Ed25519;
import io.github.muntashirakon.crypto.ed25519.Ed25519CurveParameterSpec;
import io.github.muntashirakon.crypto.ed25519.Ed25519Field;
import io.github.muntashirakon.crypto.ed25519.Ed25519ScalarOps;
import io.github.muntashirakon.crypto.ed25519.FieldElement;
import io.github.muntashirakon.crypto.ed25519.GroupElement;
import io.github.muntashirakon.crypto.ed25519.Utils;

@SuppressWarnings("unused")
public class Spake2Context implements Destroyable {
    /**
     * Maximum message size in bytes
     */
    public static final int MAX_MSG_SIZE = 32;
    /**
     * Maximum key size in bytes
     */
    public static final int MAX_KEY_SIZE = 64;

    private static final byte[][] helperTable = new byte[][]{
            Utils.hexToBytes("0100000000000000000000000000000000000000000000000000000000000000"),
            Utils.hexToBytes("0000000000000000010000000000000000000000000000000000000000000000"),
            Utils.hexToBytes("0100000000000000010000000000000000000000000000000000000000000000"),
            Utils.hexToBytes("0000000000000000000000000000000001000000000000000000000000000000"),
            Utils.hexToBytes("0100000000000000000000000000000001000000000000000000000000000000"),
            Utils.hexToBytes("0000000000000000010000000000000001000000000000000000000000000000"),
            Utils.hexToBytes("0100000000000000010000000000000001000000000000000000000000000000"),
            Utils.hexToBytes("0000000000000000000000000000000000000000000000000100000000000000"),
            Utils.hexToBytes("0100000000000000000000000000000000000000000000000100000000000000"),
            Utils.hexToBytes("0000000000000000010000000000000000000000000000000100000000000000"),
            Utils.hexToBytes("0100000000000000010000000000000000000000000000000100000000000000"),
            Utils.hexToBytes("0000000000000000000000000000000001000000000000000100000000000000"),
            Utils.hexToBytes("0100000000000000000000000000000001000000000000000100000000000000"),
            Utils.hexToBytes("0000000000000000010000000000000001000000000000000100000000000000"),
            Utils.hexToBytes("0100000000000000010000000000000001000000000000000100000000000000"),
    };

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

    private static GroupElement[] precomputeTable(String seed) {
        // TODO: 10/8/21 Hardcode this table to save the amount of time
        GroupElement[] t = new GroupElement[15];
        byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        byte[] v = getHash("SHA-256", seedBytes);
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

    // https://datatracker.ietf.org/doc/html/draft-ietf-kitten-krb-spake-preauth-01#appendix-B
    private static final String SEED_N = "edwards25519 point generation seed (N)";
    private static final String SEED_M = "edwards25519 point generation seed (M)";

    private static final GroupElement[] SPAKE_N_SMALL_PRECOMP;
    private static final GroupElement[] SPAKE_M_SMALL_PRECOMP;

    static {
        SPAKE_N_SMALL_PRECOMP = precomputeTable(SEED_N);
        SPAKE_M_SMALL_PRECOMP = precomputeTable(SEED_M);
    }

    private final byte[] myName;
    private final byte[] theirName;
    private final Spake2Role myRole;
    private final byte[] privateKey = new byte[32];
    private final byte[] myMsg = new byte[32];
    private final byte[] passwordScalar = new byte[32];
    private final byte[] passwordHash = new byte[64];
    private final Ed25519CurveParameterSpec curveSpec;

    private State state;
    private boolean disablePasswordScalarHack;
    private boolean isDestroyed = false;

    public Spake2Context(Spake2Role myRole,
                         final byte[] myName,
                         final byte[] theirName) {
        this.myRole = myRole;
        this.myName = new byte[myName.length];
        this.theirName = new byte[theirName.length];
        this.state = State.Init;

        System.arraycopy(myName, 0, this.myName, 0, myName.length);
        System.arraycopy(theirName, 0, this.theirName, 0, theirName.length);

        curveSpec = Ed25519.getSpec();
    }

    public void setDisablePasswordScalarHack(boolean disablePasswordScalarHack) {
        this.disablePasswordScalarHack = disablePasswordScalarHack;
    }

    public boolean isDisablePasswordScalarHack() {
        return disablePasswordScalarHack;
    }

    public Spake2Role getMyRole() {
        return myRole;
    }

    public byte[] getMyMsg() {
        return myMsg;
    }

    public byte[] getMyName() {
        return myName;
    }

    public byte[] getTheirName() {
        return theirName;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }

    @Override
    public void destroy() {
        isDestroyed = true;
        Arrays.fill(privateKey, (byte) 0);
        Arrays.fill(myMsg, (byte) 0);
        Arrays.fill(passwordScalar, (byte) 0);
        Arrays.fill(passwordHash, (byte) 0);
    }

    /**
     * @return A message of size {@link #MAX_MSG_SIZE}.
     * @param password Shared password.
     * @throws IllegalArgumentException If SHA-512 is unavailable for some reason.
     * @throws IllegalStateException    If the message has already been generated.
     */
    public byte[] generateMessage(final byte[] password) throws IllegalArgumentException, IllegalStateException {
        if (isDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        if (this.state != State.Init) {
            throw new IllegalStateException("Invalid state: " + this.state);
        }

        Ed25519ScalarOps scalarOps = curveSpec.getScalarOps();

        byte[] privateKey = new byte[64];
        new SecureRandom().nextBytes(privateKey);
        System.arraycopy(scalarOps.reduce(privateKey), 0, privateKey, 0, 32);
        // Multiply by the cofactor (eight) so that we'll clear it when operating on
        // the peer's point later in the protocol.
        leftShift3(privateKey);
        System.arraycopy(privateKey, 0, this.privateKey, 0, this.privateKey.length);

        final GroupElement P = curveSpec.getB().scalarMultiply(this.privateKey);

        byte[] passwordTmp = getHash("SHA-512", password);  // 64 byte
        System.arraycopy(passwordTmp, 0, this.passwordHash, 0, this.passwordHash.length);

        /**
         * Due to a copy-paste error, the call to {@link #leftShift3(byte[])} was omitted after reducing it, just above.
         * This meant that {@link #passwordScalar} was not a multiple of eight to clear the cofactor and thus three bits
         * of the password hash would leak. In order to fix this in a unilateral way, points of small order are added to
         * the mask point such as that it is in the prime-order subgroup. Since the ephemeral scalar is a multiple of
         * eight, these points will cancel out when calculating the shared secret.
         *
         * Adding points of small order is the same as adding multiples of the prime order to the password scalar. Since
         * that's faster, this what is done below. {@link #l} is a large prime, thus, odd, thus the LSB is one. So,
         * adding it will flip the LSB. Adding twice, it will flip the next bit, and so on for all the bottom three bits.
         */
        Scalar passwordScalar = new Scalar(scalarOps.reduce(passwordTmp));

        /**
         * passwordScalar is the result of scalar reducing and thus is, at most, $l-1$. In the following, we may add
         * $l+2×l+4×l$ for a max value of $8×l-1$. That is less than $2^256$ as required.
         */

        if (!this.disablePasswordScalarHack) {
            Scalar order = new Scalar(l);
            Scalar tmp = new Scalar();
            tmp.copy(order.cmov(tmp, isEqual(passwordScalar.getByte(0) & 1, 1)));
            passwordScalar.copy(passwordScalar.add(tmp));
            order.copy(order.dbl());

            tmp.reset();
            tmp.copy(order.cmov(tmp, isEqual(passwordScalar.getByte(0) & 2, 2)));
            passwordScalar.copy(passwordScalar.add(tmp));
            order.copy(order.dbl());

            tmp.reset();
            tmp.copy(order.cmov(tmp, isEqual(passwordScalar.getByte(0) & 4, 4)));
            passwordScalar.copy(passwordScalar.add(tmp));

            assert ((passwordScalar.getByte(0) & 7) == 0);
        }

        System.arraycopy(passwordScalar.getBytes(), 0, this.passwordScalar, 0, this.passwordScalar.length);

        // mask = h(password) * <N or M>.
        GroupElement mask = geScalaMultiplySmallPrecomp(curveSpec.getCurve(), this.passwordScalar,
                this.myRole == Spake2Role.Alice ? SPAKE_M_SMALL_PRECOMP : SPAKE_N_SMALL_PRECOMP);

        // P* = P + mask.
        GroupElement PStar = P.add(mask.toCached()).toP2();

        System.arraycopy(PStar.toByteArray(), 0, this.myMsg, 0, this.myMsg.length);
        this.state = State.MsgGenerated;
        return this.myMsg.clone();
    }

    /**
     * @return Key of size {@link #MAX_KEY_SIZE}.
     * @param theirMsg Message generated/received from the other end.
     * @throws IllegalArgumentException If the message is invalid or SHA-512 is unavailable for some reason.
     * @throws IllegalStateException    If the key has already been generated.
     */
    public byte[] processMessage(final byte[] theirMsg) throws IllegalArgumentException, IllegalStateException {
        if (isDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        if (this.state != State.MsgGenerated) {
            throw new IllegalStateException("Invalid state: " + this.state);
        }
        if (theirMsg.length != 32) {
            throw new IllegalArgumentException("Peer's message is not 32 bytes");
        }

        GroupElement QStar = curveSpec.getCurve().fromBytesNegateVarTime(theirMsg);
        if (QStar == null) {
            throw new IllegalArgumentException("Point received from peer was not on the curve.");
        }

        // Unmask peer's value.
        GroupElement peersMask = geScalaMultiplySmallPrecomp(curveSpec.getCurve(), this.passwordScalar,
                this.myRole == Spake2Role.Alice ? SPAKE_N_SMALL_PRECOMP : SPAKE_M_SMALL_PRECOMP);

        GroupElement QExt = QStar.sub(peersMask.toCached()).toP3();
        // FIXME: Create a single precomp converter or fix generating single precompute
        GroupElement QPrecomp = new GroupElement(QExt.getCurve(), GroupElement.Representation.P3, QExt.getX(),
                QExt.getY(), QExt.getZ(), QExt.getT(), true, true);

        byte[] dhShared = QPrecomp.scalarMultiply(this.privateKey).toByteArray();

        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("SHA-512 algorithm is not supported.");
        }
        if (this.myRole == Spake2Role.Alice) {
            updateWithLengthPrefix(sha, this.myName, this.myName.length);
            updateWithLengthPrefix(sha, this.theirName, this.theirName.length);
            updateWithLengthPrefix(sha, this.myMsg, this.myMsg.length);
            updateWithLengthPrefix(sha, theirMsg, 32);
        } else { // Bob
            updateWithLengthPrefix(sha, this.theirName, this.theirName.length);
            updateWithLengthPrefix(sha, this.myName, this.myName.length);
            updateWithLengthPrefix(sha, theirMsg, 32);
            updateWithLengthPrefix(sha, this.myMsg, this.myMsg.length);
        }
        updateWithLengthPrefix(sha, dhShared, dhShared.length);
        updateWithLengthPrefix(sha, this.passwordHash, this.passwordHash.length);

        byte[] key = sha.digest();
        this.state = State.KeyGenerated;

        return key.clone();
    }

    /**
     * Multiplies n with 8 by shifting it 3 times to the left
     *
     * @param n 32 bytes value
     */
    private static void leftShift3(byte[] n) {
        int carry = 0;
        for (int i = 0; i < 32; i++) {
            int next_carry = (byte) ((n[i] & 0xFF) >>> 5);
            n[i] = (byte) ((n[i] << 3) | carry);
            carry = next_carry;
        }
    }

    /**
     * l = 2^252 + 27742317777372353535851937790883648493
     */
    private static final byte[] l = Utils.hexToBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");


    private static void updateWithLengthPrefix(MessageDigest sha, final byte[] data, int len) {
        byte[] len_le = new byte[8];
        long l = len;
        int i;

        for (i = 0; i < 8; i++) {
            len_le[i] = (byte) (l & 0xFF);
            l = (l >>> 8) & 0xFFFF_FFFFL;
        }

        sha.update(len_le);
        sha.update(data);
    }

    // TODO: 10/8/21 Replace this with a generalised scalar multiply method
    private GroupElement geScalaMultiplySmallPrecomp(Curve curve,
                                                     final byte[] a /* 32 bytes */,
                                                     final GroupElement[] precompTable) {
        GroupElement h = curve.getZero(GroupElement.Representation.P3);
        // This loop does 64 additions and 64 doublings to calculate the result.
        for (long i = 63; i >= 0; i--) {
            int index = 0;

            for (long j = 0; j < 4; j++) {
                byte bit = (byte) (1 & (a[(int) ((8 * j) + (i >>> 3))] >>> (i & 7)));
                index |= (bit << j);
            }

            GroupElement e = curve.getZero(GroupElement.Representation.PRECOMP);
            for (int j = 1; j < 16; j++) {
                e = e.cmov(precompTable[j - 1], Utils.equal(index, j));
            }

            h = h.add(h.toCached()).toP3().madd(e).toP3();
        }
        return h;
    }

    private static byte[] getHash(String algo, byte[] bytes) throws IllegalArgumentException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Invalid hashing algorithm " + algo);
        }
        md.reset();
        return md.digest(bytes);
    }

    /**
     * @param a 32 bit value
     * @param b 32 bit value
     * @return 0xff...f if a == b and 0x0 otherwise.
     */
    private static long isEqual(long a, long b) {
        return isZero(a ^ b);
    }

    /**
     * @param a 32 bit value
     * @return 0xff...f if a == 0 and 0x0 otherwise.
     */
    private static long isZero(long a) {
        return copyMsbToEveryBit(~a & (a - 1));
    }

    /**
     * @param a 32 bit value
     * @return The given value with the MSB copied to all the other bits.
     */
    private static long copyMsbToEveryBit(long a) {
        // 2's complement of MSB
        return -(a >>> 63);
    }

    private enum State {
        Init,
        MsgGenerated,
        KeyGenerated,
    }

    static class Scalar {
        private final byte[] bytes;

        public Scalar(byte[] bytes) {
            this.bytes = new byte[32];
            System.arraycopy(bytes, 0, this.bytes, 0, 32);
        }

        public Scalar() {
            this.bytes = new byte[32];
        }

        public byte getByte(int idx) {
            return bytes[idx];
        }

        public byte[] getBytes() {
            return bytes;
        }

        public void reset() {
            Arrays.fill(this.bytes, (byte) 0);
        }

        /**
         * Copy bytes from the given scalar
         */
        public void copy(Scalar scalar) {
            System.arraycopy(scalar.bytes, 0, this.bytes, 0, 32);
        }

        /**
         * @return A new scalar with bits copied from this if the mask is all ones.
         */
        public Scalar cmov(Scalar src, long mask) {
            byte[] m = new byte[4];
            m[0] = (byte) mask;
            m[1] = (byte) (mask >>> 8);
            m[2] = (byte) (mask >>> 16);
            m[3] = (byte) (mask >>> 24);
            byte[] bytes = new byte[32];
            for (int i = 0; i < 8; ++i) {
                int idx = i * 4;
                for (int j = 0; j < 4; ++j) {
                    bytes[idx + j] = (byte) (m[j] & this.bytes[idx + j] | (~m[j] & src.bytes[idx + j]));
                }
            }
            return new Scalar(bytes);
        }

        /**
         * @return 2 * this
         */
        Scalar dbl() {
            byte[] bytes = new byte[32];
            int carry = 0;
            for (int i = 0; i < 32; ++i) {
                int carry_out = (this.bytes[i] & 0xFF) >>> 7;
                bytes[i] = (byte) ((this.bytes[i] << 1) | carry);
                carry = carry_out;
            }
            return new Scalar(bytes);
        }

        /**
         * @return src + this
         */
        Scalar add(Scalar src) {
            byte[] bytes = new byte[32];
            int carry = 0;
            for (int i = 0; i < 32; ++i) {
                int tmp = (src.bytes[i] & 0xFF) + (this.bytes[i] & 0xFF) + carry;
                bytes[i] = (byte) tmp;
                carry = tmp >>> 8;
            }
            return new Scalar(bytes);
        }
    }
}
