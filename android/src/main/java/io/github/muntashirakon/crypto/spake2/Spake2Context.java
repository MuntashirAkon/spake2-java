/*
 * Copyright (C) 2021 Muntashir Al-Islam
 *
 * Licensed according to the LICENSE file in this repository.
 */

package io.github.muntashirakon.crypto.spake2;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import javax.security.auth.Destroyable;

public class Spake2Context implements Destroyable {
    static {
        System.loadLibrary("spake2");
    }

    /**
     * Maximum message size in bytes
     */
    public static final int MAX_MSG_SIZE = 32;
    /**
     * Maximum key size in bytes
     */
    public static final int MAX_KEY_SIZE = 64;

    private final long mCtx;
    private final byte[] mMyMsg = new byte[MAX_MSG_SIZE];

    private boolean mDisablePasswordScalarHack;
    private boolean mIsDestroyed;

    public Spake2Context(@NonNull Spake2Role myRole,
                         final byte[] myName,
                         final byte[] theirName) {
        mCtx = allocNewContext(myRole.ordinal(), myName, theirName);
        if (mCtx == 0L) {
            throw new UnsupportedOperationException("Could not allocate native context");
        }
    }

    @NonNull
    public byte[] getMyMsg() {
        return mMyMsg;
    }

    public boolean isDisablePasswordScalarHack() {
        return mDisablePasswordScalarHack;
    }

    public void setDisablePasswordScalarHack(boolean disablePasswordScalarHack) {
        mDisablePasswordScalarHack = disablePasswordScalarHack;
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    /**
     * @param password Shared password.
     * @return A message of size {@link #MAX_MSG_SIZE}.
     * @throws IllegalStateException If the context was destroyed.
     */
    public byte[] generateMessage(byte[] password) throws IllegalStateException {
        if (mIsDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        byte[] myMsg = generateMessage(mCtx, password);
        if (myMsg == null) {
            throw new IllegalStateException("Generated empty message");
        }
        System.arraycopy(myMsg, 0, this.mMyMsg, 0, MAX_MSG_SIZE);
        return myMsg;
    }

    /**
     * @param theirMessage Message generated/received from the other end.
     * @return Key of size {@link #MAX_KEY_SIZE}.
     * @throws IllegalStateException If the context was destroyed.
     */
    public byte[] processMessage(byte[] theirMessage) throws IllegalStateException {
        if (mIsDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        byte[] key = processMessage(mCtx, theirMessage);
        if (key == null) {
            throw new IllegalStateException("No key was returned");
        }
        return key;
    }

    @Override
    public boolean isDestroyed() {
        return mIsDestroyed;
    }

    @Override
    public void destroy() {
        mIsDestroyed = true;
        destroy(mCtx);
    }

    private static native long allocNewContext(int myRole, byte[] myName, byte[] theirName);

    @Nullable
    private static native byte[] generateMessage(long ctx, byte[] password);

    @Nullable
    private static native byte[] processMessage(long ctx, byte[] theirMessage);

    private static native void destroy(long ctx);
}
