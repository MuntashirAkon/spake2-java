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
    private final long ctx;

    private byte[] myMsg = new byte[32];
    private boolean isDestroyed;

    public Spake2Context(@NonNull Spake2Role myRole,
                         final byte[] myName,
                         final byte[] theirName) {
        ctx = allocNewContext(myRole.ordinal(), myName, theirName);
        if (ctx == 0L) {
            throw new UnsupportedOperationException("Could not allocate native context");
        }
    }

    @NonNull
    public byte[] getMyMsg() {
        return myMsg;
    }

    public byte[] generateMessage(byte[] password) throws IllegalStateException {
        if (isDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        byte[] myMsg = generateMessage(ctx, password);
        if (myMsg == null) {
            throw new IllegalStateException("Generated empty message");
        }
        System.arraycopy(myMsg, 0, this.myMsg, 0, 32);
        return myMsg;
    }

    public byte[] processMessage(byte[] theirMessage) throws IllegalStateException {
        if (isDestroyed) {
            throw new IllegalStateException("The context was destroyed.");
        }
        byte[] key = processMessage(ctx, theirMessage);
        if (key == null) {
            throw new IllegalStateException("No key was returned");
        }
        return key;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }

    @Override
    public void destroy() {
        isDestroyed = true;
        destroy(ctx);
    }

    private static native long allocNewContext(int myRole, byte[] myName, byte[] theirName);

    @Nullable
    private static native byte[] generateMessage(long ctx, byte[] password);

    @Nullable
    private static native byte[] processMessage(long ctx, byte[] theirMessage);

    private static native void destroy(long ctx);
}
