#include<cstdio>
#include<cstdlib>
#include<jni.h>

#include "spake25519.c"

#include "io_github_muntashirakon_crypto_spake2_Spake2Context.h"

#ifndef nullptr
#define nullptr NULL
#endif

static jlong Spake2Context_AllocNewContext(JNIEnv *env, jclass clazz, jint myRole, jbyteArray myName, jbyteArray theirName) {
    spake2_role_t my_role = myRole == 0 ? spake2_role_alice : spake2_role_bob;
    auto my_len = env->GetArrayLength(myName);
    auto my_name = env->GetByteArrayElements(myName, nullptr);
    auto their_len = env->GetArrayLength(theirName);
    auto their_name = env->GetByteArrayElements(theirName, nullptr);

    struct spake2_ctx_st *ctx = SPAKE2_CTX_new(my_role, (uint8_t *) my_name, my_len, (uint8_t *) their_name, their_len);
    env->ReleaseByteArrayElements(myName, my_name, 0);
    env->ReleaseByteArrayElements(theirName, their_name, 0);
    if (ctx == nullptr) {
        printf("Couldn't create SPAKE2 context");
        return 0;
    }
    return (jlong) ctx;
}

static jbyteArray Spake2Context_GenerateMessage(JNIEnv *env, jclass clazz, jlong ctxPtr, jbyteArray password) {
    struct spake2_ctx_st *ctx = (struct spake2_ctx_st *) ctxPtr;
    auto pswd_size = env->GetArrayLength(password);
    auto pswd = env->GetByteArrayElements(password, nullptr);
    size_t msg_size = 0;
    uint8_t msg[SPAKE2_MAX_MSG_SIZE];
    int status = SPAKE2_generate_msg(ctx, msg, &msg_size, SPAKE2_MAX_MSG_SIZE, (uint8_t *) pswd, pswd_size);
    env->ReleaseByteArrayElements(password, pswd, 0);
    if (status != 1 || msg_size == 0) {
        printf("Couldn't generate message");
        SPAKE2_CTX_free(ctx);
        return nullptr;
    }
    jbyteArray outMsg = env->NewByteArray(msg_size);
    env->SetByteArrayRegion(outMsg, 0, msg_size, (jbyte *) msg);
    return outMsg;
}

static jbyteArray Spake2Context_ProcessMessage(JNIEnv *env, jclass clazz, jlong ctxPtr, jbyteArray theirMessage) {
    struct spake2_ctx_st *ctx = (struct spake2_ctx_st *) ctxPtr;
    auto their_msg_len = env->GetArrayLength(theirMessage);
    auto their_msg = env->GetByteArrayElements(theirMessage, nullptr);
    size_t key_material_len = 0;
    uint8_t key_material[SPAKE2_MAX_KEY_SIZE];
    int status = SPAKE2_process_msg(ctx, key_material, &key_material_len, SPAKE2_MAX_KEY_SIZE, (uint8_t *) their_msg, their_msg_len);
    env->ReleaseByteArrayElements(theirMessage, their_msg, 0);
    if (status != 1 || key_material_len == 0) {
        printf("Couldn't generate key");
        SPAKE2_CTX_free(ctx);
        return nullptr;
    }
    jbyteArray outKey = env->NewByteArray(key_material_len);
    env->SetByteArrayRegion(outKey, 0, key_material_len, (jbyte *) key_material);
    return outKey;
}

static void Spake2Context_Destroy(JNIEnv *env, jclass clazz, jlong ctxPtr) {
    struct spake2_ctx_st *ctx = (struct spake2_ctx_st *) ctxPtr;
    SPAKE2_CTX_free(ctx);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = nullptr;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK)
        return -1;

    JNINativeMethod methods_Spake2Context[] = {
            {"allocNewContext", "(I[B[B)J", (void *) Spake2Context_AllocNewContext},
            {"generateMessage", "(J[B)[B",  (void *) Spake2Context_GenerateMessage},
            {"processMessage",  "(J[B)[B",  (void *) Spake2Context_ProcessMessage},
            {"destroy",         "(J)V",     (void *) Spake2Context_Destroy},
    };

    env->RegisterNatives(env->FindClass("io/github/muntashirakon/crypto/spake2/Spake2Context"), methods_Spake2Context,
                         sizeof(methods_Spake2Context) / sizeof(JNINativeMethod));

    return JNI_VERSION_1_6;
}
