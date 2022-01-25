# SPAKE2-Java

Implementation of SPAKE2 protocol in Java, fully compatible with BoringSSL implementation.

**DISCLAIMER:** This is an unaudited library tested with Android 11 wireless debugging. Use it at your own risk.

The ultimate goal of this project is to provide both pure java and (for android) JNI implementation of SPAKE2.
The project is fully usable as of now, but it requires further optimizations.

## Get Started
import `io.github.muntashirakon.crypto.spake2.*` in your project. Do not import any other files from 
`io.github.muntashirakon.crypto` as there's no guarantee that they will not be modified in the future.

```java
// Create alice and bob
Spake2Context alice = new Spake2Context(Spake2Role.Alice, "alice", "bob");
Spake2Context bob = new Spake2Context(Spake2Role.Bob, "bob", "alice");
// The below methods are kept for compatibility with BoringSSL
// alice.setDisablePasswordScalarHack(true);
// bob.setDisablePasswordScalarHack(true);
// Messages
byte[] aliceMsg = alice.generateMessage(alicePassword.getBytes(StandardCharsets.UTF_8));
byte[] bobMsg = bob.generateMessage(bobPassword.getBytes(StandardCharsets.UTF_8));
// Fetch keys
byte[] aliceKey = alice.processMessage(bobMsg);
byte[] bobKey = bob.processMessage(aliceMsg);
```

### Notice for BoringSSL Users
Beware that strings in C/C++ adds a `NULL` character (i.e. `\u0000`) at the end, so if you've accidentally used
`sizeof(my_name)` instead of `sizeof(my_name)-1`, you have to make sure that you're adding this character to your
Java implementation too.

## Credits

ED25519 implementation is a modified and a simplified version of the [EdDSA-Java](https://github.com/str4d/ed25519-java) library (CC0 license).

## License
Copyright 2021 Muntashir Al-Islam

Licensed under the LGPL-3.0: http://www.gnu.org/licenses/lgpl-3.0.html
