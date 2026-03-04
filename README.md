# Yours

Encrypted P2P messaging over LoRa mesh. No servers, no internet, no metadata.

## [Demo](https://x.com/stcisgood/status/2028926459159437436)

## Stack

- **App**: Android (Kotlin)
- **Crypto**: Rust via JNI (`bedrock-core`)
- **Transport**: LoRa mesh via [LunarCore](https://github.com/STCisGOOD/lunarcore) firmware

## Features

- Double Ratchet sessions (forward secrecy + post-compromise recovery)
- Onion routing over mesh (3+ hops)
- Garlic bundling (multiple messages per packet)
- Poisson-distributed cover traffic
- Steganographic storage
- Verifiable secret sharing for identity recovery
- BBS+ anonymous credentials
- Ring signatures for anonymous mesh identity

## Hardware

[Heltec WiFi LoRa 32 V3](https://heltec.org/project/wifi-lora-32-v3/) (ESP32-S3 + SX1262) running LunarCore firmware.

## Build

### Rust (native library)

```
cargo install cargo-ndk
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs build --release
```

### Android

Open in Android Studio and build, or:

```
./gradlew assembleDebug
```

## License

MIT
