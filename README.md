# Windows API sample with Rust

## build

```shell
rustup target add x86_64-pc-windows-gnu
brew install mingw-w64
cargo build --target x86_64-pc-windows-gnu --release
```