{
  lib,
  rustPlatform,
  pkg-config,
  libfido2,
  openssl,
  zlib,
}:

rustPlatform.buildRustPackage {
  pname = "keepass-fido2-broker";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ../broker/linux-libfido2;
    filter = path: type: baseNameOf path != "target";
  };

  cargoLock.lockFile = ../broker/linux-libfido2/Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];

  buildInputs = [
    libfido2
    openssl
    zlib
  ];

  strictDeps = true;

  meta = {
    description = "One-shot Linux FIDO2 broker for KeePassXC";
    mainProgram = "keepass-fido2-broker";
    platforms = lib.platforms.linux;
  };
}
