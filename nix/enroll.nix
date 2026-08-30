{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  broker,
}:

rustPlatform.buildRustPackage {
  pname = "keepass-fido2-enroll";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ../cli/enroll;
    filter = path: type: baseNameOf path != "target";
  };
  cargoLock.lockFile = ../cli/enroll/Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ openssl ];
  strictDeps = true;
  KEEPASS_FIDO2_BROKER_PATH = "${broker}/bin/keepass-fido2-broker";

  meta = {
    description = "FIDO2 unlock file enrollment CLI for KeePassXC";
    mainProgram = "keepass-fido2-enroll";
    platforms = lib.platforms.linux;
  };
}
