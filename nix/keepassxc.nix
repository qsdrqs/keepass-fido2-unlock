{
  lib,
  stdenv,
  src,
  broker,
  cmake,
  ninja,
  pkg-config,
  qt6,
  botan3,
  curl,
  keyutils,
  libargon2,
  libusb1,
  libxkbcommon,
  libx11,
  libxi,
  libxtst,
  minizip,
  pcsclite,
  qrencode,
  readline,
  zlib,
  zxcvbn-c,
}:

stdenv.mkDerivation {
  pname = "keepassxc-fido2";
  version = "2.8.0-snapshot-85c7152";

  inherit src;

  nativeBuildInputs = [
    cmake
    ninja
    pkg-config
    qt6.qttools
    qt6.wrapQtAppsHook
  ];

  buildInputs = [
    botan3
    curl
    keyutils
    libargon2
    libusb1
    libxkbcommon
    libx11
    libxi
    libxtst
    minizip
    pcsclite
    qrencode
    readline
    qt6.qtbase
    qt6.qtsvg
    qt6.qtwayland
    zlib
    zxcvbn-c
  ];

  cmakeFlags = [
    (lib.cmakeFeature "KEEPASSXC_BUILD_TYPE" "Snapshot")
    (lib.cmakeFeature "KEEPASSXC_DIST_TYPE" "Native")
    (lib.cmakeFeature "GIT_HEAD_OVERRIDE" "85c7152")
    (lib.cmakeFeature "KPXC_FIDO2_BROKER_PATH" "${broker}/bin/keepass-fido2-broker")
    (lib.cmakeBool "KPXC_FEATURE_DOCS" false)
    (lib.cmakeBool "KPXC_FEATURE_UPDATES" false)
    (lib.cmakeBool "WITH_GUI_TESTS" false)
    (lib.cmakeBool "WITH_TESTS" true)
  ];

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    export QT_QPA_PLATFORM=offscreen
    ctest --exclude-regex 'test(cli|gui)' --output-on-failure
    runHook postCheck
  '';

  meta = {
    description = "KeePassXC snapshot with FIDO2 unlock file support";
    homepage = "https://keepassxc.org";
    license = lib.licenses.gpl2Plus;
    mainProgram = "keepassxc";
    platforms = lib.platforms.linux;
  };
}
