// swift-tools-version:5.5
import PackageDescription

// Native iOS integration. The Flutter plugin pod (ios/mobile_hardening_kit.podspec) compiles the same sources.
let package = Package(
  name: "MobileHardeningKit",
  platforms: [.iOS(.v13)],
  products: [
    .library(name: "MobileHardeningKit", targets: ["MobileHardeningKit"])
  ],
  targets: [
    .target(
      name: "MobileHardeningKit",
      path: "ios/Classes/Core",
      resources: [.copy("PrivacyInfo.xcprivacy")]
    ),
    .testTarget(
      name: "MobileHardeningKitTests",
      dependencies: ["MobileHardeningKit"],
      path: "ios/Tests/MobileHardeningKitTests"
    ),
  ]
)
