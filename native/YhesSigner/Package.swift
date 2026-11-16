// swift-tools-version: 6.0
import PackageDescription
import Foundation

let registryArchive = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent(".build/rust/release/libyhes_wire_ffi.a").path

let package = Package(
    name: "YhesSigner",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "YhesSignerCore", targets: ["YhesSignerCore"]),
        .executable(name: "YhesSigner", targets: ["YhesSigner"])
    ],
    targets: [
        .target(name: "CYhesWire", publicHeadersPath: "include",
                linkerSettings: [.unsafeFlags([registryArchive])]),
        .target(name: "YhesSignerCore", dependencies: ["CYhesWire"]),
        .executableTarget(name: "YhesSigner", dependencies: ["YhesSignerCore"]),
        .testTarget(name: "YhesSignerCoreTests", dependencies: ["YhesSignerCore"], resources: [.copy("Fixtures")])
    ]
)
