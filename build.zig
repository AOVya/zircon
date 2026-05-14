const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zircon_mod = b.addModule("zircon", .{
        .root_source_file = b.path("src/zircon.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tls_dep = b.dependency("tls", .{
        .target = target,
        .optimize = optimize,
    });

    zircon_mod.addImport("tls", tls_dep.module("tls"));

    const docs_step = b.step("docs", "Build the zircon docs");

    const docs_obj = b.addObject(.{
        .name = "zircon",
        .root_module = zircon_mod,
    });

    const docs = docs_obj.getEmittedDocs();

    docs_step.dependOn(&b.addInstallDirectory(.{
        .source_dir = docs,
        .install_dir = .prefix,
        .install_subdir = "../docs",
    }).step);

    const test_step = b.step("test", "Run unit tests");
    const test_obj = b.addTest(.{
        .name = "zircon-test",
        .root_module = zircon_mod,
    });
    test_step.dependOn(&b.addRunArtifact(test_obj).step);
}
