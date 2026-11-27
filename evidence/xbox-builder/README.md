# What Microsoft's tools say about Xbox Series builder shaders

This folder answers a review question on the `llvm.copysign.f32` change: *does that code pass Microsoft's
validator, and is there evidence that Windows drivers do not fail on it?* It is a measuring program, not part of
dxil-spirv.

## Where the shaders come from

Xbox Series titles that use ray tracing can ship an acceleration-structure builder library, `XboxBvhBuilder.dll`,
beside their executable (the copy measured here carries no version information naming its maker). The library
holds its compute shaders as DXBC containers. They are compiled by the Xbox
shader compiler (`dxcxbox`), and their DXIL carries Xbox-only parts: the target `dxil-ms-xb2`, the named metadata
`xbox.compiler.options`, calls to `xbox.*` functions, root signature flags `0x1000000` and `0x2000000`, and LLVM
constructs such as `insertvalue` and `llvm.copysign.f32`.

The shaders are not included here and cannot be: they belong to the title. The program reads them from your own
copy of the library, in memory only, and writes nothing to disk. What it prints holds sizes, container digests,
result codes and Microsoft's message lines; any message line that quotes IR is left out.

## What it does with each shader

- **A.** Microsoft's validator: `dxil.dll`, `IDxcValidator::Validate` with flags 0.
- **B.** Windows' own D3D12 runtime and the installed driver (system `d3d12.dll`, no translation layer): the
  container's own root signature, then a compute pipeline. With `--without-xbox-root-flags` the root signature is
  read with Windows' deserializer and written again without the two Xbox-only flags, so that the pipeline call can
  be reached at all. The shader itself is not changed.
- With `--dxcompiler`, the LLVM intrinsics and `xbox.*` functions each module declares, counted from
  dxcompiler's disassembly in memory.

## Build and run

From an x64 Developer Command Prompt with the Windows SDK 10.0.26100 or newer:

```
cl /nologo /std:c++17 /EHsc /O2 xbox_shader_evidence.cpp
xbox_shader_evidence "<title folder>\XboxBvhBuilder.dll" --dxil "<Windows SDK>\bin\10.0.26100.0\x64\dxil.dll" ^
    --dxcompiler "<Windows SDK or Vulkan SDK>\dxcompiler.dll" [--without-xbox-root-flags] [--debug-layer]
```

Step B creates pipelines on the graphics card and runs none of them. A fault inside the runtime or driver is
caught and reported, and the next shader gets a new device. If the driver removes the device, that is reported too.

## First results (one library, SHA-256 99f803ac22c01ef329dddb1d40be67238d2a812d01e8d040b3cb5135bc23707e, 52 shaders)

- **A**: 52 of 52 invalid. Each is refused first for `Unknown target triple 'dxil-ms-xb2'` and
  `Named metadata 'xbox.compiler.options' is unknown`. The three shaders that declare it also get
  `External function 'llvm.copysign.f32' is not a DXIL function`. So `llvm.copysign.f32` is not valid DXIL
  for Windows; it comes in the Xbox form of DXIL only.
- **B**, AMD Radeon RX 9070 XT, driver 32.0.32029.2010: with the containers' own root signatures, 52 of 52 are
  refused at the root signature (0x80004005). With `--without-xbox-root-flags`, the first seven: the two without
  `xbox.*` calls made; four with `xbox.*` calls fault inside AMD's D3D12 shader compiler (`amdxc64.dll`, the same
  place each time); the fifth makes the driver remove the device (0x887A0020), and no new device can be made
  after that. None of the three shaders that use `llvm.copysign.f32` was reached, so this does not show what a
  Windows driver does with that intrinsic alone.
