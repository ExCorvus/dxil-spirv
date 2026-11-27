// What Microsoft's own tools say about the compute shaders inside an Xbox Series XboxBvhBuilder.dll.
//
// Written for the question on dxil-spirv's llvm.copysign change: "Does it pass dxil.dll validator? Is there
// evidence Windows drivers don't explode on that code?" For every DXBC container inside the library it reports:
//
//   A. the verdict of Microsoft's validator (dxil.dll, IDxcValidator::Validate, flags 0),
//   B. what Windows' own D3D12 runtime and the installed driver do with it (system d3d12.dll, no translation
//      layer): the root signature from the container's own RTS0 part, then a compute pipeline,
//   and, when dxcompiler.dll is given, which LLVM intrinsics and which xbox.* functions the module declares
//   (from dxcompiler's disassembly, read in memory and counted, never printed).
//
// Nothing is written to disk. The shaders are read from the library in memory only; the output holds sizes,
// container digests, result codes and the validator's message lines with any line that quotes IR left out (so the
// output can be posted without quoting the shaders).
//
// Build (x64 Developer Command Prompt, Windows SDK 10.0.26100 or newer):
//   cl /nologo /std:c++17 /EHsc /O2 xbox_shader_evidence.cpp
// Run:
//   xbox_shader_evidence <path to XboxBvhBuilder.dll> --dxil <path to dxil.dll> [--dxcompiler <dxcompiler.dll>]
//                        [--debug-layer] [--no-d3d12] [--without-xbox-root-flags]
// --without-xbox-root-flags rewrites each container's own root signature without the two flags Windows refuses
// (0x1000000, 0x2000000), so that the compute pipeline call itself can be measured; the shader is not changed.
// dxil.dll ships with the Windows SDK (bin\<version>\x64\dxil.dll); dxcompiler.dll with the Windows SDK or the
// Vulkan SDK.

#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <d3d12.h>
#include <dxgi1_4.h>
#include <dxcapi.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

struct Container {
    size_t offset;
    uint32_t size;
    std::vector<std::string> parts;
};

uint32_t u32(const std::vector<uint8_t>& d, size_t at) {
    uint32_t v;
    std::memcpy(&v, d.data() + at, 4);
    return v;
}

std::vector<Container> find_containers(const std::vector<uint8_t>& d) {
    std::vector<Container> out;
    for (size_t i = 0; i + 32 <= d.size(); ++i) {
        if (std::memcmp(d.data() + i, "DXBC", 4) != 0) continue;
        const uint32_t size = u32(d, i + 24), count = u32(d, i + 28);
        if (size < 32 || i + size > d.size() || count == 0 || count > 64 || 32 + 4ull * count > size) continue;
        Container c{i, size, {}};
        bool ok = true;
        for (uint32_t p = 0; p < count && ok; ++p) {
            const uint32_t at = u32(d, i + 32 + 4 * p);
            if (at + 8ull > size) { ok = false; break; }
            c.parts.emplace_back(reinterpret_cast<const char*>(d.data() + i + at), 4);
        }
        if (!ok) continue;
        out.push_back(c);
        i += size - 1;
    }
    return out;
}

std::string sha256(const std::vector<uint8_t>& d) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    uint8_t digest[32] = {};
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(h, const_cast<PUCHAR>(d.data()), static_cast<ULONG>(d.size()), 0);
    BCryptFinishHash(h, digest, sizeof digest, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    std::string s;
    char b[3];
    for (uint8_t x : digest) { std::snprintf(b, sizeof b, "%02x", x); s += b; }
    return s;
}

// A blob over memory the caller keeps alive.
class MemoryBlob final : public IDxcBlob {
public:
    MemoryBlob(const void* p, size_t n) : p_(p), n_(n) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDxcBlob)) {
            *out = static_cast<IDxcBlob*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs_; }  // lives on the stack
    LPVOID STDMETHODCALLTYPE GetBufferPointer() override { return const_cast<void*>(p_); }
    SIZE_T STDMETHODCALLTYPE GetBufferSize() override { return n_; }

private:
    const void* p_;
    size_t n_;
    ULONG refs_ = 1;
};

std::string blob_text(IDxcBlob* b) {
    if (!b || !b->GetBufferSize()) return {};
    return std::string(static_cast<const char*>(b->GetBufferPointer()), b->GetBufferSize());
}

// Validator lines without the ones that quote IR (value names, globals, metadata).
std::vector<std::string> message_lines(const std::string& text) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(start, end - start);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\0')) line.pop_back();
        if (!line.empty() && line.find('%') == std::string::npos && line.find('@') == std::string::npos &&
            line.find('!') == std::string::npos)
            out.push_back(line.size() > 200 ? line.substr(0, 200) + " ..." : line);
        start = end + 1;
    }
    return out;
}

using CreateInstance = HRESULT(WINAPI*)(REFCLSID, REFIID, LPVOID*);

struct Dxc {
    HMODULE module = nullptr;
    CreateInstance create = nullptr;
    bool load(const char* path) {
        module = LoadLibraryA(path);
        if (module) create = reinterpret_cast<CreateInstance>(GetProcAddress(module, "DxcCreateInstance"));
        return create != nullptr;
    }
};

std::string version_of(IUnknown* o) {
    IDxcVersionInfo* info = nullptr;
    if (!o || FAILED(o->QueryInterface(__uuidof(IDxcVersionInfo), reinterpret_cast<void**>(&info)))) return "unknown";
    UINT32 major = 0, minor = 0;
    info->GetVersion(&major, &minor);
    info->Release();
    return std::to_string(major) + "." + std::to_string(minor);
}

// The D3D12 calls in their own function, so that a fault inside the runtime or the driver is caught and reported.
struct D3d12Result {
    HRESULT signature = E_FAIL, pipeline = E_FAIL, removed = S_OK;
    DWORD fault = 0;
    std::string fault_place;
    double ms = 0;
};

std::string place_of(const void* address) {
    HMODULE module = nullptr;
    char name[MAX_PATH] = "";
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            static_cast<LPCSTR>(address), &module) ||
        !GetModuleFileNameA(module, name, MAX_PATH))
        return "a place in no loaded module";
    const char* file = std::strrchr(name, '\\');
    char b[MAX_PATH + 32];
    std::snprintf(b, sizeof b, "%s+0x%llx", file ? file + 1 : name,
                  static_cast<unsigned long long>(static_cast<const char*>(address) -
                                                  reinterpret_cast<const char*>(module)));
    return b;
}

int fault_filter(EXCEPTION_POINTERS* e, D3d12Result* r) {
    r->fault = e->ExceptionRecord->ExceptionCode;
    r->fault_place = place_of(e->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}

// --without-xbox-root-flags: the container's own root signature, read with Windows' deserializer and written again
// with flags 0x1000000 and 0x2000000 cleared (Windows refuses those two; nothing else changes). Only so that the
// pipeline call can be measured at all; the shader itself is handed over unchanged.
PFN_D3D12_CREATE_VERSIONED_ROOT_SIGNATURE_DESERIALIZER g_deserializer = nullptr;
PFN_D3D12_SERIALIZE_VERSIONED_ROOT_SIGNATURE g_serializer = nullptr;
bool g_strip_flags = false;
constexpr UINT kXboxRootFlags = 0x3000000;

HRESULT root_signature_blob(const void* code, size_t size, ID3DBlob** out) {
    *out = nullptr;
    ID3D12VersionedRootSignatureDeserializer* reader = nullptr;
    HRESULT hr = g_deserializer(code, size, __uuidof(ID3D12VersionedRootSignatureDeserializer),
                                reinterpret_cast<void**>(&reader));
    if (FAILED(hr)) return hr;
    const D3D12_VERSIONED_ROOT_SIGNATURE_DESC* desc = nullptr;
    hr = reader->GetRootSignatureDescAtVersion(D3D_ROOT_SIGNATURE_VERSION_1_1, &desc);
    if (SUCCEEDED(hr)) {
        D3D12_VERSIONED_ROOT_SIGNATURE_DESC copy = *desc;
        copy.Desc_1_1.Flags = static_cast<D3D12_ROOT_SIGNATURE_FLAGS>(copy.Desc_1_1.Flags & ~kXboxRootFlags);
        ID3DBlob* error = nullptr;
        hr = g_serializer(&copy, out, &error);
        if (error) error->Release();
    }
    reader->Release();
    return hr;
}

void make_pipeline_inner(ID3D12Device* device, const void* code, size_t size, D3d12Result& r) {
    ID3D12RootSignature* signature = nullptr;
    if (g_strip_flags) {
        ID3DBlob* blob = nullptr;
        r.signature = root_signature_blob(code, size, &blob);
        if (SUCCEEDED(r.signature)) {
            r.signature = device->CreateRootSignature(0, blob->GetBufferPointer(), blob->GetBufferSize(),
                                                      __uuidof(ID3D12RootSignature),
                                                      reinterpret_cast<void**>(&signature));
            blob->Release();
        }
    } else {
        r.signature = device->CreateRootSignature(0, code, size, __uuidof(ID3D12RootSignature),
                                                  reinterpret_cast<void**>(&signature));
    }
    if (SUCCEEDED(r.signature)) {
        D3D12_COMPUTE_PIPELINE_STATE_DESC desc = {};
        desc.pRootSignature = signature;
        desc.CS = {code, size};
        ID3D12PipelineState* pipeline = nullptr;
        r.pipeline = device->CreateComputePipelineState(&desc, __uuidof(ID3D12PipelineState),
                                                        reinterpret_cast<void**>(&pipeline));
        if (pipeline) pipeline->Release();
        signature->Release();
    }
    r.removed = device->GetDeviceRemovedReason();
}

void make_pipeline(ID3D12Device* device, const void* code, size_t size, D3d12Result& r) {
    const auto t0 = std::chrono::steady_clock::now();
    __try {
        make_pipeline_inner(device, code, size, r);
    } __except (fault_filter(GetExceptionInformation(), &r)) {
    }
    r.ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

void print_debug_messages(ID3D12Device* device) {
    ID3D12InfoQueue* queue = nullptr;
    if (FAILED(device->QueryInterface(__uuidof(ID3D12InfoQueue), reinterpret_cast<void**>(&queue)))) return;
    const UINT64 n = queue->GetNumStoredMessages();
    for (UINT64 i = 0; i < n; ++i) {
        SIZE_T len = 0;
        queue->GetMessage(i, nullptr, &len);
        std::vector<uint8_t> m(len);
        auto* msg = reinterpret_cast<D3D12_MESSAGE*>(m.data());
        if (SUCCEEDED(queue->GetMessage(i, msg, &len))) {
            for (const auto& line : message_lines(std::string(msg->pDescription, msg->DescriptionByteLength)))
                std::printf("        d3d12 debug layer: %s\n", line.c_str());
        }
    }
    queue->ClearStoredMessages();
    queue->Release();
}

std::string hr_text(HRESULT hr) {
    char b[16];
    std::snprintf(b, sizeof b, "0x%08lx", static_cast<unsigned long>(hr));
    return b;
}

}  // namespace

int main(int argc, char** argv) {
    const char *library = nullptr, *dxil_path = nullptr, *dxcompiler_path = nullptr;
    bool debug_layer = false, use_d3d12 = true;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--dxil") && i + 1 < argc) dxil_path = argv[++i];
        else if (!std::strcmp(argv[i], "--dxcompiler") && i + 1 < argc) dxcompiler_path = argv[++i];
        else if (!std::strcmp(argv[i], "--debug-layer")) debug_layer = true;
        else if (!std::strcmp(argv[i], "--no-d3d12")) use_d3d12 = false;
        else if (!std::strcmp(argv[i], "--without-xbox-root-flags")) g_strip_flags = true;
        else library = argv[i];
    }
    if (!library || !dxil_path) {
        std::fprintf(stderr, "usage: xbox_shader_evidence <XboxBvhBuilder.dll> --dxil <dxil.dll> "
                             "[--dxcompiler <dxcompiler.dll>] [--debug-layer] [--no-d3d12]\n");
        return 2;
    }

    std::ifstream in(library, std::ios::binary);
    if (!in) { std::fprintf(stderr, "cannot read %s\n", library); return 2; }
    const std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::printf("library: %zu bytes, SHA-256 %s\n", data.size(), sha256(data).c_str());
    const auto containers = find_containers(data);
    std::printf("DXBC containers found: %zu\n", containers.size());

    Dxc dxil;
    if (!dxil.load(dxil_path)) { std::fprintf(stderr, "cannot load %s\n", dxil_path); return 2; }
    IDxcValidator* validator = nullptr;
    if (FAILED(dxil.create(CLSID_DxcValidator, __uuidof(IDxcValidator), reinterpret_cast<void**>(&validator)))) {
        std::fprintf(stderr, "dxil.dll gave no validator\n");
        return 2;
    }
    std::printf("validator: %s, version %s\n", dxil_path, version_of(validator).c_str());

    Dxc dxcompiler;
    IDxcCompiler* compiler = nullptr;
    if (dxcompiler_path) {
        if (!dxcompiler.load(dxcompiler_path) ||
            FAILED(dxcompiler.create(CLSID_DxcCompiler, __uuidof(IDxcCompiler), reinterpret_cast<void**>(&compiler)))) {
            std::fprintf(stderr, "cannot use %s\n", dxcompiler_path);
            return 2;
        }
        std::printf("disassembler: %s, version %s\n", dxcompiler_path, version_of(compiler).c_str());
    }

    ID3D12Device* device = nullptr;
    PFN_D3D12_CREATE_DEVICE create_device = nullptr;
    IDXGIAdapter1* adapter = nullptr;
    if (use_d3d12) {
        char system[MAX_PATH];
        GetSystemDirectoryA(system, MAX_PATH);
        const std::string d3d12_path = std::string(system) + "\\d3d12.dll", dxgi_path = std::string(system) + "\\dxgi.dll";
        HMODULE d3d12 = LoadLibraryA(d3d12_path.c_str()), dxgi = LoadLibraryA(dxgi_path.c_str());
        create_device = reinterpret_cast<PFN_D3D12_CREATE_DEVICE>(GetProcAddress(d3d12, "D3D12CreateDevice"));
        auto get_debug = reinterpret_cast<PFN_D3D12_GET_DEBUG_INTERFACE>(GetProcAddress(d3d12, "D3D12GetDebugInterface"));
        auto create_factory = reinterpret_cast<HRESULT(WINAPI*)(REFIID, void**)>(GetProcAddress(dxgi, "CreateDXGIFactory1"));
        g_deserializer = reinterpret_cast<PFN_D3D12_CREATE_VERSIONED_ROOT_SIGNATURE_DESERIALIZER>(
            GetProcAddress(d3d12, "D3D12CreateVersionedRootSignatureDeserializer"));
        g_serializer = reinterpret_cast<PFN_D3D12_SERIALIZE_VERSIONED_ROOT_SIGNATURE>(
            GetProcAddress(d3d12, "D3D12SerializeVersionedRootSignature"));
        if (g_strip_flags) {
            if (!g_deserializer || !g_serializer) { std::fprintf(stderr, "d3d12.dll has no root signature reader\n"); return 2; }
            std::printf("root signatures: the container's own, rewritten without flags 0x3000000 (--without-xbox-root-flags)\n");
        }
        if (debug_layer && get_debug) {
            ID3D12Debug* debug = nullptr;
            if (SUCCEEDED(get_debug(__uuidof(ID3D12Debug), reinterpret_cast<void**>(&debug)))) {
                debug->EnableDebugLayer();
                debug->Release();
                std::printf("d3d12 debug layer: on\n");
            } else {
                std::printf("d3d12 debug layer: not available (Graphics Tools not installed?)\n");
            }
        }
        IDXGIFactory1* factory = nullptr;
        if (create_factory && SUCCEEDED(create_factory(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&factory))) &&
            SUCCEEDED(factory->EnumAdapters1(0, &adapter))) {
            DXGI_ADAPTER_DESC1 desc = {};
            adapter->GetDesc1(&desc);
            LARGE_INTEGER umd = {};
            adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice), &umd);
            std::printf("adapter: %ls, driver %u.%u.%u.%u\n", desc.Description, HIWORD(umd.HighPart),
                        LOWORD(umd.HighPart), HIWORD(umd.LowPart), LOWORD(umd.LowPart));
        }
        const HRESULT hr = create_device ? create_device(adapter, D3D_FEATURE_LEVEL_12_0, __uuidof(ID3D12Device),
                                                         reinterpret_cast<void**>(&device))
                                         : E_FAIL;
        std::printf("d3d12 (%s): device %s\n", d3d12_path.c_str(), hr_text(hr).c_str());
        if (factory) factory->Release();
    }

    std::map<std::string, int> totals;
    int index = 0, faults_so_far = 0;
    for (const auto& c : containers) {
        const uint8_t* code = data.data() + c.offset;
        std::string names;
        for (const auto& p : c.parts) names += (names.empty() ? "" : ",") + p;
        bool digest_zero = true;
        char digest[33] = {};
        for (int i = 0; i < 16; ++i) {
            std::snprintf(digest + 2 * i, 3, "%02x", code[4 + i]);
            if (code[4 + i]) digest_zero = false;
        }
        std::printf("\nshader %d: %u bytes, digest %s%s, parts %s\n", index++, c.size, digest,
                    digest_zero ? " (zero: not signed)" : "", names.c_str());

        MemoryBlob blob(code, c.size);
        IDxcOperationResult* result = nullptr;
        HRESULT status = E_FAIL;
        const HRESULT call = validator->Validate(&blob, DxcValidatorFlags_Default, &result);
        if (SUCCEEDED(call) && result) result->GetStatus(&status);
        std::printf("  A validator: %s\n", SUCCEEDED(call) ? (SUCCEEDED(status) ? "valid" : ("invalid " + hr_text(status)).c_str())
                                                              : ("call failed " + hr_text(call)).c_str());
        totals[SUCCEEDED(call) && SUCCEEDED(status) ? "A valid" : "A not valid"]++;
        if (result) {
            IDxcBlobEncoding* errors = nullptr;
            if (SUCCEEDED(result->GetErrorBuffer(&errors)) && errors) {
                // Every distinct message once, in first-seen order, with how often it came.
                std::vector<std::pair<std::string, int>> seen;
                for (const auto& line : message_lines(blob_text(errors))) {
                    bool found = false;
                    for (auto& s : seen) {
                        if (s.first == line) { ++s.second; found = true; break; }
                    }
                    if (!found) seen.emplace_back(line, 1);
                }
                for (const auto& s : seen) {
                    if (s.second > 1) std::printf("      %s (x%d)\n", s.first.c_str(), s.second);
                    else std::printf("      %s\n", s.first.c_str());
                }
                errors->Release();
            }
            result->Release();
        }

        if (compiler) {
            IDxcBlobEncoding* text = nullptr;
            const HRESULT hr = compiler->Disassemble(&blob, &text);
            if (SUCCEEDED(hr) && text) {
                const std::string s = blob_text(text);
                std::map<std::string, int> declared;
                for (size_t at = s.find("declare "); at != std::string::npos; at = s.find("declare ", at + 8)) {
                    const size_t name = s.find('@', at), end = s.find('(', name);
                    if (name == std::string::npos || end == std::string::npos) break;
                    const std::string n = s.substr(name + 1, end - name - 1);
                    if (n.rfind("llvm.", 0) == 0 || n.rfind("xbox.", 0) == 0)
                        declared[n.rfind("llvm.", 0) == 0 ? n : "xbox.*"]++;
                }
                std::string list;
                for (const auto& d : declared)
                    list += (list.empty() ? "" : ", ") + d.first + (d.first == "xbox.*" ? " x" + std::to_string(d.second) : "");
                std::printf("  declares: %s\n", list.empty() ? "no llvm.* or xbox.* function" : list.c_str());
                if (declared.count("llvm.copysign.f32")) totals["declares llvm.copysign.f32"]++;
                text->Release();
            } else {
                std::printf("  declares: disassembly failed %s\n", hr_text(hr).c_str());
            }
        }

        if (device) {
            D3d12Result r;
            make_pipeline(device, code, c.size, r);
            if (r.fault) {
                std::printf("  B d3d12: FAULT 0x%08lx at %s (%.1f ms)\n", r.fault, r.fault_place.c_str(), r.ms);
                totals["B fault"]++;
            } else {
                std::printf("  B d3d12: root signature %s, compute pipeline %s, device %s (%.1f ms)\n",
                            hr_text(r.signature).c_str(), SUCCEEDED(r.signature) ? hr_text(r.pipeline).c_str() : "not tried",
                            r.removed == S_OK ? "fine" : ("removed " + hr_text(r.removed)).c_str(), r.ms);
                totals[std::string(SUCCEEDED(r.signature) && SUCCEEDED(r.pipeline) ? "B pipeline made" : "B refused") +
                       (faults_so_far ? " (after a fault)" : "")]++;
                if (r.removed != S_OK) totals["B device removed"]++;
            }
            if (debug_layer) print_debug_messages(device);
            if (r.fault || r.removed != S_OK) {
                // The old device is left as it is; the next shader gets a new one. Results after a fault are
                // counted apart, since the runtime or driver may not be in a clean state any more.
                device = nullptr;
                const HRESULT hr = create_device(adapter, D3D_FEATURE_LEVEL_12_0, __uuidof(ID3D12Device),
                                                 reinterpret_cast<void**>(&device));
                std::printf("  (a new device for the next shader: %s)\n", hr_text(hr).c_str());
                ++faults_so_far;
            }
        }
    }

    std::printf("\ntotals over %zu shaders:\n", containers.size());
    for (const auto& t : totals) std::printf("  %s: %d\n", t.first.c_str(), t.second);
    return 0;
}
