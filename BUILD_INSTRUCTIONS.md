# Build Instructions for CS2 Internal

## Prerequisites

### Required Software
- **Windows 10/11** (x64)
- **Visual Studio 2022** (Community Edition or higher)
- **Windows SDK** (10.0 or higher)
- **C++ Desktop Development workload**

### Visual Studio Setup
1. Download Visual Studio 2022: https://visualstudio.microsoft.com/downloads/
2. Run installer and select:
   - **Desktop development with C++**
   - **Windows 10/11 SDK**
   - **MSVC v143 or higher**
   - **CMake tools for Windows** (optional)

## Build Steps

### Method 1: Using Visual Studio IDE (Recommended)

1. **Open the solution:**
   ```
   cs2_internal.sln
   ```

2. **Select Configuration:**
   - Release (recommended for distribution)
   - Debug (for development)

3. **Select Platform:**
   - x64 (for 64-bit CS2)
   - x86 (for 32-bit if needed)

4. **Build:**
   - Right-click solution → **Build Solution** (Ctrl+Shift+B)
   - Or: **Build** → **Build Solution**

5. **Output:**
   - DLL: `cs2_internal\bin\Release\cs2_internal.dll`
   - PDB: `cs2_internal\bin\Release\cs2_internal.pdb`

### Method 2: Using MSBuild Command Line

1. **Open Command Prompt or PowerShell**

2. **Build Release x64:**
   ```cmd
   msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
   ```

3. **Build Debug x64:**
   ```cmd
   msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v143
   ```

4. **Build Both x86 and x64:**
   ```cmd
   msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
   msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
   ```

### Method 3: Using Developer Command Prompt

1. **Open Visual Studio Developer Command Prompt:**
   - Search for "Developer Command Prompt for VS 2022"

2. **Navigate to project directory:**
   ```cmd
   cd path\to\cs2-internal
   ```

3. **Run build:**
   ```cmd
   msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64
   ```

## Build Configurations

### Release Build (x64)
```
Configuration: Release
Platform: x64
Output: cs2_internal\Release\cs2_internal.dll
Optimization: Full (/O2)
Debug Info: Stripped
Recommended for: Production deployment
```

### Debug Build (x64)
```
Configuration: Debug
Platform: x64
Output: cs2_internal\Debug\cs2_internal.dll
Optimization: None
Debug Info: Full
Recommended for: Development and debugging
```

## Build Output Locations

```
cs2_internal/
├── Release/
│   ├── cs2_internal.dll      ← Main DLL
│   ├── cs2_internal.pdb      ← Debug symbols
│   └── cs2_internal.exp
├── Debug/
│   ├── cs2_internal.dll
│   ├── cs2_internal.pdb
│   └── cs2_internal.exp
```

## Troubleshooting Build Issues

### Issue: "Missing Windows SDK"
**Solution:** 
- Go to Tools → Get Tools and Features
- Select "Windows 10/11 SDK (latest)"
- Install and restart

### Issue: "Cannot find include files"
**Solution:**
- Right-click Project → Properties
- VC++ Directories → Include Directories
- Verify Windows SDK path is set correctly

### Issue: "Linker error: unresolved external symbols"
**Solution:**
- Ensure ntdll.lib is linked:
  - Project → Properties → Linker → Input
  - Add `ntdll.lib` to Additional Dependencies

### Issue: "Build fails with C1083"
**Solution:**
- Verify all header files exist:
  - anti_detection.hpp
  - HideModule.h
  - memory.hpp
  - overlay.hpp
  - sdk.hpp
  - auth.hpp

## Building from GitHub Actions

See `.github/workflows/build-and-release.yml` for automated CI/CD building.

To trigger automated build:
```bash
git tag v1.0.0
git push origin v1.0.0
```

This will automatically build and create a prerelease with all artifacts.

## Project Structure

```
cs2-internal/
├── cs2_internal.sln              ← Solution file
├── cs2_internal/
│   ├── cs2_internal.vcxproj      ← Project file
│   ├── cs2_internal.vcxproj.filters
│   ├── cs2_internal.cpp          ← Main entry point
│   ├── memory.cpp                ← Memory implementation
│   ├── HideModule.cpp            ← Module hiding implementation
│   ├── anti_detection.hpp        ← Anti-detection framework
│   ├── memory.hpp
│   ├── HideModule.h
│   ├── sdk.hpp
│   ├── auth.hpp
│   ├── overlay.hpp
│   └── Web.hpp
├── .github/workflows/
│   └── build-and-release.yml     ← GitHub Actions CI/CD
```

## Advanced Build Options

### Enable All Optimizations
```cmd
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:WholeProgramOptimization=true /p:DebugInformationFormat=None
```

### Build with Static Runtime
```cmd
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64 /p:RuntimeLibrary=MultiThreaded
```

### Clean Build
```cmd
msbuild cs2_internal.sln /t:Clean /p:Configuration=Release /p:Platform=x64
msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64
```

## Deployment

### Local Deployment
1. Build in Release mode
2. Copy `cs2_internal.dll` to target directory
3. Inject using your preferred method (handle hijack, DLL injection, etc.)

### CI/CD Deployment (GitHub Actions)
1. Tag release: `git tag v1.0.0 && git push origin v1.0.0`
2. GitHub Actions automatically:
   - Builds x86 and x64 versions
   - Creates prerelease on GitHub
   - Uploads DLL and PDB files

## Common Build Commands Quick Reference

| Task | Command |
|------|---------|
| Build Release x64 | `msbuild cs2_internal.sln /p:Configuration=Release /p:Platform=x64` |
| Build Debug x64 | `msbuild cs2_internal.sln /p:Configuration=Debug /p:Platform=x64` |
| Rebuild all | `msbuild cs2_internal.sln /t:Rebuild` |
| Clean all | `msbuild cs2_internal.sln /t:Clean` |
| Build with verbose output | `msbuild cs2_internal.sln /v:detailed` |

## Verifying Build Success

After successful build, check:
1. DLL file exists: `cs2_internal\Release\cs2_internal.dll`
2. File size > 100KB (indicates proper linking)
3. PDB file exists: `cs2_internal\Release\cs2_internal.pdb`
4. No linker errors in build output

## Next Steps

1. **Test the build:**
   - Verify DLL loads without errors
   - Check anti-detection hooks are initialized

2. **Deploy:**
   - Inject DLL into target process
   - Verify functionality

3. **Monitor:**
   - Check for VAC/VAC Live detection
   - Monitor system logs
