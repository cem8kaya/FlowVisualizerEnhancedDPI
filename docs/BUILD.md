# Build Guide

## System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- **Compiler**: GCC 7+ or Clang 6+ with C++17 support
- **CMake**: Version 3.14 or higher
- **RAM**: Minimum 2GB, recommended 8GB+
- **Disk**: ~500MB for build artifacts

## Dependencies

### Required

- **libpcap** (>= 1.9.0): Packet capture library
- **nlohmann/json** (>= 3.11.0): JSON library (fetched automatically by CMake)
- **pthreads**: POSIX threads library (usually included with system)

### Optional

- **nDPI** (>= 4.0): Deep packet inspection library (full integration in M2)
- **Google Test**: For unit tests (not yet implemented)
- **Doxygen**: For generating API documentation

## Installing Dependencies

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    pkg-config
```

### CentOS/RHEL/Fedora

```bash
sudo dnf install -y \
    gcc-c++ \
    cmake \
    git \
    libpcap-devel \
    pkgconfig

# Or for older versions with yum:
sudo yum install -y \
    gcc-c++ \
    cmake \
    git \
    libpcap-devel \
    pkgconfig
```

### macOS

```bash
brew install cmake libpcap pkg-config
```

### Installing nDPI (Optional, for M2+)

```bash
# Clone nDPI repository
git clone https://github.com/ntop/nDPI.git
cd nDPI

# Build and install
./autogen.sh
./configure
make -j$(nproc)
sudo make install

# Update library cache (Linux)
sudo ldconfig
```

## Building from Source

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd FlowVisualizerEnhancedDPI

# Create build directory
mkdir build
cd build

# Configure and build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# The binary will be at: ./src/callflowd
```

### Build Types

#### Debug Build (with sanitizers)

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

This enables:
- Debug symbols (-g)
- AddressSanitizer (detects memory errors)
- UndefinedBehaviorSanitizer (detects undefined behavior)
- No optimization (-O0)

#### Release Build (optimized)

```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

This enables:
- Optimizations (-O3)
- NDEBUG macro
- No debug symbols

#### RelWithDebInfo Build

```bash
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make -j$(nproc)
```

This enables:
- Optimizations (-O2)
- Debug symbols (-g)
- Good for profiling

### CMake Options

```bash
# Disable tests
cmake -DBUILD_TESTS=OFF ..

# Disable API server
cmake -DBUILD_API_SERVER=OFF ..

# Enable code coverage
cmake -DENABLE_COVERAGE=ON ..

# Custom install prefix
cmake -DCMAKE_INSTALL_PREFIX=/opt/callflow ..

# Verbose build
make VERBOSE=1
```

## Installation

```bash
# After building
sudo make install

# This installs:
# - Binary: /usr/local/bin/callflowd
# - UI assets: /usr/local/share/callflow-visualizer/ui/
```

### Custom Installation Prefix

```bash
cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local ..
make install

# Binary will be at: $HOME/.local/bin/callflowd
```

## Troubleshooting

### libpcap not found

**Error:**
```
CMake Error: libpcap not found
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Check installation
ldconfig -p | grep pcap
```

### nDPI not found

**Note:** This is expected for M1. nDPI is optional and will be fully integrated in M2.

If you want to build with nDPI support:

```bash
# Set nDPI paths manually
cmake \
  -DNDPI_INCLUDE_DIR=/usr/local/include/ndpi \
  -DNDPI_LIBRARY=/usr/local/lib/libndpi.so \
  ..
```

### C++17 not supported

**Error:**
```
error: 'optional' in namespace 'std' does not name a template type
```

**Solution:**
Upgrade your compiler:
```bash
# Ubuntu
sudo apt-get install gcc-9 g++-9
export CXX=g++-9
export CC=gcc-9
```

### Out of memory during build

**Solution:**
Reduce parallelism:
```bash
make -j2  # Use only 2 cores
# or
make  # Single-threaded build
```

## Cross-Compilation

### For ARM64

```bash
# Install cross-compiler
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Create toolchain file
cat > toolchain-arm64.cmake << 'EOF'
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
EOF

# Configure with toolchain
cmake -DCMAKE_TOOLCHAIN_FILE=toolchain-arm64.cmake ..
make -j$(nproc)
```

## Development Build

For active development with fast iteration:

```bash
# Configure once
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..

# Incremental builds (only rebuild changed files)
make

# Or rebuild specific target
make callflowd

# Clean build
make clean
```

## Running Tests

```bash
# Build with tests enabled
cmake -DBUILD_TESTS=ON ..
make

# Run all tests
ctest --output-on-failure

# Run with verbose output
ctest -V

# Run specific test
./tests/unit_tests --gtest_filter=SipParser.*
```

## Static Analysis

```bash
# clang-tidy
find src include -name '*.cpp' | xargs clang-tidy -p build/

# cppcheck
cppcheck --enable=all --inconclusive src/ include/
```

## Performance Profiling

### Using perf

```bash
# Build with debug symbols
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make

# Profile
perf record -g ./src/callflowd --input large.pcap
perf report
```

### Using valgrind

```bash
# Memory profiling
valgrind --tool=massif ./src/callflowd --input test.pcap

# Cachegrind
valgrind --tool=cachegrind ./src/callflowd --input test.pcap
```

## Continuous Integration

The project uses GitHub Actions for CI. See [.github/workflows/ci.yml](../.github/workflows/ci.yml).

Local CI simulation:

```bash
# Run the same commands as CI
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON ..
make -j$(nproc)
ctest --output-on-failure
```

## Docker Build

See [Docker documentation](DOCKER.md) for containerized builds.

## IDE Setup

### VS Code

1. Install C/C++ extension
2. Install CMake Tools extension
3. Open project folder
4. Configure with CMake Tools (Ctrl+Shift+P → CMake: Configure)
5. Build with CMake Tools (F7)

### CLion

1. Open project folder
2. CLion will automatically detect CMakeLists.txt
3. Configure and build

## Next Steps

After successful build:

1. See [Usage Guide](../README.md#usage) for running the application
2. See [API Documentation](API.md) for API details (M2+)
3. See [Contributing Guide](CONTRIBUTING.md) for development workflow
