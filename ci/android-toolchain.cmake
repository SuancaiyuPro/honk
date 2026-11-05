set(ANDROID_ABI arm64-v8a CACHE STRING "" FORCE)
set(ANDROID_PLATFORM android-35 CACHE STRING "" FORCE)
set(CMAKE_SYSTEM_VERSION 35 CACHE STRING "" FORCE)
set(ANDROID_STL c++_static CACHE STRING "" FORCE)
set(CMAKE_ANDROID_STL_TYPE c++_static CACHE STRING "" FORCE)
# BoringSSL's benchmark probes try to execute target binaries on the build host.
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
include("$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")
