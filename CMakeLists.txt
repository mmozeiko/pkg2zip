cmake_minimum_required(VERSION 3.13)
project(pkg2zip)
set(CMAKE_C_STANDARD 99)

set(HARDWARE_ACCELERATION "Yes" CACHE BOOL "Hardware acceleration for AES and CRC32")

set(SOURCE_FILES
miniz_tdef.c
pkg2zip.c
pkg2zip_aes.c
pkg2zip_crc32.c
pkg2zip_out.c
pkg2zip_psp.c
pkg2zip_sys.c
pkg2zip_zip.c
pkg2zip_zrif.c
puff.c
)

if(HARDWARE_ACCELERATION)
    if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86 OR ${CMAKE_SYSTEM_PROCESSOR} STREQUAL x86_64)
        set(HARDWARE_ACCELERATION_SOURCE_FILES
        pkg2zip_aes_x86.c
        pkg2zip_crc32_x86.c
        )
        set_source_files_properties(pkg2zip_aes_x86.c PROPERTIES COMPILE_FLAGS "-maes -mssse3 -MMD")
        set_source_files_properties(pkg2zip_crc32_x86.c PROPERTIES COMPILE_FLAGS "-mpclmul -msse4 -MMD")
    elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL aarch64)
        set(HARDWARE_ACCELERATION_SOURCE_FILES
        pkg2zip_aes_aarch64.c
        pkg2zip_crc32_aarch64.c
        )
        set_source_files_properties(pkg2zip_aes_aarch64.c PROPERTIES COMPILE_FLAGS "-march=armv8-a+aes+crypto+fp")
        set_source_files_properties(pkg2zip_crc32_aarch64.c PROPERTIES COMPILE_FLAGS "-march=armv8-a+crc")
    else()
        message(FATAL_ERROR "The architecture ${CMAKE_SYSTEM_PROCESSOR} is not supported for hardware acceleration currently. Use -DHARDWARE_ACCELERATION=OFF to disable this feature or add support for your architecture.")
    endif()
endif()

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(pkg2zip ${SOURCE_FILES} ${HARDWARE_ACCELERATION_SOURCE_FILES})
