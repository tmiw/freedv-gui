set(FREEDV_SOURCES
    dlg_audiooptions.cpp
    dlg_filter.cpp
    dlg_options.cpp
    dlg_ptt.cpp
    main.cpp
    pa_wrapper.cpp
    plot.cpp
    plot_scalar.cpp
    plot_scatter.cpp
    plot_spectrum.cpp
    plot_waterfall.cpp
    hamlib.cpp
    serialport.cpp
    topFrame.cpp
    sox_biquad.c
    comp.h
    dlg_audiooptions.h
    dlg_filter.h
    dlg_options.h
    dlg_ptt.h
    defines.h
    main.h
    pa_wrapper.h
    plot.h
    plot_scalar.h
    plot_scatter.h
    plot_spectrum.h
    plot_waterfall.h
    hamlib.h
    sox_biquad.h
    sox/band.h
    sox/biquad.c
    sox/biquads.c
    sox/biquad.h
    sox/effects.c
    sox/effects.h
    sox/effects_i.c
    sox/formats_i.c
    sox/libsox.c
    sox/sox.h
    sox/sox_i.h
    sox/soxomp.h
    sox/util.h
    sox/xmalloc.h
    sox/xmalloc.c
    topFrame.h
    version.h
    osx_interface.h
    pskreporter.cpp
    pskreporter.h
    callsign_encoder.cpp
    callsign_encoder.h
    udp.cpp
    util.cpp
    eq.cpp
    voicekeyer.cpp
    playrec.cpp
    ongui.cpp
    freedv_interface.cpp
    freedv_interface.h        
)

set(FREEDV_SOURCES_OSX
    osx_interface.mm
)

set(FREEDV_LINK_LIBS_OSX
    "-framework AVFoundation"
)

# WIN32 is needed for Windows GUI apps and is ignored for UNIX like systems.
# In addition, there are some required OSX-specific code files for platform specific handling.
if(APPLE)
    add_executable(freedv WIN32 ${FREEDV_SOURCES} ${RES_FILES} ${FREEDV_SOURCES_OSX})
else()
    add_executable(freedv WIN32 ${FREEDV_SOURCES} ${RES_FILES})
endif(APPLE)

# Link imported or build tree targets.
target_link_libraries(freedv codec2 lpcnetfreedv)

# Add build dependencies for interally built external libraries.
if(USE_INTERNAL_CODEC2)
    add_dependencies(freedv build_codec2 build_lpcnetfreedv)
endif()

# Add depenencies for other statically built libraries, if applicable.
if(FREEDV_STATIC_DEPS)
    add_dependencies(freedv ${FREEDV_STATIC_DEPS})
endif(FREEDV_STATIC_DEPS)

# Link other dependencies
if(APPLE)
target_link_libraries(freedv ${FREEDV_LINK_LIBS} ${FREEDV_LINK_LIBS_OSX})
elseif(WIN32)
target_link_libraries(freedv ${FREEDV_LINK_LIBS} ws2_32)
else()
target_link_libraries(freedv ${FREEDV_LINK_LIBS})
endif(APPLE)

# For older Xcode (< 9.0), bypass usage of @available.
if(APPLE)
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0.0.900037)
add_definitions(-DAPPLE_OLD_XCODE)
endif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0.0.900037)
endif(APPLE)

# Insert source and generated header directories before other search directories.
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS freedv
    RUNTIME DESTINATION bin
)

# Custom commands to build OSX images.
if(APPLE)
    add_custom_command(
        TARGET freedv
        POST_BUILD
        COMMAND rm ARGS -rf FreeDV.* dist_tmp
        COMMAND mkdir ARGS -p FreeDV.app/Contents/MacOS
        COMMAND mkdir ARGS -p FreeDV.app/Contents/Resources/English.lproj
        COMMAND cp ARGS ${CMAKE_CURRENT_BINARY_DIR}/info.plist FreeDV.app/Contents
        COMMAND cp ARGS ${CMAKE_CURRENT_SOURCE_DIR}/freedv.icns FreeDV.app/Contents/Resources
        COMMAND echo ARGS -n "APPL????" > FreeDV.app/Contents/PkgInfo
        COMMAND cp ARGS freedv FreeDV.app/Contents/MacOS/FreeDV
        COMMAND DYLD_LIBRARY_PATH=${CODEC2_BUILD_DIR}/src:${LPCNET_BUILD_DIR}/src:${DYLD_LIBRARY_PATH} ${CMAKE_SOURCE_DIR}/macdylibbundler/dylibbundler ARGS -od -b -x FreeDV.app/Contents/MacOS/FreeDV -d FreeDV.app/Contents/libs -p @loader_path/../libs/ -i /usr/lib -s ${CODEC2_BUILD_DIR}/src -s ${LPCNET_BUILD_DIR}/src
        COMMAND mkdir dist_tmp
        COMMAND cp -r FreeDV.app dist_tmp
        COMMAND hdiutil create -srcfolder dist_tmp/ -volname FreeDV -format UDZO -fs HFS+ ./FreeDV.dmg
        COMMAND rm -rf dist_tmp
    )
endif(APPLE)
