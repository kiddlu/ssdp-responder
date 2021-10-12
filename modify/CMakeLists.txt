cmake_minimum_required(VERSION 2.8)
project (ssdpd)

add_definitions (
	-O2
	-W -Wall -Wextra -Wno-unused -std=c11
	-D_GNU_SOURCE -D_XOPEN_SOURCE
	-D_PIDFILEDIR=\"@runstatedir@\" -D_CACHEDIR=\"@localstatedir@/@vardb@\"
	-D_FORTIFY_SOURCE=2
)

set(SOURCES
 ${PROJECT_SOURCE_DIR}/ssdpd.c
)

#static link
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

include_directories (${PROJECT_SOURCE_DIR})

add_executable(ssdpd ${SOURCES})
target_link_libraries(ssdpd -lpthread)

include(cross.cmake)
