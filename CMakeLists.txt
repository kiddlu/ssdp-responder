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
 ${PROJECT_SOURCE_DIR}/origin/src/ssdpd.c
 ${PROJECT_SOURCE_DIR}/origin/src/ssdp.c
 ${PROJECT_SOURCE_DIR}/origin/src/web.c

 ${PROJECT_SOURCE_DIR}/origin/lib/pidfile.c
 ${PROJECT_SOURCE_DIR}/origin/lib/strlcpy.c
)

#static link
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

include_directories (${PROJECT_SOURCE_DIR}/origin/)

add_executable(ssdpd ${SOURCES})
target_link_libraries(ssdpd -lpthread)

include(cross.cmake)
