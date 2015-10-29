CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build/modules")

PROJECT(freenetconfd-plugin-dt-fw)

FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

SET(SOURCES
	src/ietf-system.c
	src/firmware_upgrade.c
	src/firmware_upgrade.h
)

ADD_LIBRARY(example_opencpe_firmware_mgmt MODULE ${SOURCES})
SET_TARGET_PROPERTIES(example_opencpe_firmware_mgmt PROPERTIES OUTPUT_NAME opencpe_firmware_mgmt PREFIX "")

FIND_PACKAGE(CURL REQUIRED)
FIND_PACKAGE(LIBUBOX REQUIRED)
INCLUDE_DIRECTORIES(${LIBUBOX_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(example_opencpe_firmware_mgmt ${CURL_LIBRARIES} ${LIBUBOX_LIBRARIES})

INSTALL(
	TARGETS
		example_opencpe_firmware_mgmt
	LIBRARY DESTINATION lib/freenetconfd/
)

INSTALL(
	FILES
		yang/opencpe-firmware-mgmt@2014-02-06.yang
	DESTINATION etc/yang/
)
