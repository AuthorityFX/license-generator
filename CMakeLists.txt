#cmake version
cmake_minimum_required(VERSION 2.8)

#update project name here
set(PROJ_NAME "generator")

#set project
project(${PROJ_NAME})

SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
SET(CMAKE_INSTALL_RPATH "./lib")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)


#project include directory
include_directories(./)

set(SOURCES

main.cpp
licensegenerator.cpp
)

#Add all files to be built here
add_executable(${PROJ_NAME} ${SOURCES})

# Ipp
##################################################

#Ipp root install directory
set(IPP_ROOT /opt/intel/composer_xe_2013.0.079/ipp)

#Ipp include directory
include_directories(${IPP_ROOT}/include)

#Ipp library paths
set(IPP_LIB_PATH ${IPP_ROOT}/lib/intel64)
set(IPP_COMP_PATH ${IPP_ROOT}/../compiler/lib/intel64)

#Libraries to link
set(IPP_LIBS ${IPP_LIB_PATH}/libippcp.so ${IPP_LIB_PATH}/libippcore.so ${IPP_COMP_PATH}/libiomp5.so)

#Link
target_link_libraries(${PROJ_NAME} ${IPP_LIBS})




