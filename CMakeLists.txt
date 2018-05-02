cmake_minimum_required(VERSION 3.10)
project(pam_ldapsetquota C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMake")

find_package(PAM REQUIRED)
find_package(Ldap REQUIRED)

add_library(pam_ldapsetquota SHARED library.c library.h config.h)

target_link_libraries(pam_ldapsetquota ${PAM_LIBRARIES} ${LDAP_LIBRARIES})
