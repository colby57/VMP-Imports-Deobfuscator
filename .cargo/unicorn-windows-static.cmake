if(CMAKE_PROJECT_NAME STREQUAL "unicorn")
    set(unicorn_copy_command "${CMAKE_BINARY_DIR}/copy-unicorn-static.cmd")
    file(WRITE "${unicorn_copy_command}"
        "@echo off\r\ncopy /Y \"%~3\" \"%~4\" >nul\r\n"
    )
    set(CMAKE_COMMAND "${unicorn_copy_command}")
else()
    set(CMAKE_PROJECT_INCLUDE "${CMAKE_CURRENT_LIST_FILE}" CACHE FILEPATH "" FORCE)
endif()
