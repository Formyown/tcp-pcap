# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.14

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/deyu/CLionProjects/gtpv2-utrans

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/gtpv2_utrans.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/gtpv2_utrans.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/gtpv2_utrans.dir/flags.make

CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o: CMakeFiles/gtpv2_utrans.dir/flags.make
CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o: ../src/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o -c /Users/deyu/CLionProjects/gtpv2-utrans/src/main.cpp

CMakeFiles/gtpv2_utrans.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gtpv2_utrans.dir/src/main.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/deyu/CLionProjects/gtpv2-utrans/src/main.cpp > CMakeFiles/gtpv2_utrans.dir/src/main.cpp.i

CMakeFiles/gtpv2_utrans.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gtpv2_utrans.dir/src/main.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/deyu/CLionProjects/gtpv2-utrans/src/main.cpp -o CMakeFiles/gtpv2_utrans.dir/src/main.cpp.s

# Object files for target gtpv2_utrans
gtpv2_utrans_OBJECTS = \
"CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o"

# External object files for target gtpv2_utrans
gtpv2_utrans_EXTERNAL_OBJECTS =

gtpv2_utrans: CMakeFiles/gtpv2_utrans.dir/src/main.cpp.o
gtpv2_utrans: CMakeFiles/gtpv2_utrans.dir/build.make
gtpv2_utrans: CMakeFiles/gtpv2_utrans.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable gtpv2_utrans"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gtpv2_utrans.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/gtpv2_utrans.dir/build: gtpv2_utrans

.PHONY : CMakeFiles/gtpv2_utrans.dir/build

CMakeFiles/gtpv2_utrans.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/gtpv2_utrans.dir/cmake_clean.cmake
.PHONY : CMakeFiles/gtpv2_utrans.dir/clean

CMakeFiles/gtpv2_utrans.dir/depend:
	cd /Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/deyu/CLionProjects/gtpv2-utrans /Users/deyu/CLionProjects/gtpv2-utrans /Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug /Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug /Users/deyu/CLionProjects/gtpv2-utrans/cmake-build-debug/CMakeFiles/gtpv2_utrans.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/gtpv2_utrans.dir/depend

