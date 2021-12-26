# arguments
runlink                = static
platform               = linux/x64



# paths home
project_home           = ..
build_dir              = $(project_home)/sln
bin_dir                = $(project_home)/lib/$(platform)
object_dir             = $(project_home)/.objs



# includes of packet_xor headers
packet_xor_inc_path    = $(project_home)/inc
packet_xor_includes    = -I$(packet_xor_inc_path)



# all includes that packet_xor solution needs
includes               = $(packet_xor_includes)



# source files of packet_xor solution
packet_xor_src_path    = $(project_home)/src
packet_xor_source      = $(filter %.cpp, $(shell find $(packet_xor_src_path) -depth -name "*.cpp"))



# objects of packet_xor solution
packet_xor_objects     = $(packet_xor_source:$(project_home)%.cpp=$(object_dir)%.o)



# packet_xor depends libraries
packet_xor_depends     =



# output libraries
ifeq ($(runlink), static)
	packet_xor_outputs = $(bin_dir)/libpacket_xor.a
else ifeq ($(platform), mac)
	packet_xor_outputs = $(bin_dir)/libpacket_xor.dylib
else
	packet_xor_outputs = $(bin_dir)/libpacket_xor.so
endif



# build output command line
ifeq ($(runlink), static)
	build_command      = ar -rv $(packet_xor_outputs) $^
else
	build_command      = g++ -std=c++11 -shared -o $(packet_xor_outputs) $^ $(packet_xor_depends)
endif



# build targets
targets                = packet_xor

# let 'build' be default target, build all targets
build    : $(targets)

packet_xor      : $(packet_xor_objects)
	@echo
	@echo "@@@@@  start making packet_xor  @@@@@"
	$(build_command)
	@echo "@@@@@  make packet_xor success  @@@@@"
	@echo

# build all objects
$(object_dir)/%.o:$(project_home)/%.cpp
	@dir=`dirname $@`;		\
	if [ ! -d $$dir ]; then	\
		mkdir -p $$dir;		\
	fi
	g++ -c -std=c++11 -g -Wall -O1 -pipe -fPIC $(includes) -o $@ $<

clean            :
	rm -rf $(object_dir) $(bin_dir)/libpacket_xor.*

rebuild          : clean build
