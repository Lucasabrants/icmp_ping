# Makefile

# Project Name
PROJ_NAME := ping

# Compiler and linker
CC := gcc

# Compiler and linker
CXX := g++

# SOURCE folder
SRC_DIR := src

# HEADER folder
INC_DIR := ./inc

# Build folder
BUILD_DIR := build

# Source files C++
SRCS := $(wildcard $(CLIB_DIR)/*.c)

# Source files C++
SRCSXX := $(wildcard $(SRC_DIR)/*.cpp)

# Object files
OBJS := $(patsubst %.c,%.o, $(SRCS))
OBJS += $(patsubst %.cpp,%.o, $(SRCSXX))

# Flags for compiler
CC_FLAGS := -c \
		    -o \

# Project dependences -L$(LIB_DIR) ,-rpath $(LIB_DIR) -Wl
PROJ_DEP := -std=c++11 \
			-std=gnu++11 \
			-lpthread \

all: folders $(PROJ_NAME)

$(PROJ_NAME): $(OBJS)
	@echo "Linking $^ ..."
	$(CXX) $^ -o $(BUILD_DIR)/$@ $(PROJ_DEP)
	@rm $(SRC_DIR)/*.o
	@echo "\033[92mBinary are ready in $(BUILD_DIR)/$@!\033[0m"

#
%.o: %.c
	@echo "Compiling $@ ..."
	$(CC) -c -O0 -g $^ -o $@ -I$(INC_DIR)
	@echo "\033[94m$@ Compiled!\033[0m"

%.o: %.cpp
	@echo "Compiling $@ ..."
	$(CXX) -c -O0 -g $^ -o $@ -I$(INC_DIR)
	@echo "\033[94m$@ Compiled!\033[0m"

folders:
	@mkdir -p $(BUILD_DIR)

clean:
	@rm -rf $(BUILD_DIR)/* *.deb $(SRC_DIR)/*.o $(BUILD_DIR)
