CXX ?= g++
UNAME_M := $(shell uname -m)

SRC_FILES := $(wildcard src/*.cpp)

ifeq ($(UNAME_M),arm64)
    BTC_FILES    := btc_sha/sha256.cpp btc_sha/sha256_arm_shani.cpp
    HW_FLAGS     := -march=native -DENABLE_ARM_SHANI
    SHA2_FLAG    := -march=armv8-a+sha2
else ifeq ($(UNAME_M),x86_64)
    BTC_FILES    := $(wildcard btc_sha/*.cpp)
    HW_FLAGS     := -march=native -msse4.1 -mavx2 -msha -DENABLE_SSE41 -DENABLE_AVX2 -DENABLE_SHANI
    SHA2_FLAG    :=
else
    BTC_FILES    := $(wildcard btc_sha/*.cpp)
    HW_FLAGS     := -O3
    SHA2_FLAG    :=
endif

LIB_NAME  = libshrincs.a
SRC_DIR   = src
INC_DIR   = include
OBJ_DIR   = obj

OBJS     = $(SRC_FILES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
BTC_OBJS = $(BTC_FILES:btc_sha/%.cpp=$(OBJ_DIR)/%.o)

CXXFLAGS := -O3 -Wall $(HW_FLAGS) -fPIC -std=c++17 -I$(INC_DIR) -I. -Ibtc_sha -DSHRINCS_B32
INCLUDES := -I$(INC_DIR) -I. -Ibtc_sha

build: $(OBJS) $(BTC_OBJS)
	ar rcs $(LIB_NAME) $(OBJS) $(BTC_OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/sha256_arm_shani.o: btc_sha/sha256_arm_shani.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) -O3 -Wall $(SHA2_FLAG) -fPIC -std=c++17 $(INCLUDES) -DSHRINCS_B32 -c $< -o $@

$(OBJ_DIR)/%.o: btc_sha/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME) bin/

BTC_OTHER_FILES := $(filter-out btc_sha/sha256_arm_shani.cpp, $(BTC_FILES))

TEST_FLAGS := -lgtest -lpthread -fsanitize=address -fno-omit-frame-pointer

test: clean
	@mkdir -p bin obj
	$(CXX) -O3 -Wall $(SHA2_FLAG) -fPIC -std=c++17 $(INCLUDES) -DSHRINCS_B32 \
		-c btc_sha/sha256_arm_shani.cpp -o obj/sha256_arm_shani.o
	$(CXX) -g -Wall $(HW_FLAGS) -std=c++17 -Wno-deprecated-declarations -DSHRINCS_B32 \
		$(SRC_FILES) $(BTC_OTHER_FILES) tests/tests.cpp obj/sha256_arm_shani.o \
		$(INCLUDES) -o bin/run_tests $(TEST_FLAGS)
	./bin/run_tests

benchmark: clean
	@mkdir -p bin obj
	$(CXX) -O3 -Wall $(SHA2_FLAG) -fPIC -std=c++17 $(INCLUDES) -DSHRINCS_B32 \
		-c btc_sha/sha256_arm_shani.cpp -o obj/sha256_arm_shani.o
	$(CXX) -O3 -Wall $(HW_FLAGS) -std=c++17 -Wno-deprecated-declarations -DSHRINCS_B32 \
		$(SRC_FILES) $(BTC_OTHER_FILES) tests/bench.cpp obj/sha256_arm_shani.o \
		$(INCLUDES) -o bin/bench
	./bin/bench