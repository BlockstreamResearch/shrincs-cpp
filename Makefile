CXX ?= g++
SRC_FILES := $(wildcard src/*.cpp)
BTC_FILES := $(wildcard btc_sha/*.cpp)

HW_FLAGS := -march=native -msse4.1 -mavx2 -msha -DENABLE_SSE41 -DENABLE_AVX2 -DENABLE_SHANI

LIB_NAME = libshrincs.a
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

OBJS = $(SRC_FILES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
BTC_OBJS = $(BTC_FILES:btc_sha/%.cpp=$(OBJ_DIR)/%.o)

UNAME_S := $(shell uname -s)

CXXFLAGS := -O3 -Wall $(HW_FLAGS) -fPIC -std=c++17 -I$(INC_DIR) -I. -Ibtc_sha -DSHRINCS_B32

build: $(OBJS) $(BTC_OBJS)
	ar rcs $(LIB_NAME) $(OBJS) $(BTC_OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: btc_sha/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME) bin/

TEST_FLAGS := -lgtest -lpthread -fsanitize=address -fno-omit-frame-pointer

test: clean
	mkdir -p bin
	$(CXX) -g -Wall $(HW_FLAGS) -std=c++17 -Wno-deprecated-declarations -DSHRINCS_B32 \
		$(SRC_FILES) $(BTC_FILES) tests/tests.cpp -I$(INC_DIR) -I. -Ibtc_sha \
		-o bin/run_tests $(TEST_FLAGS)
	./bin/run_tests

benchmark: clean
	mkdir -p bin
	$(CXX) -O3 -Wall $(HW_FLAGS) -std=c++17 -Wno-deprecated-declarations -DSHRINCS_B32 \
		$(SRC_FILES) $(BTC_FILES) tests/bench.cpp -I$(INC_DIR) -I. -Ibtc_sha \
		-o bin/bench
	./bin/bench