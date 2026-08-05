CXX ?= g++
UNAME_M := $(shell uname -m)

SRC_FILES := $(wildcard src/*.cpp)

ifeq ($(UNAME_M),arm64)
    BTC_FILES    := btc_sha/sha256.cpp btc_sha/sha256_arm_shani.cpp
    HW_FLAGS     := -march=native -DENABLE_ARM_SHANI -DMAC_OSX
    SHA2_FLAG    := -march=armv8-a+sha2
else ifeq ($(UNAME_M),aarch64)
    BTC_FILES    := btc_sha/sha256.cpp btc_sha/sha256_arm_shani.cpp
    HW_FLAGS     := -march=native -DENABLE_ARM_SHANI
    SHA2_FLAG    := -march=armv8-a+sha2
else ifeq ($(UNAME_M),x86_64)
    BTC_FILES    := $(wildcard btc_sha/*.cpp)
    HW_FLAGS     := -march=native -msse4.1 -mavx2 -msha -DENABLE_SSE41 -DENABLE_AVX2 -DENABLE_X86_SHANI
    SHA2_FLAG    :=
else
    BTC_FILES    := $(wildcard btc_sha/*.cpp)
    HW_FLAGS     :=
    SHA2_FLAG    :=
endif

LIB_NAME  = libshrincs.a
SRC_DIR   = src
INC_DIR   = include
OBJ_DIR   = obj

OBJS     = $(SRC_FILES:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
BTC_OBJS = $(BTC_FILES:btc_sha/%.cpp=$(OBJ_DIR)/%.o)

# Parallelism is opt-in: without OPENMP=1 the pragmas are ignored and the
# library builds exactly as before. Build with `make OPENMP=1`.
ifeq ($(OPENMP),1)
    LIBOMP_PREFIX := $(shell brew --prefix libomp 2>/dev/null)
    ifneq ($(LIBOMP_PREFIX),)
        OMP_FLAGS := -Xpreprocessor -fopenmp -I$(LIBOMP_PREFIX)/include
        OMP_LIBS  := -L$(LIBOMP_PREFIX)/lib -lomp
    else
        OMP_FLAGS := -fopenmp
        OMP_LIBS  := -fopenmp
    endif
endif

INCLUDES := -I$(INC_DIR) -I. -Ibtc_sha
CXXFLAGS := -O3 -Wall $(HW_FLAGS) $(OMP_FLAGS) -fPIC -std=c++17 $(INCLUDES)

.PHONY: build tests benchmark clean

build: $(OBJS) $(BTC_OBJS)
	ar rcs $(LIB_NAME) $(OBJS) $(BTC_OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/sha256_arm_shani.o: btc_sha/sha256_arm_shani.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(SHA2_FLAG) -c $< -o $@

$(OBJ_DIR)/%.o: btc_sha/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME) bin/

BTC_OTHER_FILES := $(filter-out btc_sha/sha256_arm_shani.cpp, $(BTC_FILES))

BREW_PREFIX := $(shell brew --prefix 2>/dev/null)
ifneq ($(BREW_PREFIX),)
    GTEST_INCLUDES := -I$(BREW_PREFIX)/include
    GTEST_LIBS     := -L$(BREW_PREFIX)/lib
endif

TEST_FLAGS := $(GTEST_LIBS) $(OMP_LIBS) -lgtest -lpthread -fsanitize=address -fno-omit-frame-pointer
TEST_CXXFLAGS := -O2 -g -Wall $(HW_FLAGS) $(OMP_FLAGS) -std=c++17 $(INCLUDES) $(GTEST_INCLUDES) -fsanitize=address -fno-omit-frame-pointer

tests:
	@mkdir -p bin obj
	$(CXX) $(TEST_CXXFLAGS) $(SHA2_FLAG) \
		-c btc_sha/sha256_arm_shani.cpp -o obj/sha256_arm_shani_test.o
	$(CXX) $(TEST_CXXFLAGS) \
		$(SRC_FILES) $(BTC_OTHER_FILES) tests/tests.cpp obj/sha256_arm_shani_test.o \
		-o bin/run_tests $(TEST_FLAGS)
	./bin/run_tests

benchmark:
	@mkdir -p bin obj
	$(CXX) $(CXXFLAGS) $(SHA2_FLAG) \
		-c btc_sha/sha256_arm_shani.cpp -o obj/sha256_arm_shani.o
	$(CXX) $(CXXFLAGS) \
		$(SRC_FILES) $(BTC_OTHER_FILES) tests/bench.cpp obj/sha256_arm_shani.o \
		-o bin/bench $(OMP_LIBS)
	./bin/bench
