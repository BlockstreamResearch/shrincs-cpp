SRC_FILES := $(wildcard src/*.cpp)
SRC_NO_MAIN := $(filter-out src/main.cpp, $(SRC_FILES))

LIB_NAME = libshrincs.a
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

OBJS = $(SRC_NO_MAIN:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

OPENSSL_PREFIX := $(shell brew --prefix openssl)
OPENSSL_INC := -I$(OPENSSL_PREFIX)/include
OPENSSL_LIB := -L$(OPENSSL_PREFIX)/lib

CXXFLAGS := -O3 -Wall -fPIC -std=c++17 -I$(INC_DIR) $(OPENSSL_INC)
# Grouped linker flags
LDFLAGS := $(OPENSSL_LIB) -lssl -lcrypto -DSHRINCS_B32

build: $(OBJS)
	ar rcs $(LIB_NAME) $(OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	g++ $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME) bin/

TEST_FLAGS := -lgtest -lpthread -fsanitize=address -fno-omit-frame-pointer
test: clean
	mkdir -p bin
	g++ -g -Wall -std=c++17 -Wno-deprecated-declarations $(SRC_NO_MAIN) tests/tests.cpp -I include $(OPENSSL_INC) -o bin/run_tests $(TEST_FLAGS) $(LDFLAGS)
	./bin/run_tests

benchmark: clean
	mkdir -p bin
	g++ -O3 -Wall -std=c++17 -Wno-deprecated-declarations $(SRC_NO_MAIN) tests/bench.cpp -I include $(OPENSSL_INC) -o bin/bench $(LDFLAGS)
	./bin/bench