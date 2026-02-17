SRC_FILES := $(wildcard src/*.cpp)
SRC_NO_MAIN := $(filter-out src/main.cpp, $(SRC_FILES))

LIB_NAME = libshrincs.a
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

OBJS = $(SRC_NO_MAIN:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)

build: $(OBJS)
	ar rcs $(LIB_NAME) $(OBJS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	g++ -O3 -Wall -fPIC -I$(INC_DIR) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME)

TEST_FLAGS := -lgtest -lpthread -fsanitize=address -fno-omit-frame-pointer
test:
	mkdir -p bin
	g++ -g -Wall -Wno-deprecated-declarations $(SRC_NO_MAIN) tests/tests.cpp -I include -o bin/run_tests $(TEST_FLAGS) -lssl -lcrypto
	./bin/run_tests

BENCH_FLAGS := -lgtest -lpthread
benchmark:
	mkdir -p bin
	g++ -O3 -Wall -Wno-deprecated-declarations $(SRC_NO_MAIN) tests/bench.cpp -I include -o bin/bench $(BENCH_FLAGS) -lssl -lcrypto
	./bin/bench