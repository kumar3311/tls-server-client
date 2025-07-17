# Compiler
CXX = g++ 

# Compiler flags

CXXFLAGS = -g -std=c++2a -lssl -lcrypto -o

CPP_FILES = $(wildcard *.cpp)

EXECUTABLES = $(CPP_FILES:.cpp=)

all: $(EXECUTABLES)

%: %.cpp
	$(CXX) $(INCLUDE_DIRS) $(CXXFLAGS) $@ $<

clean:
	rm -f $(EXECUTABLES)
