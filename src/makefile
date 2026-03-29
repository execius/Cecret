CC=clang
remove=rm
DEPENDENCIES= -lsqlite3 -lssl -lcrypto
DEBFLGS=-g -Wall  -pedantic -fsanitize=thread 
OPFLGS=-O3  
PREFIX ?= /usr/local



SRC_DIR=.
INC_DIRS = $(shell find $(SRC_DIR) -type d)
INCLUDE_FLAGS = $(addprefix -I, $(INC_DIRS))


SRC_FILES = $(shell find $(SRC_DIR) -type f -name "*.c")
FILES= $(SRC_FILES) $(INCLUDE_FLAGS)

LOCK20wn :
	$(CC) $(DEPENDENCIES) $(FILES) -o $@

LOCK20wn_opt :
	$(CC) $(OPFLGS) $(DEPENDENCIES) $(FILES) -o $@
LOCK20wn_dbg :
	$(CC)  $(DEBFLGS) $(DEPENDENCIES) $(FILES) -o $@ 
clean :
	$(remove) LOCK20wn*


