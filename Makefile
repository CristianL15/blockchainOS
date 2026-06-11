CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=gnu11 -g
LDFLAGS = -lssl -lcrypto -lcurl -lpthread -lm
RM = rm -f

SRC_DIR = src
OBJ_DIR = obj
BIN = auditor

SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/capture.c $(SRC_DIR)/proc_monitor.c \
       $(SRC_DIR)/queue.c $(SRC_DIR)/http_client.c $(SRC_DIR)/log_local.c \
       $(SRC_DIR)/event.c $(SRC_DIR)/crypto.c $(SRC_DIR)/utils.c $(SRC_DIR)/daemonize.c

HAS_AUDIT := $(shell pkg-config --exists audit 2>/dev/null && echo 1 || echo 0)

ifeq ($(HAS_AUDIT), 1)
    SRCS += $(SRC_DIR)/audit_monitor.c
    CFLAGS += $(shell pkg-config --cflags audit 2>/dev/null || echo "")
    LDFLAGS += -laudit
endif

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: src clean gateway chaincode distclean test full

src: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(BIN)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

gateway:
	@echo "Installing Gateway dependencies..."
	cd gateway && npm install
	@echo "Gateway ready: cd gateway && npm start"

chaincode:
	@echo "Installing Chaincode dependencies..."
	cd chaincode && npm install
	@echo "Chaincode ready"

full: src gateway chaincode

clean:
	$(RM) -r $(OBJ_DIR) $(BIN)

distclean: clean
	$(RM) -rf gateway/node_modules chaincode/node_modules

test: $(BIN)
	@echo "Building test suite..."
	$(CC) $(CFLAGS) -o $(OBJ_DIR)/test_blockchain \
		tests/test_blockchain.c \
		$(SRC_DIR)/event.c $(SRC_DIR)/crypto.c $(SRC_DIR)/utils.c \
		$(SRC_DIR)/capture.c \
		-lssl -lcrypto -lm -lpthread
	@echo "Running tests..."
	$(OBJ_DIR)/test_blockchain
