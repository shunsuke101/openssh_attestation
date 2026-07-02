CC=cc
DEP_DIR=/home/ubuntu/tpm2-tools
DEP_SRC=$(DEP_DIR)/lib/*.c
CFLAGS= -I /usr/include/tss2 -I $(DEP_DIR)/lib -I $(DEP_DIR)/tools/
LDFLAGS= -lssl -lcrypto -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tctildr -ltss2-rc
TARGET=tpm2_checkquote
COPY_DIR=/home/ubuntu/.ssh
CLEAN_TARGET=certificate*

all:mytpm2_checkquote.c
	$(CC) -o $(TARGET) $? $(DEP_SRC) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(CLEAN_TARGET) $(TARGET)
copy:
	cp $(COPY_DIR)/$(CLEAN_TARGET) .
