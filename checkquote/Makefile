CC=cc
DEP_DIR=/home/ubuntu/tpm2-tools/lib
DEP_SRC=$(DEP_DIR)/*.c
CFLAGS= -I /usr/include/tss2 -I ~/tpm2-tools/lib -I ~/tpm2-tools/tools/
LDFLAGS= -Ilib -lssl -lcrypto -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tctildr -ltss2-rc
TARGET=tpm2_checkquote

all:mytpm2_checkquote.c
	$(CC) -o $(TARGET) $? $(DEP_SRC) $(CFLAGS) $(LDFLAGS)
