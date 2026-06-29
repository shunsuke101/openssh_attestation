CC=cc
CFLAGS= -I /usr/include/tss2 -I ~/tpm2-tools/lib -I ~/tpm2-tools/tools/
LDFLAGS= -Ilib -lssl -lcrypto -ltss2-esys -ltss2-mu -ltss2-tctildr  -ltss2-sys -ltss2-rc
TARGET=check_quote

all:mytpm2_checkquote.c
	$(CC) -o $(TARGET) mytpm2_checkquote.c ~/tpm2-tools/lib/*.c $(CFLAGS) $(LDFLAGS)
