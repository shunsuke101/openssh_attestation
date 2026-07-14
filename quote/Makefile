
DEP_DIR=/home/ubuntu/openssh_attestation/checkquote/tpm2-tools/lib

CFLAGS= -I /usr/include/tss2 -I $(DEP_DIR)
TARGET=mytpm2_quote

LDFLAGS= -lssl -lcrypto -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tctildr -ltss2-rc
LIB=$(DEP_DIR)/libcommon.a

CLEAN_TARGET=primary.ctx nonce.bin ak.* quote.*

all:mytpm2_quote.c $(LIB)
	$(CC) -o $(TARGET) $? $(LIB) $(CFLAGS) $(LDFLAGS) 

clean:
	rm -f $(CLEAN_TARGET) $(TARGET) 
