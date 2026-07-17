CC=cc

DEP_DIR=/home/ubuntu/openssh_attestation/checkquote/tpm2-tools/lib
COPY_DIR=/home/ubuntu/.ssh

DEP_SRC=$(wildcard $(DEP_DIR)/*.c)
FINAL_OBJS=$(DEP_SRC:.c=.o)

CFLAGS= -I /usr/include/tss2 -I $(DEP_DIR)
LDFLAGS= -lssl -lcrypto -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tctildr -ltss2-rc

TARGET=mytpm2_checkquote
CLEAN_TARGET=certificate*

TPM2TOOLS_LIBS=$(DEP_DIR)/libcommon.a

all:mytpm2_checkquote.c $(TPM2TOOLS_LIBS) 
	$(CC) -o $(TARGET) $? $(CFLAGS) $(LDFLAGS)

$(TPM2TOOLS_LIBS): $(FINAL_OBJS)
	$(AR) crv $@ $(FINAL_OBJS)

$(DIP_DIR)/%.o:$(DEP_DIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS) 

clean:
	rm -f $(CLEAN_TARGET) $(TARGET) $(FINAL_OBJS)

copy:
	cp $(COPY_DIR)/$(CLEAN_TARGET) .
