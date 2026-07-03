CC=cc

DEP_DIR=/home/ubuntu/openssh_attestation/checkquote/tpm2-tools/lib
COPY_DIR=/home/ubuntu/.ssh

DEP_SRC=$(wildcard $(DEP_DIR)/*.c)
FINAL_OBJS=$(DEP_SRC:.c=.o)

CFLAGS= -I /usr/include/tss2 -I $(DEP_DIR)
LDFLAGS= -lssl -lcrypto -ltss2-esys -ltss2-sys -ltss2-mu -ltss2-tctildr -ltss2-rc

TARGET=tpm2_checkquote
CLEAN_TARGET=certificate*

all:mytpm2_checkquote.c $(FINAL_OBJS)
	$(CC) -o $(TARGET) $? $(CFLAGS) $(LDFLAGS)

$(DEP_DIR)/%.o:$(DIP_DIR)/%.c
	$(CC) -c -o $@ $< $(CFALGS)
clean:
	rm -f $(CLEAN_TARGET) $(TARGET) $(FINAL_OBJS)

copy:
	cp $(COPY_DIR)/$(CLEAN_TARGET) .
