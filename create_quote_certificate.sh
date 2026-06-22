
SSH_DIR=$HOME/.ssh

tpm2_createprimary -C o -c primary.ctx -G rsa2048 -g sha256
tpm2_create -C primary.ctx -u ak.pub -r ak.priv -G ecc:ecdsa:null -g sha256 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx
openssl rand -out nonce.bin 20
tpm2_quote -c ak.ctx -l sha256:0,1,2,4 -q nonce.bin -m quote.msg -s quote.sig -o quote.pcrs -F values

base64 -w0 quote.msg > quote_msg.b64
base64 -d quote_msg.b64 > encoded_quote.msg
base64 -w0 quote.sig > quote_sig.b64
base64 -d quote_sig.b64 > encoded_quote.sig
base64 -w0 nonce.bin > nonce_bin.b64
base64 -d nonce_bin.b64 > encoded_nonce.bin

ssh-keygen -s $SSH_DIR/ca.key -I certificate_test -n ubuntu -z 1 \
	-O extension:quote_msg.b64="$(cat ./quote_msg.b64)"\
	-O extension:quote_sig.b64="$(cat ./quote_sig.b64)"\
	-O extension:nonce_bin.b64="$(cat ./nonce_bin.b64)"\
	$SSH_DIR/test_cert.pub
