/*
 *certificateの情報を表示するプログラムを書く
 *
 *
 *
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include<pwd.h>
#include"includes.h"
#include "sshkey.h"

/* The identity file name, given on the command line or entered by the user. */
static char identity_file[PATH_MAX];
static int have_identity = 0;

static void print_cert(struct sshkey *key)
{
	char valid[64], *key_fp, *ca_fp;
	u_int i;

	key_fp = sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
	ca_fp = sshkey_fingerprint(key->cert->signature_key,
	    fingerprint_hash, SSH_FP_DEFAULT);
	if (key_fp == NULL || ca_fp == NULL)
		fatal_f("sshkey_fingerprint fail");
	sshkey_format_cert_validity(key->cert, valid, sizeof(valid));

	printf("        Type: %s %s certificate\n", sshkey_ssh_name(key),
	    sshkey_cert_type(key));
	printf("        Public key: %s %s\n", sshkey_type(key), key_fp);
	printf("        Signing CA: %s %s (using %s)\n",
	    sshkey_type(key->cert->signature_key), ca_fp,
	    key->cert->signature_type);
	printf("        Key ID: \"%s\"\n", key->cert->key_id);
	printf("        Serial: %llu\n", (unsigned long long)key->cert->serial);
	printf("        Valid: %s\n", valid);
	printf("        Principals: ");
	if (key->cert->nprincipals == 0)
		printf("(none)\n");
	else {
		for (i = 0; i < key->cert->nprincipals; i++)
			printf("\n                %s",
			    key->cert->principals[i]);
		printf("\n");
	}
	printf("        Critical Options: ");
	if (sshbuf_len(key->cert->critical) == 0)
		printf("(none)\n");
	else {
		printf("\n");
		show_options(key->cert->critical, 1);
	}
	printf("        Extensions: ");
	if (sshbuf_len(key->cert->extensions) == 0)
		printf("(none)\n");
	else {
		printf("\n");
		show_options(key->cert->extensions, 0);
	}
}

/*
 *-L のoptionが追加された時に、実行される、これはcertificateを出力する関数である
 *sshkey.c:sshkey_new(),ssh_read(),ssh_is_cert()
 * ssh-keygen.c:cert_print(),ask_filename()
 * 
 * */



static void
ask_filename(struct passwd *pw, const char *prompt)
{
	char buf[1024];
	char *name = NULL;

	if (key_type_name == NULL)
		name = _PATH_SSH_CLIENT_ID_ED25519;
	else {
		switch (sshkey_type_from_shortname(key_type_name)) {
#ifdef OPENSSL_HAS_ECC
		case KEY_ECDSA_CERT:
		case KEY_ECDSA:
			name = _PATH_SSH_CLIENT_ID_ECDSA;
			break;
		case KEY_ECDSA_SK_CERT:
		case KEY_ECDSA_SK:
			name = _PATH_SSH_CLIENT_ID_ECDSA_SK;
			break;
#endif
		case KEY_RSA_CERT:
		case KEY_RSA:
			name = _PATH_SSH_CLIENT_ID_RSA;
			break;
		case KEY_ED25519:
		case KEY_ED25519_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519;
			break;
		case KEY_ED25519_SK:
		case KEY_ED25519_SK_CERT:
			name = _PATH_SSH_CLIENT_ID_ED25519_SK;
			break;
		default:
			fatal("bad key type");
		}
	}
	snprintf(identity_file, sizeof(identity_file),
	    "%s/%s", pw->pw_dir, name);
	printf("%s (%s): ", prompt, identity_file);
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
		exit(1);
	buf[strcspn(buf, "\n")] = '\0';
	if (strcmp(buf, "") != 0)
		strlcpy(identity_file, buf, sizeof(identity_file));
	have_identity = 1;
}

static void do_show_cert(struct passwd *pw)
{
        struct sshkey *key = NULL;
        struct stat st;
        int r, is_stdin = 0, ok = 0;
        FILE *f;
        char *cp, *line = NULL;
        const char *path;
        size_t linesize = 0;
        u_long lnum = 0;

        if (!have_identity)
                ask_filename(pw, "Enter file in which the key is");
        if (strcmp(identity_file, "-") != 0 && stat(identity_file, &st) == -1)
                fatal("%s: %s: %s", __progname, identity_file, strerror(errno));
        } else if ((f = fopen(identity_file, "r")) == NULL)
                fatal("fopen %s: %s", identity_file, strerror(errno));

        while (getline(&line, &linesize, f) != -1) {
                lnum++;
                sshkey_free(key);
                key = NULL;
                /* Trim leading space and comments */
                cp = line + strspn(line, " \t");
                if (*cp == '#' || *cp == '\0')
                        continue;
                if ((key = sshkey_new(KEY_UNSPEC)) == NULL)
                        fatal("sshkey_new");
                if ((r = sshkey_read(key, &cp)) != 0) {
                        error_r(r, "%s:%lu: invalid key", path, lnum);
                        continue;
                }
                if (!sshkey_is_cert(key)) {
                        error("%s:%lu is not a certificate", path, lnum);
                        continue;
                }
                ok = 1;
                if (!is_stdin && lnum == 1)
                        printf("%s:\n", path);
                else
                        printf("%s:%lu:\n", path, lnum);
                print_cert(key);
        }
        free(line);
        sshkey_free(key);
        fclose(f);
        exit(ok ? 0 : 1);
}



int main(int argc,char *argv[])
{
#if 0
	struct passwd *pw;

	/* we need this for the home * directory.  */
        pw = getpwuid(getuid());
        if (!pw)
                fatal("No user exists for uid %lu", (u_long)getuid());
        pw = pwcopy(pw);
        if (gethostname(hostname, sizeof(hostname)) == -1)
                fatal("gethostname: %s", strerror(errno));

        sk_provider = getenv("SSH_SK_PROVIDER");
#endif

	int opt;
	int flag;
	extern char *optarg;

	while((opt=getopt(argc,argv,"Lt:"))!=-1){
		switch(opt){
			case 'L':
				/*flag=1;
				printf("flag1がっ立った\n");*/
				do_show_cert(pw);
				break;
			case 'f':
				if (strlcpy(identity_file, optarg,sizeof(identity_file)) >= sizeof(identity_file))
                                fatal("Identity filename too long");
                        	have_identity = 1;
				/*printf("inputfilename=%s\n",optarg);*/
				break;
		}
	}


	return 0;
}
