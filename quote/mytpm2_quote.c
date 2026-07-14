/* SPDX-License-Identifier: BSD-3-Clause */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <tss2/tss2_tctildr.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_convert.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"
#include "tpm2_systemdeps.h"
#include "tpm2_tool_output.h"

#define MAX_SESSIONS 3

/* ------------------------------------------------------------------ *
 * context
 * ------------------------------------------------------------------ */

typedef struct tpm_quote_ctx tpm_quote_ctx;
struct tpm_quote_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    bool restricted_pwd_session;

    tpm2_convert_sig_fmt sig_format;
    TPMI_ALG_HASH sig_hash_algorithm;
    TPM2B_DATA qualification_data;
    TPML_PCR_SELECTION pcr_selections;
    TPMS_CAPABILITY_DATA cap_data;
    tpm2_pcrs pcrs;
    tpm2_convert_pcrs_output_fmt pcrs_format;
    TPMT_SIG_SCHEME in_scheme;
    TPMI_ALG_SIG_SCHEME sig_scheme;

    /*
     * Outputs
     */
    FILE *pcr_output;
    char *pcr_path;
    char *signature_path;
    char *message_path;
    TPMS_ATTEST attest;
    TPM2B_ATTEST *quoted;
    TPMT_SIGNATURE *signature;

    /*
     * Parameter hashes
     */
    const char *cp_hash_path;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;
    TPMI_ALG_HASH parameter_hash_algorithm;
};

static tpm_quote_ctx ctx = {
    .sig_hash_algorithm = TPM2_ALG_NULL,
    .qualification_data = TPM2B_EMPTY_INIT,
    .pcrs_format = pcrs_output_format_serialized,
    .in_scheme.scheme = TPM2_ALG_NULL,
    .sig_scheme = TPM2_ALG_NULL,
    .parameter_hash_algorithm = TPM2_ALG_ERROR,
};

/* ------------------------------------------------------------------ *
 * quote
 * ------------------------------------------------------------------ */

static tool_rc quote(ESYS_CONTEXT *ectx)
{
    return tpm2_quote(ectx, &ctx.key.object, &ctx.in_scheme,
        &ctx.qualification_data, &ctx.pcr_selections, &ctx.quoted,
        &ctx.signature, &ctx.cp_hash, ctx.parameter_hash_algorithm);
}

/* ------------------------------------------------------------------ *
 * write_output_files
 * ------------------------------------------------------------------ */

static tool_rc write_output_files(void)
{
    bool is_file_op_success = true;
    bool result = true;

    if (ctx.signature_path) {
        result = tpm2_convert_sig_save(ctx.signature, ctx.sig_format,
            ctx.signature_path);
        if (!result) {
            is_file_op_success = result;
        }
    }

    if (ctx.message_path) {
        result = files_save_bytes_to_file(ctx.message_path,
            (UINT8*) &ctx.quoted->attestationData, ctx.quoted->size);
        if (!result) {
            is_file_op_success = result;
        }
    }

    if (ctx.pcr_output) {
        if (ctx.pcrs_format == pcrs_output_format_serialized) {
            result = pcr_fwrite_serialized(&ctx.pcr_selections, &ctx.pcrs,
                ctx.pcr_output);
            if (!result) {
                is_file_op_success = result;
            }
        } else if (ctx.pcrs_format == pcrs_output_format_values) {
            result = pcr_fwrite_values(&ctx.pcr_selections, &ctx.pcrs,
                ctx.pcr_output);
            if (!result) {
                is_file_op_success = result;
            }
        } else if (ctx.pcrs_format == pcrs_output_format_marshaled) {
            result = pcr_fwrite_marshaled(&ctx.pcr_selections, &ctx.pcrs,
               ctx.pcr_output);
            if (!result) {
                is_file_op_success = result;
            }
        }
    }

    return is_file_op_success ? tool_rc_success : tool_rc_general_error;
}

/* ------------------------------------------------------------------ *
 * process_output
 * ------------------------------------------------------------------ */

static tool_rc process_output(ESYS_CONTEXT *ectx)
{
    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    tpm2_tool_output("quoted: ");
    tpm2_util_print_tpm2b(ctx.quoted);
    tpm2_tool_output("\nsignature:\n");
    tpm2_tool_output("  alg: %s\n", tpm2_alg_util_algtostr(
        ctx.signature->sigAlg, tpm2_alg_util_flags_sig));

    UINT16 size;
    BYTE *sig = tpm2_convert_sig(&size, ctx.signature);
    if (!sig) {
        return tool_rc_general_error;
    }
    tpm2_tool_output("  sig: ");
    tpm2_util_hexdump(sig, size);
    tpm2_tool_output("\n");
    free(sig);

    if (ctx.pcr_output) {
        /* Filter out invalid/unavailable PCR selections */
        if (!pcr_check_pcr_selection(&ctx.cap_data, &ctx.pcr_selections)) {
            LOG_ERR("Failed to filter unavailable PCR values for quote!");
            return tool_rc_general_error;
        }

        /* Gather PCR values from the TPM (the quote doesn't have them!) */
        rc = pcr_read_pcr_values(ectx, &ctx.pcr_selections, &ctx.pcrs,
             NULL, TPM2_ALG_ERROR, ESYS_TR_NONE,
             ESYS_TR_NONE, ESYS_TR_NONE);
        if (rc != tool_rc_success) {
            LOG_ERR("Failed to retrieve PCR values related to quote!");
            return rc;
        }

        /* Grab the digest from the quote */
        rc = files_tpm2b_attest_to_tpms_attest(ctx.quoted, &ctx.attest);
        if (rc != tool_rc_success) {
            return rc;
        }

        /* Print out PCR values as output */
        bool is_pcr_print_successful = pcr_print_pcr_struct(&ctx.pcr_selections,
            &ctx.pcrs);
        if (!is_pcr_print_successful) {
            LOG_ERR("Failed to print PCR values related to quote!");
            return tool_rc_general_error;
        }

        /* Calculate the digest from our selected PCR values (to ensure correctness) */
        TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
        bool is_pcr_hashing_success = tpm2_openssl_hash_pcr_banks(
            ctx.sig_hash_algorithm, &ctx.pcr_selections, &ctx.pcrs,
            &pcr_digest);
        if (!is_pcr_hashing_success) {
            LOG_ERR("Failed to hash PCR values related to quote!");
            return tool_rc_general_error;
        }
        tpm2_tool_output("calcDigest: ");
        tpm2_util_hexdump(pcr_digest.buffer, pcr_digest.size);
        tpm2_tool_output("\n");

        /* Make sure digest from quote matches calculated PCR digest */
        bool is_pcr_digests_equal = tpm2_util_verify_digests(
            &ctx.attest.attested.quote.pcrDigest, &pcr_digest);
        if (!is_pcr_digests_equal) {
            LOG_ERR("Error validating calculated PCR composite with quote");
            return tool_rc_general_error;
        }
    }

    /* Write everything out */
    return write_output_files();
}

/* ------------------------------------------------------------------ *
 * process_inputs
 * ------------------------------------------------------------------ */

static tool_rc process_inputs(ESYS_CONTEXT *ectx)
{
    /*
     * 1. Object and auth initializations
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
            ctx.key.auth_str, &ctx.key.object, ctx.restricted_pwd_session,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid key authorization");
        return rc;
    }

    /*
     * 2. Command specific initializations
     */
    if (ctx.pcr_path) {
        ctx.pcr_output = fopen(ctx.pcr_path, "wb+");
        if (!ctx.pcr_output) {
            LOG_ERR("Could not open PCR output file \"%s\" error: \"%s\"",
                    ctx.pcr_path, strerror(errno));
            return tool_rc_general_error;
        }
    }

    tpm2_algorithm algs;
    rc = pcr_get_banks(ectx, &ctx.cap_data, &algs);
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_alg_util_get_signature_scheme(ectx, ctx.key.object.tr_handle,
        &ctx.sig_hash_algorithm, ctx.sig_scheme, &ctx.in_scheme);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. Configuration for calculating the pHash
     */
    tpm2_session *all_sessions[MAX_SESSIONS] = {
        ctx.key.object.session,
        0,
        0
    };

    const char **cphash_path = ctx.cp_hash_path ? &ctx.cp_hash_path : 0;

    ctx.parameter_hash_algorithm = tpm2_util_calculate_phash_algorithm(ectx,
        cphash_path, &ctx.cp_hash, 0, 0, all_sessions);

    ctx.is_command_dispatch = ctx.cp_hash_path ? false : true;

    return rc;
}

/* ------------------------------------------------------------------ *
 * check_options
 * ------------------------------------------------------------------ */

static tool_rc check_options(void)
{
    if (!ctx.key.ctx_path) {
        LOG_ERR("Expected -c to be specified.");
        return tool_rc_option_error;
    }

    if (!ctx.pcr_selections.count) {
        LOG_ERR("Expected -l to be specified.");
        return tool_rc_option_error;
    }

    if (ctx.cp_hash_path && (ctx.signature_path || ctx.message_path)) {
        LOG_ERR("Cannot produce output when calculating cpHash");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

/* ------------------------------------------------------------------ *
 * print_usage
 * ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -c <key.ctx> -l <pcr-list> [options]\n"
        "\n"
        "Required:\n"
        "  -c, --key-context     <file>  署名鍵のコンテキストファイル\n"
        "  -l, --pcr-list        <str>   PCR選択 (例: sha256:0,1,2)\n"
        "\n"
        "Optional:\n"
        "  -p, --auth            <str>   鍵の認証値\n"
        "  -q, --qualification   <hex>   nonce (16進数またはファイル)\n"
        "  -s, --signature       <file>  署名の出力先\n"
        "  -m, --message         <file>  attestationメッセージの出力先\n"
        "  -o, --pcr             <file>  PCR値の出力先\n"
        "  -F, --pcrs_format     <fmt>   PCR出力形式 (serialized|values|marshaled)\n"
        "  -f, --format          <fmt>   署名フォーマット\n"
        "  -g, --hash-algorithm  <alg>   署名ハッシュアルゴリズム\n"
        "      --cphash          <file>  cpHashの出力先\n"
        "      --scheme          <alg>   署名スキーム\n"
        "  -v, --verbose                 詳細ログ\n"
        "  -h, --help                    このヘルプ\n"
        "\n", prog);
}

/* ------------------------------------------------------------------ *
 * main
 * ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    umask(0117);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    static const struct option long_opts[] = {
        { "key-context",    required_argument, NULL, 'c' },
        { "auth",           required_argument, NULL, 'p' },
        { "pcr-list",       required_argument, NULL, 'l' },
        { "qualification",  required_argument, NULL, 'q' },
        { "signature",      required_argument, NULL, 's' },
        { "message",        required_argument, NULL, 'm' },
        { "pcr",            required_argument, NULL, 'o' },
        { "pcrs_format",    required_argument, NULL, 'F' },
        { "format",         required_argument, NULL, 'f' },
        { "hash-algorithm", required_argument, NULL, 'g' },
        { "cphash",         required_argument, NULL,  0  },
        { "scheme",         required_argument, NULL,  1  },
        { "verbose",        no_argument,       NULL, 'v' },
        { "help",           no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:l:q:s:m:o:F:f:g:vh",
            long_opts, NULL)) != -1) {
        switch (opt) {
        case 'v':
            log_set_level(log_level_verbose);
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'c':
            ctx.key.ctx_path = optarg;
            break;
        case 'p':
            ctx.key.auth_str = optarg;
            break;
        case 'l':
            if (!pcr_parse_selections(optarg, &ctx.pcr_selections, NULL)) {
                LOG_ERR("Could not parse pcr selections, got: \"%s\"", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'q':
            ctx.qualification_data.size = sizeof(ctx.qualification_data.buffer);
            if (!tpm2_util_bin_from_hex_or_file(optarg,
                    &ctx.qualification_data.size, ctx.qualification_data.buffer)) {
                return EXIT_FAILURE;
            }
            break;
        case 's':
            ctx.signature_path = optarg;
            break;
        case 'm':
            ctx.message_path = optarg;
            break;
        case 'o':
            ctx.pcr_path = optarg;
            break;
        case 'F':
            ctx.pcrs_format = tpm2_convert_pcrs_output_fmt_from_optarg(optarg);
            if (ctx.pcrs_format == pcrs_output_format_err) {
                return EXIT_FAILURE;
            }
            break;
        case 'f':
            ctx.sig_format = tpm2_convert_sig_fmt_from_optarg(optarg);
            if (ctx.sig_format == signature_format_err) {
                return EXIT_FAILURE;
            }
            break;
        case 'g':
            ctx.sig_hash_algorithm = tpm2_alg_util_from_optarg(optarg,
                    tpm2_alg_util_flags_hash);
            if (ctx.sig_hash_algorithm == TPM2_ALG_ERROR) {
                LOG_ERR("Could not convert signature hash algorithm selection, "
                        "got: \"%s\"", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 0:
            ctx.cp_hash_path = optarg;
            break;
        case 1:
            ctx.sig_scheme = tpm2_alg_util_from_optarg(optarg,
                    tpm2_alg_util_flags_sig);
            if (ctx.sig_scheme == TPM2_ALG_ERROR) {
                LOG_ERR("Unknown signing scheme, got: \"%s\"", optarg);
                return EXIT_FAILURE;
            }
            break;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        if (rc == tool_rc_option_error) {
            print_usage(argv[0]);
        }
        return (int) rc;
    }

    /*
     * TCTI / ESYS setup (normally handled by tpm2_tool.c's dispatcher;
     * done here directly since this is a standalone binary).
     */
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_RC trc = Tss2_TctiLdr_Initialize(NULL, &tcti);
    if (trc != TSS2_RC_SUCCESS) {
        LOG_PERR(Tss2_TctiLdr_Initialize, trc);
        return (int) tool_rc_tcti_error;
    }

    ESYS_CONTEXT *ectx = NULL;
    trc = Esys_Initialize(&ectx, tcti, NULL);
    if (trc != TPM2_RC_SUCCESS) {
        LOG_PERR(Esys_Initialize, trc);
        Tss2_TctiLdr_Finalize(&tcti);
        return (int) tool_rc_tcti_error;
    }

    tool_rc return_value = tool_rc_general_error;

    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return_value = rc;
        goto out;
    }

    rc = quote(ectx);
    if (rc != tool_rc_success) {
        return_value = rc;
        goto out;
    }

    return_value = process_output(ectx);

out:
    /*
     * Cleanup
     */
    if (ctx.pcr_output) {
        fclose(ctx.pcr_output);
    }

    free(ctx.quoted);
    free(ctx.signature);

    tpm2_session_close(&ctx.key.object.session);

    Esys_Finalize(&ectx);
    Tss2_TctiLdr_Finalize(&tcti);

    if (return_value == tool_rc_option_error) {
        print_usage(argv[0]);
    }

    return (int) return_value;
}
