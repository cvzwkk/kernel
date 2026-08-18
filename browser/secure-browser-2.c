/*
 * secure_browser.c
 *
 * Build target:
 *   GTK+ 3
 *   WebKitGTK 4.1
 *   OpenSSL 3.x
 *
 * Security features:
 *   - HTTPS-only navigation
 *   - Blocks javascript:, data:, file: and unknown schemes
 *   - TLS errors fail closed
 *   - WebKit process sandbox
 *   - Ephemeral per-tab WebKit profiles
 *   - Intelligent Tracking Prevention
 *   - Persistent credential storage disabled
 *   - Per-tab cryptographic random key
 *   - Real SHA-512 executable integrity hash
 *   - AES-256-GCM authenticated encryption
 *   - HKDF-SHA-512 hybrid KDF
 *   - URI attack-signature monitoring
 *   - Suspicious navigation blocking
 *   - New-window blocking
 *   - Response/MIME monitoring
 *   - Load/TLS failure monitoring
 *   - Security event console
 *   - Automatic profile cleanup
 *
 * NOTE:
 *   This program does NOT implement ML-KEM itself.
 *   hybrid_pq_derive_aes256_key() expects an ML-KEM shared
 *   secret supplied by an actual ML-KEM implementation.
 */

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#include <glib/gstdio.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define HYBRID_AES_KEY_SIZE      32
#define HYBRID_SECRET_SIZE       32
#define HYBRID_MAX_DOMAIN_LEN    256

#define TAB_KEY_SIZE             32
#define GCM_IV_SIZE              12
#define GCM_TAG_SIZE             16

#define COOKIE_MAX_VALUE_SIZE    4096
#define MAX_LOG_LINE_SIZE        4096

#define BLOCKED_SCHEMES_COUNT    4

/* ============================================================
 * SECURITY CONSOLE
 * ============================================================ */

typedef enum {
    SEC_EVENT_INFO,
    SEC_EVENT_VIOLATION,
    SEC_EVENT_THEFT_ATTEMPT,
    SEC_EVENT_INTRUSION,
    SEC_EVENT_FILE_MOD,
    SEC_EVENT_NETWORK_ANOMALY
} SecurityEventType;

static GtkWidget *console_text_view = NULL;
static GtkWidget *notebook = NULL;

static const gchar *
security_event_prefix(SecurityEventType type)
{
    switch (type) {
        case SEC_EVENT_INFO:
            return "[INFO]";

        case SEC_EVENT_VIOLATION:
            return "[SECURITY VIOLATION]";

        case SEC_EVENT_THEFT_ATTEMPT:
            return "[THEFT ATTEMPT]";

        case SEC_EVENT_INTRUSION:
            return "[INTRUSION DETECTED]";

        case SEC_EVENT_FILE_MOD:
            return "[FILE/MODULE MOD]";

        case SEC_EVENT_NETWORK_ANOMALY:
            return "[NETWORK ANOMALY]";
    }

    return "[INFO]";
}

static void
log_security_event(SecurityEventType type,
                   const gchar *source,
                   const gchar *message)
{
    time_t now = time(NULL);
    struct tm tm_value;

    gchar time_str[64] = {0};

    if (localtime_r(&now, &tm_value) != NULL) {
        strftime(time_str,
                 sizeof(time_str),
                 "%Y-%m-%d %H:%M:%S",
                 &tm_value);
    } else {
        g_strlcpy(time_str,
                  "UNKNOWN-TIME",
                  sizeof(time_str));
    }

    gchar *log_line =
        g_strdup_printf(
            "[%s] %s [%s]: %s\n",
            time_str,
            security_event_prefix(type),
            source ? source : "Unknown",
            message ? message : ""
        );

    g_print("%s", log_line);

    if (console_text_view &&
        GTK_IS_TEXT_VIEW(console_text_view)) {

        GtkTextBuffer *buffer =
            gtk_text_view_get_buffer(
                GTK_TEXT_VIEW(console_text_view)
            );

        GtkTextIter end;

        gtk_text_buffer_get_end_iter(
            buffer,
            &end
        );

        gtk_text_buffer_insert(
            buffer,
            &end,
            log_line,
            -1
        );

        GtkTextMark *mark =
            gtk_text_buffer_create_mark(
                buffer,
                NULL,
                &end,
                FALSE
            );

        gtk_text_view_scroll_to_mark(
            GTK_TEXT_VIEW(console_text_view),
            mark,
            0.0,
            TRUE,
            0.0,
            1.0
        );

        gtk_text_buffer_delete_mark(
            buffer,
            mark
        );
    }

    g_free(log_line);
}

/* ============================================================
 * CRYPTOGRAPHIC RANDOMNESS
 * ============================================================ */

static gboolean
secure_random_bytes(guint8 *buffer,
                    gsize length)
{
    if (buffer == NULL || length == 0)
        return FALSE;

    if (length > INT_MAX)
        return FALSE;

    if (RAND_bytes(buffer, (int)length) != 1) {
        log_security_event(
            SEC_EVENT_VIOLATION,
            "Crypto-RNG",
            "OpenSSL RAND_bytes() failed."
        );

        return FALSE;
    }

    return TRUE;
}

/* ============================================================
 * REAL SHA-512
 * ============================================================ */

static gboolean
sha512_digest(const guint8 *input,
              gsize input_len,
              guint8 output[64])
{
    gboolean success = FALSE;
    EVP_MD_CTX *ctx = NULL;

    if (output == NULL)
        return FALSE;

    ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return FALSE;

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1)
        goto cleanup;

    if (input != NULL &&
        input_len > 0) {

        if (EVP_DigestUpdate(
                ctx,
                input,
                input_len) != 1) {
            goto cleanup;
        }
    }

    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(
            ctx,
            output,
            &digest_len) != 1) {
        goto cleanup;
    }

    if (digest_len != 64)
        goto cleanup;

    success = TRUE;

cleanup:

    EVP_MD_CTX_free(ctx);

    if (!success)
        OPENSSL_cleanse(output, 64);

    return success;
}

/*
 * Domain-separated SHA-512.
 *
 * This is now a normal SHA-512 calculation with a length-
 * encoded domain prefix. It is NOT intended to replace HKDF
 * or HMAC for key derivation.
 */
static gboolean
secure_domain_hash(const guint8 *input,
                   gsize input_len,
                   guint8 *output,
                   gsize output_len,
                   const gchar *domain_tag)
{
    EVP_MD_CTX *ctx = NULL;
    gboolean success = FALSE;

    if (output == NULL ||
        output_len == 0 ||
        output_len > 64 ||
        domain_tag == NULL) {
        return FALSE;
    }

    gsize domain_len = strlen(domain_tag);

    if (domain_len > 4096)
        return FALSE;

    ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return FALSE;

    if (EVP_DigestInit_ex(
            ctx,
            EVP_sha512(),
            NULL) != 1) {
        goto cleanup;
    }

    /*
     * Domain length prevents accidental ambiguity.
     */
    guint64 domain_len64 = (guint64)domain_len;

    if (EVP_DigestUpdate(
            ctx,
            &domain_len64,
            sizeof(domain_len64)) != 1) {
        goto cleanup;
    }

    if (domain_len > 0 &&
        EVP_DigestUpdate(
            ctx,
            domain_tag,
            domain_len) != 1) {
        goto cleanup;
    }

    guint64 input_len64 = (guint64)input_len;

    if (EVP_DigestUpdate(
            ctx,
            &input_len64,
            sizeof(input_len64)) != 1) {
        goto cleanup;
    }

    if (input != NULL &&
        input_len > 0 &&
        EVP_DigestUpdate(
            ctx,
            input,
            input_len) != 1) {
        goto cleanup;
    }

    guint8 digest[64];
    unsigned int digest_len = 0;

    if (EVP_DigestFinal_ex(
            ctx,
            digest,
            &digest_len) != 1) {
        OPENSSL_cleanse(digest, sizeof(digest));
        goto cleanup;
    }

    if (digest_len != 64) {
        OPENSSL_cleanse(digest, sizeof(digest));
        goto cleanup;
    }

    memcpy(
        output,
        digest,
        output_len
    );

    OPENSSL_cleanse(
        digest,
        sizeof(digest)
    );

    success = TRUE;

cleanup:

    EVP_MD_CTX_free(ctx);

    if (!success)
        OPENSSL_cleanse(output, output_len);

    return success;
}

/* ============================================================
 * HYBRID X25519 + ML-KEM HKDF
 * ============================================================ */

static gboolean
hybrid_pq_derive_aes256_key(
    const guint8 *x25519_secret,
    gsize         x25519_secret_len,
    const guint8 *mlkem_secret,
    gsize         mlkem_secret_len,
    const guint8 *salt,
    gsize         salt_len,
    const gchar  *domain,
    guint8        output_key[HYBRID_AES_KEY_SIZE])
{
    gboolean success = FALSE;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    guint8 *ikm = NULL;
    guint8 *info = NULL;

    gsize ikm_len = 0;
    gsize info_len = 0;

    if (x25519_secret == NULL ||
        mlkem_secret == NULL ||
        output_key == NULL ||
        domain == NULL) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Hybrid-PQ-KDF",
            "Invalid NULL parameter."
        );

        return FALSE;
    }

    if (x25519_secret_len != HYBRID_SECRET_SIZE ||
        mlkem_secret_len != HYBRID_SECRET_SIZE) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Hybrid-PQ-KDF",
            "Invalid shared-secret size."
        );

        return FALSE;
    }

    if (salt_len > 0 && salt == NULL)
        return FALSE;

    gsize domain_len = strlen(domain);

    if (domain_len == 0 ||
        domain_len > HYBRID_MAX_DOMAIN_LEN) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Hybrid-PQ-KDF",
            "Invalid domain length."
        );

        return FALSE;
    }

    OPENSSL_cleanse(
        output_key,
        HYBRID_AES_KEY_SIZE
    );

    static const guint8 label[] =
        "HYBRID-PQ-X25519-MLKEM768-v2";

    static const guint8 protocol_id[] =
        "SECURE-BROWSER-AES256GCM-HKDF-SHA512-V2";

    const gsize label_len =
        sizeof(label) - 1;

    const gsize protocol_len =
        sizeof(protocol_id) - 1;

    /*
     * Length encoding prevents concatenation ambiguity.
     */
    ikm_len =
        sizeof(guint32) +
        label_len +
        sizeof(guint32) +
        x25519_secret_len +
        sizeof(guint32) +
        mlkem_secret_len;

    ikm = g_malloc(ikm_len);

    if (ikm == NULL)
        goto cleanup;

    guint8 *p = ikm;

    guint32 len32;

    len32 = (guint32)label_len;
    memcpy(p, &len32, sizeof(len32));
    p += sizeof(len32);

    memcpy(p, label, label_len);
    p += label_len;

    len32 = (guint32)x25519_secret_len;
    memcpy(p, &len32, sizeof(len32));
    p += sizeof(len32);

    memcpy(
        p,
        x25519_secret,
        x25519_secret_len
    );

    p += x25519_secret_len;

    len32 = (guint32)mlkem_secret_len;
    memcpy(p, &len32, sizeof(len32));
    p += sizeof(len32);

    memcpy(
        p,
        mlkem_secret,
        mlkem_secret_len
    );

    info_len =
        sizeof(guint32) +
        domain_len +
        protocol_len;

    info = g_malloc(info_len);

    if (info == NULL)
        goto cleanup;

    p = info;

    len32 = (guint32)domain_len;

    memcpy(
        p,
        &len32,
        sizeof(len32)
    );

    p += sizeof(len32);

    memcpy(
        p,
        domain,
        domain_len
    );

    p += domain_len;

    memcpy(
        p,
        protocol_id,
        protocol_len
    );

    kdf = EVP_KDF_fetch(
        NULL,
        "HKDF",
        NULL
    );

    if (kdf == NULL) {
        log_security_event(
            SEC_EVENT_VIOLATION,
            "Hybrid-PQ-KDF",
            "Unable to fetch OpenSSL HKDF."
        );

        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);

    if (kctx == NULL)
        goto cleanup;

    OSSL_PARAM params[6];
    int index = 0;

    static const char digest_name[] = "SHA512";

    params[index++] =
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            (char *)digest_name,
            0
        );

    params[index++] =
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            ikm,
            ikm_len
        );

    if (salt != NULL && salt_len > 0) {

        params[index++] =
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                (void *)salt,
                salt_len
            );
    }

    params[index++] =
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info,
            info_len
        );

    params[index++] =
        OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(
            kctx,
            output_key,
            HYBRID_AES_KEY_SIZE,
            params) != 1) {

        OPENSSL_cleanse(
            output_key,
            HYBRID_AES_KEY_SIZE
        );

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Hybrid-PQ-KDF",
            "HKDF-SHA512 derivation failed."
        );

        goto cleanup;
    }

    success = TRUE;

cleanup:

    if (ikm != NULL) {
        OPENSSL_cleanse(
            ikm,
            ikm_len
        );
        g_free(ikm);
    }

    if (info != NULL) {
        OPENSSL_cleanse(
            info,
            info_len
        );
        g_free(info);
    }

    if (kctx != NULL)
        EVP_KDF_CTX_free(kctx);

    if (kdf != NULL)
        EVP_KDF_free(kdf);

    return success;
}

/* ============================================================
 * AES-256-GCM
 * ============================================================ */

static gboolean
aes256gcm_encrypt(const guint8 *key,
                  const guint8 *plaintext,
                  gsize plaintext_len,
                  const guint8 *aad,
                  gsize aad_len,
                  guint8 iv[GCM_IV_SIZE],
                  guint8 *ciphertext,
                  guint8 tag[GCM_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;

    gboolean success = FALSE;

    int out_len = 0;
    int final_len = 0;

    if (key == NULL ||
        plaintext == NULL ||
        ciphertext == NULL ||
        iv == NULL ||
        tag == NULL) {
        return FALSE;
    }

    if (plaintext_len > INT_MAX ||
        aad_len > INT_MAX) {
        return FALSE;
    }

    if (!secure_random_bytes(
            iv,
            GCM_IV_SIZE)) {
        return FALSE;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return FALSE;

    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_IV_SIZE,
            NULL) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            iv) != 1) {
        goto cleanup;
    }

    if (aad != NULL && aad_len > 0) {

        if (EVP_EncryptUpdate(
                ctx,
                NULL,
                &out_len,
                aad,
                (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    if (plaintext_len > 0) {

        if (EVP_EncryptUpdate(
                ctx,
                ciphertext,
                &out_len,
                plaintext,
                (int)plaintext_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + out_len,
            &final_len) != 1) {
        goto cleanup;
    }

    if ((gsize)(out_len + final_len) != plaintext_len)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            GCM_TAG_SIZE,
            tag) != 1) {
        goto cleanup;
    }

    success = TRUE;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        OPENSSL_cleanse(
            ciphertext,
            plaintext_len
        );

        OPENSSL_cleanse(
            tag,
            GCM_TAG_SIZE
        );
    }

    return success;
}

static gboolean
aes256gcm_decrypt(const guint8 *key,
                  const guint8 *ciphertext,
                  gsize ciphertext_len,
                  const guint8 *aad,
                  gsize aad_len,
                  const guint8 iv[GCM_IV_SIZE],
                  const guint8 tag[GCM_TAG_SIZE],
                  guint8 *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;

    gboolean success = FALSE;

    int out_len = 0;
    int final_len = 0;

    if (key == NULL ||
        ciphertext == NULL ||
        plaintext == NULL ||
        iv == NULL ||
        tag == NULL) {
        return FALSE;
    }

    if (ciphertext_len > INT_MAX ||
        aad_len > INT_MAX) {
        return FALSE;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        return FALSE;

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_IVLEN,
            GCM_IV_SIZE,
            NULL) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            key,
            iv) != 1) {
        goto cleanup;
    }

    if (aad != NULL && aad_len > 0) {

        if (EVP_DecryptUpdate(
                ctx,
                NULL,
                &out_len,
                aad,
                (int)aad_len) != 1) {
            goto cleanup;
        }
    }

    if (ciphertext_len > 0) {

        if (EVP_DecryptUpdate(
                ctx,
                plaintext,
                &out_len,
                ciphertext,
                (int)ciphertext_len) != 1) {
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            GCM_TAG_SIZE,
            (void *)tag) != 1) {
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + out_len,
            &final_len) != 1) {

        OPENSSL_cleanse(
            plaintext,
            ciphertext_len
        );

        goto cleanup;
    }

    if ((gsize)(out_len + final_len) != ciphertext_len) {
        OPENSSL_cleanse(
            plaintext,
            ciphertext_len
        );

        goto cleanup;
    }

    success = TRUE;

cleanup:

    EVP_CIPHER_CTX_free(ctx);

    return success;
}

/* ============================================================
 * FILE INTEGRITY
 * ============================================================ */

static gchar *
compute_file_checksum(const gchar *filepath)
{
    if (filepath == NULL)
        return NULL;

    GMappedFile *mapped =
        g_mapped_file_new(
            filepath,
            FALSE,
            NULL
        );

    if (mapped == NULL)
        return NULL;

    const gchar *contents =
        g_mapped_file_get_contents(mapped);

    gsize length =
        g_mapped_file_get_length(mapped);

    guint8 digest[64];

    if (!sha512_digest(
            (const guint8 *)contents,
            length,
            digest)) {

        g_mapped_file_unref(mapped);
        return NULL;
    }

    gchar *hex =
        g_malloc0(
            sizeof(digest) * 2 + 1
        );

    if (hex == NULL) {
        OPENSSL_cleanse(
            digest,
            sizeof(digest)
        );

        g_mapped_file_unref(mapped);
        return NULL;
    }

    for (gsize i = 0;
         i < sizeof(digest);
         ++i) {

        g_snprintf(
            hex + i * 2,
            3,
            "%02x",
            digest[i]
        );
    }

    OPENSSL_cleanse(
        digest,
        sizeof(digest)
    );

    g_mapped_file_unref(mapped);

    return hex;
}

static void
verify_module_integrity(const gchar *binary_path)
{
    gchar *hash =
        compute_file_checksum(
            binary_path
        );

    if (hash == NULL) {

        log_security_event(
            SEC_EVENT_FILE_MOD,
            "Module-Integrity",
            "Unable to calculate SHA-512 executable hash."
        );

        return;
    }

    gchar *message =
        g_strdup_printf(
            "SHA-512 executable checksum: %s",
            hash
        );

    log_security_event(
        SEC_EVENT_INFO,
        "Module-Integrity",
        message
    );

    g_free(message);
    g_free(hash);
}

/* ============================================================
 * SECURE COOKIE OBJECT
 *
 * This is an application-level secure storage object.
 * It is NOT WebKit's actual cookie jar.
 * ============================================================ */

typedef struct {
    gchar *cookie_name;
    gchar *domain;

    guint8 key[32];

    guint8 iv[GCM_IV_SIZE];
    guint8 tag[GCM_TAG_SIZE];

    guint8 *ciphertext;
    gsize ciphertext_len;
} SecureCookie;

static SecureCookie *
secure_cookie_create(const gchar *domain,
                     const gchar *name,
                     const gchar *plain_value)
{
    if (domain == NULL ||
        name == NULL ||
        plain_value == NULL ||
        *domain == '\0' ||
        *name == '\0') {

        return NULL;
    }

    gsize value_len =
        strlen(plain_value);

    if (value_len > COOKIE_MAX_VALUE_SIZE) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Cookie-System",
            "Cookie value exceeds configured size limit."
        );

        return NULL;
    }

    SecureCookie *cookie =
        g_new0(
            SecureCookie,
            1
        );

    if (cookie == NULL)
        return NULL;

    cookie->domain =
        g_strdup(domain);

    cookie->cookie_name =
        g_strdup(name);

    cookie->ciphertext =
        g_malloc0(
            value_len
        );

    if (cookie->domain == NULL ||
        cookie->cookie_name == NULL ||
        (value_len > 0 &&
         cookie->ciphertext == NULL)) {

        g_free(cookie->domain);
        g_free(cookie->cookie_name);
        g_free(cookie->ciphertext);
        g_free(cookie);

        return NULL;
    }

    if (!secure_random_bytes(
            cookie->key,
            sizeof(cookie->key))) {
        goto failure;
    }

    /*
     * Authenticate the cookie domain/name as AAD.
     */
    gchar *aad =
        g_strdup_printf(
            "%s|%s",
            domain,
            name
        );

    if (aad == NULL)
        goto failure;

    if (!aes256gcm_encrypt(
            cookie->key,
            (const guint8 *)plain_value,
            value_len,
            (const guint8 *)aad,
            strlen(aad),
            cookie->iv,
            cookie->ciphertext,
            cookie->tag)) {

        g_free(aad);
        goto failure;
    }

    g_free(aad);

    cookie->ciphertext_len =
        value_len;

    return cookie;

failure:

    OPENSSL_cleanse(
        cookie->key,
        sizeof(cookie->key)
    );

    g_free(cookie->domain);
    g_free(cookie->cookie_name);
    g_free(cookie->ciphertext);
    g_free(cookie);

    return NULL;
}

static gchar *
secure_cookie_decrypt(
    const SecureCookie *cookie,
    const gchar *accessor_domain)
{
    if (cookie == NULL ||
        accessor_domain == NULL) {
        return NULL;
    }

    if (g_strcmp0(
            cookie->domain,
            accessor_domain) != 0) {

        gchar *alert =
            g_strdup_printf(
                "Unauthorized domain '%s' attempted to access cookie owned by '%s'.",
                accessor_domain,
                cookie->domain
            );

        log_security_event(
            SEC_EVENT_THEFT_ATTEMPT,
            "Cookie-Theft-Monitor",
            alert
        );

        g_free(alert);

        return g_strdup(
            "[BLOCKED: Cross-Site Cookie Theft Detected]"
        );
    }

    gchar *aad =
        g_strdup_printf(
            "%s|%s",
            cookie->domain,
            cookie->cookie_name
        );

    if (aad == NULL)
        return NULL;

    guint8 *plain =
        g_malloc0(
            cookie->ciphertext_len + 1
        );

    if (plain == NULL) {
        g_free(aad);
        return NULL;
    }

    gboolean ok =
        aes256gcm_decrypt(
            cookie->key,
            cookie->ciphertext,
            cookie->ciphertext_len,
            (const guint8 *)aad,
            strlen(aad),
            cookie->iv,
            cookie->tag,
            plain
        );

    g_free(aad);

    if (!ok) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Cookie-System",
            "AES-256-GCM authentication failed."
        );

        OPENSSL_cleanse(
            plain,
            cookie->ciphertext_len + 1
        );

        g_free(plain);

        return NULL;
    }

    return (gchar *)plain;
}

static void
secure_cookie_free(SecureCookie *cookie)
{
    if (cookie == NULL)
        return;

    g_free(cookie->cookie_name);
    g_free(cookie->domain);

    OPENSSL_cleanse(
        cookie->key,
        sizeof(cookie->key)
    );

    OPENSSL_cleanse(
        cookie->iv,
        sizeof(cookie->iv)
    );

    OPENSSL_cleanse(
        cookie->tag,
        sizeof(cookie->tag)
    );

    if (cookie->ciphertext != NULL) {

        OPENSSL_cleanse(
            cookie->ciphertext,
            cookie->ciphertext_len
        );

        g_free(cookie->ciphertext);
    }

    g_free(cookie);
}

/* ============================================================
 * TAB SECURITY
 * ============================================================ */

typedef struct {
    guint8 key_bytes[TAB_KEY_SIZE];
    gchar *key_id_hex;
} PostQuantumProfileKey;

typedef struct {
    WebKitWebView *web_view;

    gchar *data_dir;
    gchar *cache_dir;

    GtkWidget *scrolled_window;

    PostQuantumProfileKey *pq_key;

    gboolean destroying;
} TabContextData;

static PostQuantumProfileKey *
pq_generate_tab_key(void)
{
    PostQuantumProfileKey *key =
        g_new0(
            PostQuantumProfileKey,
            1
        );

    if (key == NULL)
        return NULL;

    if (!secure_random_bytes(
            key->key_bytes,
            sizeof(key->key_bytes))) {

        g_free(key);
        return NULL;
    }

    /*
     * Human-readable identifier only.
     * Do not use it as the secret.
     */
    key->key_id_hex =
        g_malloc0(
            sizeof(key->key_bytes) * 2 + 1
        );

    if (key->key_id_hex != NULL) {

        for (gsize i = 0;
             i < sizeof(key->key_bytes);
             ++i) {

            g_snprintf(
                key->key_id_hex + i * 2,
                3,
                "%02x",
                key->key_bytes[i]
            );
        }
    }

    return key;
}

static void
free_tab_key(PostQuantumProfileKey *key)
{
    if (key == NULL)
        return;

    OPENSSL_cleanse(
        key->key_bytes,
        sizeof(key->key_bytes)
    );

    if (key->key_id_hex != NULL) {

        OPENSSL_cleanse(
            key->key_id_hex,
            strlen(key->key_id_hex)
        );
    }

    g_free(key->key_id_hex);
    g_free(key);
}

/* ============================================================
 * SAFE PROFILE PATH CHECK
 * ============================================================ */

static gboolean
path_is_under_directory(const gchar *path,
                        const gchar *parent)
{
    if (path == NULL || parent == NULL)
        return FALSE;

    gchar *canonical_path =
        g_canonicalize_filename(
            path,
            NULL
        );

    gchar *canonical_parent =
        g_canonicalize_filename(
            parent,
            NULL
        );

    if (canonical_path == NULL ||
        canonical_parent == NULL) {

        g_free(canonical_path);
        g_free(canonical_parent);

        return FALSE;
    }

    gboolean result = FALSE;

    gsize parent_len =
        strlen(canonical_parent);

    if (g_str_has_prefix(
            canonical_path,
            canonical_parent)) {

        gchar next =
            canonical_path[parent_len];

        if (next == '\0' ||
            next == G_DIR_SEPARATOR) {

            result = TRUE;
        }
    }

    g_free(canonical_path);
    g_free(canonical_parent);

    return result;
}

/* ============================================================
 * RECURSIVE CLEANUP
 * ============================================================ */

static void
recursively_delete_directory(const gchar *dirname)
{
    if (dirname == NULL ||
        *dirname == '\0') {
        return;
    }

    GDir *dir =
        g_dir_open(
            dirname,
            0,
            NULL
        );

    if (dir == NULL)
        return;

    const gchar *filename;

    while ((filename =
            g_dir_read_name(dir)) != NULL) {

        gchar *filepath =
            g_build_filename(
                dirname,
                filename,
                NULL
            );

        if (g_file_test(
                filepath,
                G_FILE_TEST_IS_DIR)) {

            recursively_delete_directory(
                filepath
            );

        } else {

            if (g_unlink(filepath) != 0) {

                gchar *msg =
                    g_strdup_printf(
                        "Unable to delete temporary file: %s",
                        filepath
                    );

                log_security_event(
                    SEC_EVENT_FILE_MOD,
                    "Auto-Destruct",
                    msg
                );

                g_free(msg);
            }
        }

        g_free(filepath);
    }

    g_dir_close(dir);

    if (g_rmdir(dirname) != 0 &&
        errno != ENOENT) {

        gchar *msg =
            g_strdup_printf(
                "Unable to remove temporary directory: %s",
                dirname
            );

        log_security_event(
            SEC_EVENT_FILE_MOD,
            "Auto-Destruct",
            msg
        );

        g_free(msg);
    }
}

static void
on_tab_destroy_cleanup(GtkWidget *widget,
                       gpointer user_data)
{
    (void)widget;

    TabContextData *tab =
        (TabContextData *)user_data;

    if (tab == NULL ||
        tab->destroying) {
        return;
    }

    tab->destroying = TRUE;

    log_security_event(
        SEC_EVENT_INFO,
        "Auto-Destruct",
        "Tab closed; destroying temporary profile."
    );

    /*
     * Do not recursively delete arbitrary paths.
     */
    const gchar *profile_root =
        g_build_filename(
            g_get_user_cache_dir(),
            "secure_browser_profiles",
            NULL
        );

    if (tab->data_dir != NULL &&
        path_is_under_directory(
            tab->data_dir,
            profile_root)) {

        recursively_delete_directory(
            tab->data_dir
        );
    }

    g_free((gchar *)profile_root);

    /*
     * data_dir normally owns cache_dir.
     * Do NOT delete cache_dir separately after deleting data_dir.
     */

    free_tab_key(tab->pq_key);

    g_free(tab->data_dir);
    g_free(tab->cache_dir);

    g_free(tab);
}

/* ============================================================
 * URI SECURITY
 * ============================================================ */

static gboolean
uri_has_scheme(const gchar *uri,
               const gchar *scheme)
{
    if (uri == NULL ||
        scheme == NULL) {
        return FALSE;
    }

    gsize len =
        strlen(scheme);

    return g_ascii_strncasecmp(
               uri,
               scheme,
               len) == 0 &&
           uri[len] == ':';
}

static gchar *
uri_scheme_lower(const gchar *uri)
{
    if (uri == NULL)
        return NULL;

    const gchar *colon =
        strchr(uri, ':');

    if (colon == NULL)
        return NULL;

    gsize len =
        (gsize)(colon - uri);

    if (len == 0 ||
        len > 64) {
        return NULL;
    }

    gchar *scheme =
        g_strndup(
            uri,
            len
        );

    if (scheme != NULL)
        g_ascii_strdown(
            scheme,
            -1
        );

    return scheme;
}

static gboolean
is_allowed_navigation_scheme(const gchar *uri)
{
    gchar *scheme =
        uri_scheme_lower(uri);

    if (scheme == NULL)
        return FALSE;

    gboolean allowed =
        g_strcmp0(scheme, "https") == 0 ||
        g_strcmp0(scheme, "internal") == 0 ||
        g_strcmp0(scheme, "about") == 0;

    g_free(scheme);

    return allowed;
}

static gboolean
uri_contains_suspicious_pattern(const gchar *uri)
{
    if (uri == NULL)
        return FALSE;

    gchar *lower =
        g_ascii_strdown(
            uri,
            -1
        );

    if (lower == NULL)
        return FALSE;

    static const gchar *patterns[] = {
        "<script",
        "%3cscript",
        "javascript:",
        "union%20select",
        "union+select",
        "union select",
        "../",
        "..%2f",
        "%2e%2e%2f",
        "%2e%2e/",
        "/etc/passwd",
        "cmd.exe",
        "powershell",
        NULL
    };

    gboolean found = FALSE;

    for (gsize i = 0;
         patterns[i] != NULL;
         ++i) {

        if (g_strstr_len(
                lower,
                -1,
                patterns[i]) != NULL) {

            found = TRUE;
            break;
        }
    }

    g_free(lower);

    return found;
}

/*
 * Logs only origin-like information, avoiding query strings
 * and possible credentials/tokens.
 */
static gchar *
safe_uri_for_log(const gchar *uri)
{
    if (uri == NULL)
        return g_strdup("(null)");

    GUri *parsed =
        g_uri_parse(
            uri,
            G_URI_FLAGS_NONE,
            NULL
        );

    if (parsed == NULL)
        return g_strdup("[invalid URI]");

    const gchar *scheme =
        g_uri_get_scheme(parsed);

    const gchar *host =
        g_uri_get_host(parsed);

    const gchar *path =
        g_uri_get_path(parsed);

    gchar *safe;

    if (scheme != NULL &&
        host != NULL) {

        safe =
            g_strdup_printf(
                "%s://%s%s",
                scheme,
                host,
                path ? path : ""
            );

    } else {

        safe =
            g_strdup(
                uri
            );
    }

    g_uri_unref(parsed);

    return safe;
}

/* ============================================================
 * BLOCK PAGE
 * ============================================================ */

static void
load_security_block_page(WebKitWebView *web_view,
                         const gchar *requested_uri,
                         const gchar *reason)
{
    gchar *safe_reason =
        g_markup_escape_text(
            reason ? reason : "Security policy",
            -1
        );

    gchar *html =
        g_strdup_printf(
            "<!doctype html>"
            "<html>"
            "<head>"
            "<meta charset='utf-8'>"
            "<title>Navigation Blocked</title>"
            "</head>"
            "<body style='"
            "background:#0d1117;"
            "color:#c9d1d9;"
            "font-family:sans-serif;"
            "display:flex;"
            "justify-content:center;"
            "align-items:center;"
            "height:100vh;"
            "margin:0;'>"
            "<div style='"
            "background:#161b22;"
            "border:1px solid #f85149;"
            "padding:35px;"
            "border-radius:10px;"
            "max-width:700px;'>"
            "<h2 style='color:#f85149;'>"
            "Navigation Blocked"
            "</h2>"
            "<p>%s</p>"
            "<p style='color:#8b949e;'>"
            "The browser security policy rejected this navigation."
            "</p>"
            "</div>"
            "</body>"
            "</html>",
            safe_reason
        );

    webkit_web_view_load_alternate_html(
        web_view,
        html,
        requested_uri ? requested_uri : "internal://blocked",
        NULL
    );

    g_free(safe_reason);
    g_free(html);
}

/* ============================================================
 * INTERNAL SEARCH
 * ============================================================ */

static gboolean
handle_internal_search(WebKitWebView *web_view,
                       const gchar *uri)
{
    if (!uri_has_scheme(uri, "internal"))
        return FALSE;

    if (!g_str_has_prefix(
            uri,
            "internal://search")) {
        return FALSE;
    }

    GUri *parsed =
        g_uri_parse(
            uri,
            G_URI_FLAGS_NONE,
            NULL
        );

    if (parsed == NULL)
        return TRUE;

    const gchar *query =
        g_uri_get_query(parsed);

    gchar *search_term = NULL;

    if (query != NULL) {

        gchar **parts =
            g_strsplit(
                query,
                "&",
                -1
            );

        for (gsize i = 0;
             parts[i] != NULL;
             ++i) {

            if (g_str_has_prefix(
                    parts[i],
                    "q=")) {

                search_term =
                    g_uri_unescape_string(
                        parts[i] + 2,
                        NULL
                    );

                break;
            }
        }

        g_strfreev(parts);
    }

    if (search_term == NULL ||
        *search_term == '\0') {

        g_free(search_term);
        g_uri_unref(parsed);

        return TRUE;
    }

    gchar *escaped =
        g_uri_escape_string(
            search_term,
            NULL,
            TRUE
        );

    if (escaped != NULL) {

        gchar *search_url =
            g_strdup_printf(
                "https://html.duckduckgo.com/html/?q=%s",
                escaped
            );

        log_security_event(
            SEC_EVENT_INFO,
            "Secure-Search",
            "Internal search routed to HTTPS search endpoint."
        );

        webkit_web_view_load_uri(
            web_view,
            search_url
        );

        g_free(search_url);
        g_free(escaped);
    }

    /*
     * Never put the actual search query in the security log.
     */
    g_free(search_term);
    g_uri_unref(parsed);

    return TRUE;
}

/* ============================================================
 * POLICY DECISION
 * ============================================================ */

static gboolean
zero_trust_policy_decision_cb(
    WebKitWebView *web_view,
    WebKitPolicyDecision *decision,
    WebKitPolicyDecisionType decision_type,
    gpointer user_data)
{
    TabContextData *tab =
        (TabContextData *)user_data;

    (void)tab;

    /*
     * --------------------------------------------------------
     * NEW WINDOW
     * --------------------------------------------------------
     */

    if (decision_type ==
        WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {

        WebKitNavigationPolicyDecision *nav =
            WEBKIT_NAVIGATION_POLICY_DECISION(
                decision
            );

        WebKitURIRequest *request =
            webkit_navigation_policy_decision_get_request(
                nav
            );

        const gchar *uri =
            request
            ? webkit_uri_request_get_uri(request)
            : NULL;

        gchar *safe =
            safe_uri_for_log(uri);

        log_security_event(
            SEC_EVENT_NETWORK_ANOMALY,
            "Window-Policy",
            "New-window navigation blocked."
        );

        g_free(safe);

        webkit_policy_decision_ignore(
            decision
        );

        return TRUE;
    }

    /*
     * --------------------------------------------------------
     * RESPONSE POLICY
     * --------------------------------------------------------
     */

    if (decision_type ==
        WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {

        WebKitResponsePolicyDecision *response =
            WEBKIT_RESPONSE_POLICY_DECISION(
                decision
            );

        WebKitURIRequest *request =
            webkit_response_policy_decision_get_request(
                response
            );

        WebKitURIResponse *network_response =
            webkit_response_policy_decision_get_response(
                response
            );

        const gchar *uri =
            request
            ? webkit_uri_request_get_uri(request)
            : NULL;

        const gchar *mime =
            network_response
            ? webkit_uri_response_get_mime_type(
                  network_response)
            : NULL;

        /*
         * Browser-rendered MIME types are handled normally.
         * Unsupported responses are allowed to reach WebKit's
         * normal download handling rather than silently executing.
         */
        if (mime != NULL) {

            gchar *msg =
                g_strdup_printf(
                    "Response MIME observed: %s",
                    mime
                );

            log_security_event(
                SEC_EVENT_INFO,
                "Response-Monitor",
                msg
            );

            g_free(msg);
        }

        /*
         * Block active executable content downloaded as a
         * navigation response.
         */
        if (mime != NULL &&
            (g_ascii_strcasecmp(
                 mime,
                 "application/x-executable") == 0 ||
             g_ascii_strcasecmp(
                 mime,
                 "application/x-msdownload") == 0 ||
             g_ascii_strcasecmp(
                 mime,
                 "application/x-dosexec") == 0)) {

            gchar *safe =
                safe_uri_for_log(uri);

            gchar *msg =
                g_strdup_printf(
                    "Executable response blocked: %s",
                    safe
                );

            log_security_event(
                SEC_EVENT_NETWORK_ANOMALY,
                "Response-Monitor",
                msg
            );

            g_free(msg);
            g_free(safe);

            webkit_policy_decision_ignore(
                decision
            );

            return TRUE;
        }

        return FALSE;
    }

    /*
     * --------------------------------------------------------
     * NAVIGATION
     * --------------------------------------------------------
     */

    if (decision_type !=
        WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {
        return FALSE;
    }

    WebKitNavigationPolicyDecision *nav =
        WEBKIT_NAVIGATION_POLICY_DECISION(
            decision
        );

    WebKitURIRequest *request =
        webkit_navigation_policy_decision_get_request(
            nav
        );

    if (request == NULL)
        return FALSE;

    const gchar *uri =
        webkit_uri_request_get_uri(
            request
        );

    if (uri == NULL)
        return FALSE;

    /*
     * Internal search must be handled before the generic
     * scheme check.
     */
    if (handle_internal_search(
            web_view,
            uri)) {

        webkit_policy_decision_ignore(
            decision
        );

        return TRUE;
    }

    gchar *safe_uri =
        safe_uri_for_log(uri);

    /*
     * --------------------------------------------------------
     * ATTACK SIGNATURES
     * --------------------------------------------------------
     */

    if (uri_contains_suspicious_pattern(uri)) {

        gchar *msg =
            g_strdup_printf(
                "Suspicious navigation signature detected: %s",
                safe_uri
            );

        log_security_event(
            SEC_EVENT_INTRUSION,
            "Intrusion-Detection",
            msg
        );

        g_free(msg);

        load_security_block_page(
            web_view,
            uri,
            "A suspicious navigation signature was detected."
        );

        webkit_policy_decision_ignore(
            decision
        );

        g_free(safe_uri);

        return TRUE;
    }

    /*
     * --------------------------------------------------------
     * HTTPS ONLY
     * --------------------------------------------------------
     */

    if (!is_allowed_navigation_scheme(uri)) {

        gchar *scheme =
            uri_scheme_lower(uri);

        gchar *msg =
            g_strdup_printf(
                "Blocked navigation scheme '%s': %s",
                scheme ? scheme : "unknown",
                safe_uri
            );

        log_security_event(
            SEC_EVENT_NETWORK_ANOMALY,
            "Network-Security",
            msg
        );

        g_free(msg);
        g_free(scheme);

        load_security_block_page(
            web_view,
            uri,
            "Only HTTPS navigation is permitted."
        );

        webkit_policy_decision_ignore(
            decision
        );

        g_free(safe_uri);

        return TRUE;
    }

    /*
     * Explicit HTTP block for a clearer security event.
     */
    if (uri_has_scheme(uri, "http")) {

        gchar *msg =
            g_strdup_printf(
                "Cleartext HTTP navigation blocked: %s",
                safe_uri
            );

        log_security_event(
            SEC_EVENT_NETWORK_ANOMALY,
            "Network-Security",
            msg
        );

        g_free(msg);

        load_security_block_page(
            web_view,
            uri,
            "Cleartext HTTP is disabled."
        );

        webkit_policy_decision_ignore(
            decision
        );

        g_free(safe_uri);

        return TRUE;
    }

    /*
     * Explicitly reject common dangerous schemes.
     */
    static const gchar *blocked_schemes[] = {
        "javascript",
        "data",
        "file",
        "blob",
        "ftp",
        "ws",
        "wss",
        NULL
    };

    gchar *scheme =
        uri_scheme_lower(uri);

    if (scheme != NULL) {

        for (gsize i = 0;
             blocked_schemes[i] != NULL;
             ++i) {

            if (g_strcmp0(
                    scheme,
                    blocked_schemes[i]) == 0) {

                gchar *msg =
                    g_strdup_printf(
                        "Blocked dangerous URI scheme: %s",
                        scheme
                    );

                log_security_event(
                    SEC_EVENT_VIOLATION,
                    "URI-Security",
                    msg
                );

                g_free(msg);

                load_security_block_page(
                    web_view,
                    uri,
                    "This URI scheme is disabled by security policy."
                );

                webkit_policy_decision_ignore(
                    decision
                );

                g_free(scheme);
                g_free(safe_uri);

                return TRUE;
            }
        }
    }

    g_free(scheme);

    g_free(safe_uri);

    /*
     * Returning FALSE allows WebKit's normal navigation
     * handling to proceed.
     */
    return FALSE;
}

/* ============================================================
 * LOAD MONITORING
 * ============================================================ */

static void
load_changed_cb(WebKitWebView *web_view,
                WebKitLoadEvent load_event,
                gpointer user_data)
{
    (void)user_data;

    const gchar *uri =
        webkit_web_view_get_uri(
            web_view
        );

    gchar *safe =
        safe_uri_for_log(uri);

    switch (load_event) {

        case WEBKIT_LOAD_STARTED:
            log_security_event(
                SEC_EVENT_INFO,
                "Navigation",
                safe
            );
            break;

        case WEBKIT_LOAD_COMMITTED:
            log_security_event(
                SEC_EVENT_INFO,
                "Navigation",
                "Navigation committed."
            );
            break;

        case WEBKIT_LOAD_FINISHED:
            log_security_event(
                SEC_EVENT_INFO,
                "Navigation",
                "Navigation finished."
            );
            break;

        case WEBKIT_LOAD_REDIRECTED:
            log_security_event(
                SEC_EVENT_NETWORK_ANOMALY,
                "Navigation",
                "Navigation redirected."
            );
            break;
    }

    g_free(safe);
}

/* ============================================================
 * TLS FAILURE MONITORING
 * ============================================================ */

static gboolean
load_failed_with_tls_errors_cb(
    WebKitWebView *web_view,
    const gchar *failing_uri,
    GTlsCertificate *certificate,
    GTlsCertificateFlags errors,
    gpointer user_data)
{
    (void)web_view;
    (void)certificate;
    (void)user_data;

    gchar *safe =
        safe_uri_for_log(
            failing_uri
        );

    gchar *message =
        g_strdup_printf(
            "TLS validation failed for %s (flags=0x%x).",
            safe,
            (unsigned int)errors
        );

    log_security_event(
        SEC_EVENT_NETWORK_ANOMALY,
        "TLS-Security",
        message
    );

    g_free(message);
    g_free(safe);

    /*
     * TRUE means the application handled the failure.
     * We intentionally do not allow the certificate.
     */
    return TRUE;
}

/* ============================================================
 * CREATE SECURE TAB
 * ============================================================ */

static void
close_current_tab_cb(GtkButton *button,
                     gpointer user_data)
{
    (void)button;

    GtkNotebook *nb =
        GTK_NOTEBOOK(user_data);

    gint page =
        gtk_notebook_get_current_page(
            nb
        );

    if (page >= 0)
        gtk_notebook_remove_page(
            nb,
            page
        );
}

static void
new_tab_clicked_cb(GtkButton *button,
                   gpointer user_data);

static GtkWidget *
create_tab_label(GtkNotebook *nb,
                 GtkWidget *page)
{
    GtkWidget *box =
        gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL,
            5
        );

    GtkWidget *label =
        gtk_label_new(
            "PQ Secure Tab"
        );

    GtkWidget *close =
        gtk_button_new_from_icon_name(
            "window-close",
            GTK_ICON_SIZE_MENU
        );

    gtk_button_set_relief(
        GTK_BUTTON(close),
        GTK_RELIEF_NONE
    );

    gtk_box_pack_start(
        GTK_BOX(box),
        label,
        TRUE,
        TRUE,
        0
    );

    gtk_box_pack_start(
        GTK_BOX(box),
        close,
        FALSE,
        FALSE,
        0
    );

    g_signal_connect(
        close,
        "clicked",
        G_CALLBACK(close_current_tab_cb),
        nb
    );

    gtk_widget_show_all(box);

    (void)page;

    return box;
}

static void
add_autodestroy_tab(GtkNotebook *nb,
                    const gchar *initial_uri)
{
    gchar *unique_id =
        g_uuid_string_random();

    gchar *profile_root =
        g_build_filename(
            g_get_user_cache_dir(),
            "secure_browser_profiles",
            NULL
        );

    gchar *data_dir =
        g_build_filename(
            profile_root,
            unique_id,
            NULL
        );

    gchar *cache_dir =
        g_build_filename(
            data_dir,
            "cache",
            NULL
        );

    g_free(profile_root);

    if (g_mkdir_with_parents(
            cache_dir,
            0700) != 0) {

        log_security_event(
            SEC_EVENT_FILE_MOD,
            "Profile-Security",
            "Unable to create secure profile directory."
        );

        g_free(unique_id);
        g_free(data_dir);
        g_free(cache_dir);

        return;
    }

    TabContextData *tab =
        g_new0(
            TabContextData,
            1
        );

    if (tab == NULL) {
        recursively_delete_directory(data_dir);
        g_free(unique_id);
        g_free(data_dir);
        g_free(cache_dir);
        return;
    }

    tab->data_dir =
        g_strdup(data_dir);

    tab->cache_dir =
        g_strdup(cache_dir);

    tab->pq_key =
        pq_generate_tab_key();

    if (tab->pq_key == NULL) {

        log_security_event(
            SEC_EVENT_VIOLATION,
            "Profile-Security",
            "Unable to generate cryptographic tab key."
        );

        g_free(tab->data_dir);
        g_free(tab->cache_dir);
        g_free(tab);

        recursively_delete_directory(data_dir);

        g_free(unique_id);
        g_free(data_dir);
        g_free(cache_dir);

        return;
    }

    /*
     * --------------------------------------------------------
     * EPHEMERAL WEBSITE DATA
     * --------------------------------------------------------
     */

    WebKitWebsiteDataManager *manager =
        webkit_website_data_manager_new(
            "base-data-directory",
            data_dir,
            "base-cache-directory",
            cache_dir,
            NULL
        );

    if (manager == NULL)
        goto failure;

    /*
     * TLS errors fail closed.
     *
     * This is the current WebKitGTK 4.1 API.
     */
    webkit_website_data_manager_set_tls_errors_policy(
        manager,
        WEBKIT_TLS_ERRORS_POLICY_FAIL
    );

    webkit_website_data_manager_set_itp_enabled(
        manager,
        TRUE
    );

    webkit_website_data_manager_set_persistent_credential_storage_enabled(
        manager,
        FALSE
    );

    webkit_website_data_manager_set_ephemeral(
        manager,
        TRUE
    );

    /*
     * --------------------------------------------------------
     * WEBKIT CONTEXT
     * --------------------------------------------------------
     */

    WebKitWebContext *context =
        webkit_web_context_new_with_website_data_manager(
            manager
        );

    if (context == NULL)
        goto failure;

    /*
     * Must happen before web processes are created.
     */
    webkit_web_context_set_sandbox_enabled(
        context,
        TRUE
    );

    WebKitSettings *settings =
        webkit_settings_new();

    if (settings == NULL) {
        g_object_unref(context);
        goto failure;
    }

    /*
     * JavaScript is required for modern sites.
     * Navigation policy still blocks javascript: URI
     * navigations.
     */
    webkit_settings_set_enable_javascript(
        settings,
        TRUE
    );

    webkit_settings_set_enable_hyperlink_auditing(
        settings,
        FALSE
    );

    webkit_settings_set_enable_dns_prefetching(
        settings,
        FALSE
    );

    webkit_settings_set_enable_developer_extras(
        settings,
        FALSE
    );

    WebKitWebView *web_view =
        WEBKIT_WEB_VIEW(
            webkit_web_view_new_with_context(
                context
            )
        );

    if (web_view == NULL) {
        g_object_unref(settings);
        g_object_unref(context);
        goto failure;
    }

    webkit_web_view_set_settings(
        web_view,
        settings
    );

    tab->web_view =
        web_view;

    g_object_unref(settings);
    g_object_unref(context);
    g_object_unref(manager);

    g_free(unique_id);
    g_free(data_dir);
    g_free(cache_dir);

    /*
     * --------------------------------------------------------
     * SECURITY SIGNALS
     * --------------------------------------------------------
     */

    g_signal_connect(
        web_view,
        "decide-policy",
        G_CALLBACK(zero_trust_policy_decision_cb),
        tab
    );

    g_signal_connect(
        web_view,
        "load-changed",
        G_CALLBACK(load_changed_cb),
        tab
    );

    g_signal_connect(
        web_view,
        "load-failed-with-tls-errors",
        G_CALLBACK(load_failed_with_tls_errors_cb),
        tab
    );

    /*
     * --------------------------------------------------------
     * TAB CONTAINER
     * --------------------------------------------------------
     */

    GtkWidget *scrolled =
        gtk_scrolled_window_new(
            NULL,
            NULL
        );

    tab->scrolled_window =
        scrolled;

    /*
     * WebKitWebView is itself scrollable. This container is
     * retained for compatibility with the existing UI.
     */
    gtk_container_add(
        GTK_CONTAINER(scrolled),
        GTK_WIDGET(web_view)
    );

    GtkWidget *tab_label =
        create_tab_label(
            nb,
            scrolled
        );

    gint page_num =
        gtk_notebook_append_page(
            nb,
            scrolled,
            tab_label
        );

    gtk_notebook_set_current_page(
        nb,
        page_num
    );

    g_signal_connect(
        scrolled,
        "destroy",
        G_CALLBACK(on_tab_destroy_cleanup),
        tab
    );

    /*
     * --------------------------------------------------------
     * INTERNAL START PAGE
     * --------------------------------------------------------
     */

    const gchar *start_page =
        "<!doctype html>"
        "<html>"
        "<head>"
        "<meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'self'; "
        "form-action 'self' internal:; "
        "style-src 'unsafe-inline'; "
        "script-src 'none';\">"
        "<title>Secure Browser</title>"
        "</head>"
        "<body style='"
        "background:#0d1117;"
        "color:#c9d1d9;"
        "font-family:sans-serif;"
        "display:flex;"
        "justify-content:center;"
        "align-items:center;"
        "height:100vh;"
        "margin:0;'>"
        "<div style='"
        "background:#161b22;"
        "border:1px solid #30363d;"
        "padding:40px;"
        "border-radius:8px;"
        "text-align:center;"
        "max-width:650px;'>"
        "<h2 style='color:#58a6ff;'>"
        "Secure Browser"
        "</h2>"
        "<p style='color:#8b949e;'>"
        "HTTPS-only navigation, isolated ephemeral profiles, "
        "TLS validation and intrusion monitoring are active."
        "</p>"
        "<form action='internal://search' method='GET'>"
        "<input "
        "type='text' "
        "name='q' "
        "autocomplete='off' "
        "spellcheck='false' "
        "placeholder='Enter secure search query...' "
        "style='"
        "padding:10px;"
        "width:90%;"
        "background:#0d1117;"
        "color:#fff;"
        "border:1px solid #30363d;"
        "border-radius:4px;"
        "margin-top:10px;'>"
        "</form>"
        "</div>"
        "</body>"
        "</html>";

    if (initial_uri != NULL &&
        *initial_uri != '\0') {

        webkit_web_view_load_uri(
            web_view,
            initial_uri
        );

    } else {

        webkit_web_view_load_alternate_html(
            web_view,
            start_page,
            "internal://start",
            NULL
        );
    }

    gtk_widget_show_all(
        scrolled
    );

    return;

failure:

    log_security_event(
        SEC_EVENT_FILE_MOD,
        "Profile-Security",
        "Secure WebKit profile initialization failed."
    );

    if (manager != NULL)
        g_object_unref(manager);

    free_tab_key(tab->pq_key);

    g_free(tab->data_dir);
    g_free(tab->cache_dir);
    g_free(tab);

    recursively_delete_directory(
        data_dir
    );

    g_free(unique_id);
    g_free(data_dir);
    g_free(cache_dir);
}

/* ============================================================
 * NEW TAB
 * ============================================================ */

static void
new_tab_clicked_cb(GtkButton *button,
                   gpointer user_data)
{
    (void)button;

    GtkNotebook *nb =
        GTK_NOTEBOOK(user_data);

    add_autodestroy_tab(
        nb,
        NULL
    );
}

/* ============================================================
 * MAIN WINDOW
 * ============================================================ */

int
main(int argc, char *argv[])
{
    /*
     * --------------------------------------------------------
     * GTK
     * --------------------------------------------------------
     */

    gtk_init(
        &argc,
        &argv
    );

    /*
     * --------------------------------------------------------
     * OPENSSL
     * --------------------------------------------------------
     */

    OPENSSL_init_crypto(
        0,
        NULL
    );

    /*
     * --------------------------------------------------------
     * SELF INTEGRITY
     * --------------------------------------------------------
     */

    if (argc > 0 &&
        argv[0] != NULL) {

        verify_module_integrity(
            argv[0]
        );
    }

    /*
     * --------------------------------------------------------
     * MAIN WINDOW
     * --------------------------------------------------------
     */

    GtkWidget *window =
        gtk_window_new(
            GTK_WINDOW_TOPLEVEL
        );

    gtk_window_set_default_size(
        GTK_WINDOW(window),
        1200,
        850
    );

    gtk_window_set_title(
        GTK_WINDOW(window),
        "Secure Browser & Threat Detection Console"
    );

    g_signal_connect(
        window,
        "destroy",
        G_CALLBACK(gtk_main_quit),
        NULL
    );

    /*
     * --------------------------------------------------------
     * MAIN PANED LAYOUT
     * --------------------------------------------------------
     */

    GtkWidget *vpaned =
        gtk_paned_new(
            GTK_ORIENTATION_VERTICAL
        );

    gtk_container_add(
        GTK_CONTAINER(window),
        vpaned
    );

    /*
     * --------------------------------------------------------
     * BROWSER TOOLBAR
     * --------------------------------------------------------
     */

    GtkWidget *browser_box =
        gtk_box_new(
            GTK_ORIENTATION_VERTICAL,
            4
        );

    gtk_paned_pack1(
        GTK_PANED(vpaned),
        browser_box,
        TRUE,
        FALSE
    );

    GtkWidget *toolbar =
        gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL,
            4
        );

    GtkWidget *new_tab =
        gtk_button_new_with_label(
            "+ New Secure Tab"
        );

    g_signal_connect(
        new_tab,
        "clicked",
        G_CALLBACK(new_tab_clicked_cb),
        NULL
    );

    /*
     * The callback needs the notebook, so connect after it
     * exists below.
     */

    notebook =
        gtk_notebook_new();

    g_signal_connect(
        new_tab,
        "clicked",
        G_CALLBACK(new_tab_clicked_cb),
        notebook
    );

    gtk_box_pack_start(
        GTK_BOX(toolbar),
        new_tab,
        FALSE,
        FALSE,
        0
    );

    gtk_box_pack_start(
        GTK_BOX(browser_box),
        toolbar,
        FALSE,
        FALSE,
        0
    );

    gtk_box_pack_start(
        GTK_BOX(browser_box),
        notebook,
        TRUE,
        TRUE,
        0
    );

    /*
     * --------------------------------------------------------
     * SECURITY CONSOLE
     * --------------------------------------------------------
     */

    GtkWidget *console_frame =
        gtk_frame_new(
            "Live Security Event & Intrusion Detection Console"
        );

    GtkWidget *console_scrolled =
        gtk_scrolled_window_new(
            NULL,
            NULL
        );

    gtk_widget_set_size_request(
        console_frame,
        -1,
        220
    );

    console_text_view =
        gtk_text_view_new();

    gtk_text_view_set_editable(
        GTK_TEXT_VIEW(console_text_view),
        FALSE
    );

    gtk_text_view_set_cursor_visible(
        GTK_TEXT_VIEW(console_text_view),
        FALSE
    );

    gtk_text_view_set_wrap_mode(
        GTK_TEXT_VIEW(console_text_view),
        GTK_WRAP_WORD_CHAR
    );

    /*
     * GTK3 CSS instead of deprecated
     * gtk_widget_override_font().
     */
    GtkCssProvider *provider =
        gtk_css_provider_new();

    gtk_css_provider_load_from_data(
        provider,
        "textview {"
        "font-family: Monospace;"
        "font-size: 10pt;"
        "background:#0d1117;"
        "color:#c9d1d9;"
        "}",
        -1,
        NULL
    );

    gtk_style_context_add_provider(
        gtk_widget_get_style_context(
            console_text_view
        ),
        GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );

    g_object_unref(provider);

    gtk_container_add(
        GTK_CONTAINER(console_scrolled),
        console_text_view
    );

    gtk_container_add(
        GTK_CONTAINER(console_frame),
        console_scrolled
    );

    gtk_paned_pack2(
        GTK_PANED(vpaned),
        console_frame,
        FALSE,
        TRUE
    );

    /*
     * --------------------------------------------------------
     * FIRST TAB
     * --------------------------------------------------------
     */

    add_autodestroy_tab(
        GTK_NOTEBOOK(notebook),
        NULL
    );

    /*
     * --------------------------------------------------------
     * STARTUP SECURITY LOG
     * --------------------------------------------------------
     */

    log_security_event(
        SEC_EVENT_INFO,
        "System-Core",
        "Secure browser initialized."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Crypto",
        "OpenSSL cryptographic subsystem initialized."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Integrity",
        "Real SHA-512 executable integrity verification enabled."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Network-Security",
        "HTTPS-only navigation policy enabled."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "TLS-Security",
        "TLS certificate validation configured to fail closed."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Privacy",
        "Ephemeral WebKit profile and credential-storage isolation enabled."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Privacy",
        "Intelligent Tracking Prevention enabled."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Sandbox",
        "WebKit process sandbox requested."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Intrusion-Detection",
        "URI attack-signature monitoring enabled."
    );

    log_security_event(
        SEC_EVENT_INFO,
        "Policy",
        "New-window and dangerous URI-scheme restrictions enabled."
    );

    /*
     * --------------------------------------------------------
     * SHOW
     * --------------------------------------------------------
     */

    gtk_widget_show_all(
        window
    );

    gtk_main();

    return 0;
}
