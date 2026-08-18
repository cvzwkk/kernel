#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <libsoup/soup.h>
#include <string.h>
#include <glib/gstdio.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#if defined(GDK_WINDOWING_X11)
#include <gdk/gdkx.h>
#elif defined(GDK_WINDOWING_WAYLAND)
#include <gdk/gdkwayland.h>
#endif

/* ============================================================
 *  SECURITY EVENT CONSOLE
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

static void
log_security_event(SecurityEventType type,
                   const gchar *source,
                   const gchar *message)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    gchar time_str[64] = {0};

    if (t != NULL) {
        strftime(time_str, sizeof(time_str),
                 "%Y-%m-%d %H:%M:%S", t);
    } else {
        g_strlcpy(time_str, "UNKNOWN-TIME", sizeof(time_str));
    }

    const gchar *prefix = "[INFO]";

    switch (type) {
        case SEC_EVENT_INFO:
            prefix = "[INFO]";
            break;

        case SEC_EVENT_VIOLATION:
            prefix = "[SECURITY VIOLATION]";
            break;

        case SEC_EVENT_THEFT_ATTEMPT:
            prefix = "[THEFT ATTEMPT]";
            break;

        case SEC_EVENT_INTRUSION:
            prefix = "[INTRUSION DETECTED]";
            break;

        case SEC_EVENT_FILE_MOD:
            prefix = "[FILE/MODULE MOD]";
            break;

        case SEC_EVENT_NETWORK_ANOMALY:
            prefix = "[NETWORK ANOMALY]";
            break;
    }

    gchar *log_line = g_strdup_printf(
        "[%s] %s [%s]: %s\n",
        time_str,
        prefix,
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
        gtk_text_buffer_get_end_iter(buffer, &end);

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

        gtk_text_buffer_delete_mark(buffer, mark);
    }

    g_free(log_line);
}


/* ============================================================
 *  HYBRID POST-QUANTUM KDF (OpenSSL 3.x)
 *
 *  Construction:
 *        X25519 shared secret  (32 bytes)
 *                +
 *        ML-KEM-768 shared secret (32 bytes)
 *                |
 *                v
 *        HKDF-SHA-512
 *            IKM  = "HYBRID-PQ-X25519-MLKEM768-v1" || X25519 || ML-KEM
 *            salt = optional caller-supplied salt
 *            info = domain || "BROWSER-HYBRID-PQ-AES256GCM-V1"
 *                |
 *                v
 *        256-bit AES-GCM key
 *
 *  Requires OpenSSL 3.x (link with -lcrypto).
 *  Compatible with the rest of this browser's GLib / security-console style.
 * ============================================================ */

#define HYBRID_AES_KEY_SIZE  32
#define HYBRID_SECRET_SIZE   32
#define HYBRID_MAX_DOMAIN_LEN 256

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
    gboolean      success = FALSE;
    EVP_KDF      *kdf     = NULL;
    EVP_KDF_CTX  *kctx    = NULL;
    guint8       *ikm     = NULL;
    guint8       *info    = NULL;
    gsize         ikm_len = 0;
    gsize         info_len = 0;

    /* ---- 1. Parameter validation ---- */
    if (x25519_secret == NULL || mlkem_secret == NULL ||
        output_key == NULL || domain == NULL) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "NULL parameter passed to hybrid_pq_derive_aes256_key");
        return FALSE;
    }

    if (x25519_secret_len != HYBRID_SECRET_SIZE ||
        mlkem_secret_len  != HYBRID_SECRET_SIZE) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "Invalid shared-secret length (expected 32 bytes)");
        return FALSE;
    }

    gsize domain_len = strlen(domain);
    if (domain_len == 0 || domain_len > HYBRID_MAX_DOMAIN_LEN) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "Invalid domain length");
        return FALSE;
    }

    /* Always start with a clean output buffer on any failure path */
    OPENSSL_cleanse(output_key, HYBRID_AES_KEY_SIZE);

    /* ---- 2. Build IKM = label || X25519_ss || ML-KEM_ss ---- */
    static const char label[] = "HYBRID-PQ-X25519-MLKEM768-v1";
    const gsize label_len = sizeof(label) - 1;

    ikm_len = label_len + x25519_secret_len + mlkem_secret_len;
    ikm = g_malloc(ikm_len);
    if (ikm == NULL) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "Out of memory allocating IKM");
        return FALSE;
    }

    gsize off = 0;
    memcpy(ikm + off, label, label_len);                 off += label_len;
    memcpy(ikm + off, x25519_secret, x25519_secret_len); off += x25519_secret_len;
    memcpy(ikm + off, mlkem_secret,  mlkem_secret_len);

    /* ---- 3. Build info = domain || protocol_id ---- */
    static const guint8 protocol_id[] = "BROWSER-HYBRID-PQ-AES256GCM-V1";
    const gsize proto_id_len = sizeof(protocol_id) - 1;

    info_len = domain_len + proto_id_len;
    info = g_malloc(info_len);
    if (info == NULL) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "Out of memory allocating info");
        goto cleanup;
    }

    memcpy(info, domain, domain_len);
    memcpy(info + domain_len, protocol_id, proto_id_len);

    /* ---- 4. OpenSSL 3.x HKDF-SHA-512 ---- */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "EVP_KDF_fetch(HKDF) failed");
        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "EVP_KDF_CTX_new failed");
        goto cleanup;
    }

    /*
     * params[6] is required:
     *   digest + key + [salt] + info + end
     */
    OSSL_PARAM params[6];
    int p = 0;

    static const char *md_name = "SHA512";

    params[p++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)md_name, 0);

    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, ikm, ikm_len);

    if (salt != NULL && salt_len > 0) {
        params[p++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    }

    params[p++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, info_len);

    params[p++] = OSSL_PARAM_construct_end();

    /* ---- 5. Derive ---- */
    if (EVP_KDF_derive(kctx, output_key, HYBRID_AES_KEY_SIZE, params) <= 0) {
        OPENSSL_cleanse(output_key, HYBRID_AES_KEY_SIZE);
        log_security_event(SEC_EVENT_VIOLATION,
                           "Hybrid-PQ-KDF",
                           "EVP_KDF_derive failed");
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (ikm) {
        OPENSSL_cleanse(ikm, ikm_len);
        g_free(ikm);
    }
    if (info) {
        OPENSSL_cleanse(info, info_len);
        g_free(info);
    }
    if (kctx)
        EVP_KDF_CTX_free(kctx);
    if (kdf)
        EVP_KDF_free(kdf);

    return success;
}


/* ============================================================
 *  FILE INTEGRITY
 * ============================================================ */

static gchar *
compute_file_checksum(const gchar *filepath)
{
    if (filepath == NULL) {
        return NULL;
    }

    GMappedFile *mapped =
        g_mapped_file_new(filepath, FALSE, NULL);

    if (mapped == NULL) {
        return NULL;
    }

    const gchar *contents =
        g_mapped_file_get_contents(mapped);

    gsize length =
        g_mapped_file_get_length(mapped);

    guint8 digest[64];

    secure_domain_hash(
        (const guint8 *)contents,
        length,
        digest,
        sizeof(digest),
        "BROWSER-FILE-INTEGRITY-V3"
    );

    gchar *hex =
        g_malloc0(sizeof(digest) * 2 + 1);

    for (gsize i = 0; i < sizeof(digest); ++i) {
        g_snprintf(
            hex + (i * 2),
            3,
            "%02x",
            digest[i]
        );
    }

    g_mapped_file_unref(mapped);

    return hex;
}


static void
verify_module_integrity(const gchar *binary_path)
{
    gchar *hash =
        compute_file_checksum(binary_path);

    if (hash != NULL) {

        gchar *message =
            g_strdup_printf(
                "SHA-512 domain-separated module checksum: %s",
                hash
            );

        log_security_event(
            SEC_EVENT_INFO,
            "Module-Integrity",
            message
        );

        g_free(message);
        g_free(hash);

    } else {

        log_security_event(
            SEC_EVENT_FILE_MOD,
            "Module-Integrity",
            "Unable to read executable for integrity verification."
        );
    }
}


/* ============================================================
 *  SECURED COOKIE SUBSYSTEM
 * ============================================================ */

typedef struct {
    gchar *cookie_name;
    gchar *domain;

    guint8 ciphertext[256];
    gsize ciphertext_len;

    guint8 current_pq_state[64];

    guint64 version_counter;

} PostQuantumSecuredCookie;


static void
pq_ratchet_cookie_key(PostQuantumSecuredCookie *cookie)
{
    if (cookie == NULL) {
        return;
    }

    cookie->version_counter++;

    guint8 combined[72];

    memcpy(
        combined,
        cookie->current_pq_state,
        64
    );

    memcpy(
        combined + 64,
        &cookie->version_counter,
        sizeof(cookie->version_counter)
    );

    secure_domain_hash(
        combined,
        sizeof(combined),
        cookie->current_pq_state,
        64,
        "COOKIE-RATCHET-V3"
    );
}


static PostQuantumSecuredCookie *
pq_create_or_update_cookie(const gchar *domain,
                           const gchar *name,
                           const gchar *plain_value,
                           const guint8 *initial_seed)
{
    if (domain == NULL ||
        name == NULL ||
        plain_value == NULL ||
        *domain == '\0') {
        return NULL;
    }

    PostQuantumSecuredCookie *cookie =
        g_new0(PostQuantumSecuredCookie, 1);

    cookie->domain =
        g_strdup(domain);

    cookie->cookie_name =
        g_strdup(name);

    cookie->version_counter = 1;


    if (initial_seed != NULL) {

        memcpy(
            cookie->current_pq_state,
            initial_seed,
            sizeof(cookie->current_pq_state)
        );

    } else {

        /*
         * GLib GRand is not a cryptographic RNG.
         * This is retained for compatibility with your original
         * design, but should be replaced by OS CSPRNG for real
         * credential protection.
         */
        GRand *rand =
            g_rand_new();

        for (gsize i = 0; i < 64; ++i) {
            cookie->current_pq_state[i] =
                (guint8)(g_rand_int(rand) & 0xff);
        }

        g_rand_free(rand);
    }


    gsize value_len =
        strlen(plain_value);

    /*
     * The original structure has a fixed 256-byte ciphertext.
     * Reject larger values rather than overflowing it.
     */
    if (value_len > sizeof(cookie->ciphertext)) {
        log_security_event(
            SEC_EVENT_VIOLATION,
            "Cookie-System",
            "Cookie value exceeds the 256-byte subsystem limit."
        );

        g_free(cookie->cookie_name);
        g_free(cookie->domain);
        g_free(cookie);

        return NULL;
    }


    for (gsize i = 0; i < value_len; ++i) {

        guint8 domain_mask =
            (guint8)cookie->domain[
                i % strlen(cookie->domain)
            ];

        cookie->ciphertext[i] =
            ((guint8)plain_value[i] ^
             cookie->current_pq_state[i % 64]) ^
             domain_mask;
    }

    cookie->ciphertext_len =
        value_len;

    pq_ratchet_cookie_key(cookie);

    return cookie;
}


static gchar *
pq_decrypt_cookie(PostQuantumSecuredCookie *cookie,
                  const gchar *accessor_domain)
{
    if (cookie == NULL ||
        accessor_domain == NULL) {
        return NULL;
    }

    if (g_strcmp0(cookie->domain,
                  accessor_domain) != 0) {

        gchar *alert =
            g_strdup_printf(
                "Unauthorized domain '%s' attempted to access "
                "cookie owned by '%s'.",
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


    gchar *plain =
        g_malloc0(
            cookie->ciphertext_len + 1
        );

    for (gsize i = 0;
         i < cookie->ciphertext_len;
         ++i) {

        guint8 domain_mask =
            (guint8)cookie->domain[
                i % strlen(cookie->domain)
            ];

        plain[i] =
            (cookie->ciphertext[i] ^
             domain_mask) ^
             cookie->current_pq_state[i % 64];
    }

    return plain;
}


static void
pq_free_cookie(PostQuantumSecuredCookie *cookie)
{
    if (cookie == NULL) {
        return;
    }

    g_free(cookie->cookie_name);
    g_free(cookie->domain);

    memset(
        cookie->ciphertext,
        0,
        sizeof(cookie->ciphertext)
    );

    memset(
        cookie->current_pq_state,
        0,
        sizeof(cookie->current_pq_state)
    );

    g_free(cookie);
}


/* ============================================================
 *  TAB / PROFILE SECURITY
 * ============================================================ */

typedef struct {
    guint8 key_bytes[64];
    gchar *key_id_hex;
} PostQuantumProfileKey;


typedef struct {
    WebKitWebView *web_view;

    gchar *data_dir;
    gchar *cache_dir;

    GtkWidget *scrolled_window;

    PostQuantumProfileKey *pq_key;

} TabContextData;


static PostQuantumProfileKey *
pq_generate_tab_key(void)
{
    PostQuantumProfileKey *key =
        g_new0(PostQuantumProfileKey, 1);

    GRand *rand =
        g_rand_new();

    guint8 seed[64];

    for (gsize i = 0; i < sizeof(seed); ++i) {
        seed[i] =
            (guint8)(g_rand_int(rand) & 0xff);
    }

    g_rand_free(rand);


    secure_domain_hash(
        seed,
        sizeof(seed),
        key->key_bytes,
        sizeof(key->key_bytes),
        "TAB-KEY-GENERATION-V3"
    );

    return key;
}


static void
free_tab_key(PostQuantumProfileKey *key)
{
    if (key == NULL) {
        return;
    }

    memset(
        key->key_bytes,
        0,
        sizeof(key->key_bytes)
    );

    g_free(key->key_id_hex);
    g_free(key);
}


/* ============================================================
 *  SECURE PROFILE CLEANUP
 * ============================================================ */

static void
recursively_delete_directory(const gchar *dirname)
{
    if (dirname == NULL ||
        *dirname == '\0') {
        return;
    }

    GDir *dir =
        g_dir_open(dirname, 0, NULL);

    if (dir == NULL) {
        return;
    }

    const gchar *filename;

    while ((filename = g_dir_read_name(dir)) != NULL) {

        gchar *filepath =
            g_build_filename(
                dirname,
                filename,
                NULL
            );

        if (g_file_test(
                filepath,
                G_FILE_TEST_IS_DIR)) {

            recursively_delete_directory(filepath);

        } else {

            g_unlink(filepath);
        }

        g_free(filepath);
    }

    g_dir_close(dir);

    g_rmdir(dirname);
}


static void
on_tab_destroy_cleanup(GtkWidget *widget,
                       gpointer user_data)
{
    (void)widget;

    TabContextData *tab =
        (TabContextData *)user_data;

    if (tab == NULL) {
        return;
    }

    log_security_event(
        SEC_EVENT_INFO,
        "Auto-Destruct",
        "Tab closed. Removing temporary profile sandbox and caches."
    );


    if (tab->data_dir != NULL) {
        recursively_delete_directory(
            tab->data_dir
        );
    }

    /*
     * cache_dir is normally inside data_dir, so attempting to
     * remove it separately is harmless.
     */
    if (tab->cache_dir != NULL) {
        recursively_delete_directory(
            tab->cache_dir
        );
    }


    free_tab_key(tab->pq_key);

    g_free(tab->data_dir);
    g_free(tab->cache_dir);

    g_free(tab);
}


/* ============================================================
 *  URI / INTRUSION DETECTION
 * ============================================================ */

static gboolean
uri_contains_suspicious_pattern(const gchar *uri)
{
    if (uri == NULL) {
        return FALSE;
    }

    /*
     * Basic indicators only.
     * These are NOT a complete IDS/WAF.
     */
    static const gchar *patterns[] = {
        "<script>",
        "union select",
        "../../../",
        "%3cscript",
        "%3Cscript",
        "../",
        NULL
    };

    for (gsize i = 0;
         patterns[i] != NULL;
         ++i) {

        if (g_strstr_len(
                uri,
                -1,
                patterns[i])) {
            return TRUE;
        }
    }

    return FALSE;
}


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


    if (decision_type !=
        WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {
        return FALSE;
    }


    WebKitNavigationPolicyDecision *nav =
        WEBKIT_NAVIGATION_POLICY_DECISION(
            decision
        );

    WebKitNavigationAction *action =
        webkit_navigation_policy_decision_get_navigation_action(
            nav
        );

    if (action == NULL) {
        return FALSE;
    }


    WebKitURIRequest *request =
        webkit_navigation_action_get_request(
            action
        );

    if (request == NULL) {
        return FALSE;
    }


    const gchar *uri =
        webkit_uri_request_get_uri(request);

    if (uri == NULL) {
        return FALSE;
    }


    /*
     * --------------------------------------------------------
     * BLOCK CLEAR-TEXT HTTP
     * --------------------------------------------------------
     */

    if (g_str_has_prefix(uri, "http://") &&
        !g_str_has_prefix(uri, "http://localhost")) {

        gchar *message =
            g_strdup_printf(
                "Cleartext HTTP navigation blocked: %s",
                uri
            );

        log_security_event(
            SEC_EVENT_NETWORK_ANOMALY,
            "Network-Security",
            message
        );

        g_free(message);


        const gchar *block_html =
            "<!doctype html>"
            "<html>"
            "<head>"
            "<meta charset='utf-8'>"
            "<title>Blocked</title>"
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
            "text-align:center;"
            "background:#161b22;"
            "padding:40px;"
            "border:1px solid #30363d;"
            "border-radius:8px;'>"

            "<h2 style='color:#f85149;'>"
            "Network Traffic Blocked"
            "</h2>"

            "<p>"
            "Cleartext HTTP navigation is disabled "
            "by the browser security policy."
            "</p>"

            "</div>"
            "</body>"
            "</html>";


        webkit_web_view_load_alternate_html(
            web_view,
            block_html,
            uri,
            NULL
        );

        webkit_policy_decision_ignore(
            decision
        );

        return TRUE;
    }


    /*
     * --------------------------------------------------------
     * INTRUSION SIGNATURE DETECTION
     * --------------------------------------------------------
     */

    if (uri_contains_suspicious_pattern(uri)) {

        gchar *message =
            g_strdup_printf(
                "Suspicious URI attack signature detected: %s",
                uri
            );

        log_security_event(
            SEC_EVENT_INTRUSION,
            "Intrusion-Detection",
            message
        );

        g_free(message);
    }


    /*
     * --------------------------------------------------------
     * INTERNAL SEARCH ROUTER
     * --------------------------------------------------------
     */

    if (g_str_has_prefix(
            uri,
            "internal://search")) {

        const gchar *query =
            strchr(uri, '?');

        if (query != NULL) {
            query++;
        } else {
            query = "";
        }


        /*
         * Extract q= if present.
         */
        const gchar *q =
            g_strstr_len(
                query,
                -1,
                "q="
            );

        if (q != NULL) {

            q += 2;

            gchar *decoded =
                g_uri_unescape_string(
                    q,
                    NULL
                );

            if (decoded == NULL) {
                decoded = g_strdup(q);
            }


            gchar *escaped =
                g_uri_escape_string(
                    decoded,
                    NULL,
                    TRUE
                );


            gchar *search_url =
                g_strdup_printf(
                    "https://html.duckduckgo.com/html/?q=%s",
                    escaped
                );


            log_security_event(
                SEC_EVENT_INFO,
                "Secure-Search",
                "Routing internal search request to HTTPS search endpoint."
            );


            webkit_web_view_load_uri(
                web_view,
                search_url
            );


            g_free(search_url);
            g_free(escaped);
            g_free(decoded);

            webkit_policy_decision_ignore(
                decision
            );

            return TRUE;
        }
    }


    return FALSE;
}


/* ============================================================
 *  CREATE SECURE TAB
 * ============================================================ */

static void
add_autodestroy_tab(GtkNotebook *nb,
                    const gchar *initial_uri)
{
    gchar *unique_id =
        g_uuid_string_random();


    gchar *data_dir =
        g_build_filename(
            g_get_user_cache_dir(),
            "secure_browser_profiles",
            unique_id,
            NULL
        );


    gchar *cache_dir =
        g_build_filename(
            data_dir,
            "cache",
            NULL
        );


    /*
     * Create profile directories before WebKit uses them.
     */
    g_mkdir_with_parents(
        cache_dir,
        0700
    );


    TabContextData *tab =
        g_new0(TabContextData, 1);

    tab->data_dir =
        g_strdup(data_dir);

    tab->cache_dir =
        g_strdup(cache_dir);

    tab->pq_key =
        pq_generate_tab_key();


    /*
     * --------------------------------------------------------
     * PRIVATE WEBKIT DATA MANAGER
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


    /*
     * Ephemeral mode means WebKit should avoid persistent
     * website data where possible.
     */
    webkit_website_data_manager_set_ephemeral(
        manager,
        TRUE
    );


    WebKitWebContext *context =
        webkit_web_context_new_with_website_data_manager(
            manager
        );


    WebKitSettings *settings =
        webkit_settings_new();


    webkit_settings_set_enable_javascript(
        settings,
        TRUE
    );


    /*
     * Treat TLS errors as fatal where supported.
     */
    webkit_settings_set_tls_errors_are_fatal(
        settings,
        TRUE
    );


    WebKitWebView *web_view =
        WEBKIT_WEB_VIEW(
            webkit_web_view_new_with_context_and_settings(
                context,
                settings
            )
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
     * SECURITY POLICY
     * --------------------------------------------------------
     */

    g_signal_connect(
        web_view,
        "decide-policy",
        G_CALLBACK(zero_trust_policy_decision_cb),
        tab
    );


    /*
     * --------------------------------------------------------
     * SCROLLED BROWSER AREA
     * --------------------------------------------------------
     */

    GtkWidget *scrolled =
        gtk_scrolled_window_new(
            NULL,
            NULL
        );

    tab->scrolled_window =
        scrolled;


    gtk_container_add(
        GTK_CONTAINER(scrolled),
        GTK_WIDGET(web_view)
    );


    /*
     * --------------------------------------------------------
     * TAB LABEL
     * --------------------------------------------------------
     */

    GtkWidget *tab_box =
        gtk_box_new(
            GTK_ORIENTATION_HORIZONTAL,
            4
        );


    GtkWidget *tab_label =
        gtk_label_new(
            "PQ Secure Tab"
        );


    gtk_box_pack_start(
        GTK_BOX(tab_box),
        tab_label,
        TRUE,
        TRUE,
        0
    );


    gtk_widget_show_all(
        tab_box
    );


    gint page_num =
        gtk_notebook_append_page(
            nb,
            scrolled,
            tab_box
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
        "Private tab isolation and network security "
        "monitoring are active."
        "</p>"

        "<form action='internal://search' method='GET'>"

        "<input "
        "type='text' "
        "name='q' "
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
}


/* ============================================================
 *  MAIN WINDOW
 * ============================================================ */

int
main(int argc, char *argv[])
{
    /*
     * --------------------------------------------------------
     * GTK INITIALIZATION
     * --------------------------------------------------------
     */

    gtk_init(
        &argc,
        &argv
    );


    /*
     * --------------------------------------------------------
     * SELF-INTEGRITY CHECK
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
        1100,
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
     * MAIN VERTICAL PANED LAYOUT
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
     * BROWSER AREA
     * --------------------------------------------------------
     */

    GtkWidget *browser_box =
        gtk_box_new(
            GTK_ORIENTATION_VERTICAL,
            0
        );


    gtk_paned_pack1(
        GTK_PANED(vpaned),
        browser_box,
        TRUE,
        FALSE
    );


    notebook =
        gtk_notebook_new();


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
        200
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


    /*
     * Monospace console font.
     */
    PangoFontDescription *font_desc =
        pango_font_description_from_string(
            "Monospace 10"
        );


    gtk_widget_override_font(
        console_text_view,
        font_desc
    );


    pango_font_description_free(
        font_desc
    );


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
     * FIRST SECURE TAB
     * --------------------------------------------------------
     */

    add_autodestroy_tab(
        GTK_NOTEBOOK(notebook),
        NULL
    );


    /*
     * --------------------------------------------------------
     * STARTUP LOGS
     * --------------------------------------------------------
     */

    log_security_event(
        SEC_EVENT_INFO,
        "System-Core",
        "Secure browser initialized."
    );


    log_security_event(
        SEC_EVENT_INFO,
        "Integrity",
        "Domain-separated SHA-512 integrity subsystem initialized."
    );


    log_security_event(
        SEC_EVENT_INFO,
        "Network-Security",
        "Cleartext HTTP navigation blocking enabled."
    );


    log_security_event(
        SEC_EVENT_INFO,
        "Privacy",
        "Ephemeral WebKit tab profile initialized."
    );


    log_security_event(
        SEC_EVENT_INFO,
        "Intrusion-Detection",
        "Basic URI attack-signature monitoring enabled."
    );


    /*
     * --------------------------------------------------------
     * SHOW APPLICATION
     * --------------------------------------------------------
     */

    gtk_widget_show_all(
        window
    );


    gtk_main();

    return 0;
}
