/**
 * worker.js — Shared contact form Worker
 *
 * Deployed to: Cloudflare Workers (rr-shared-contact)
 * Handles route: www.[customer].com/mailform
 *
 * ROLE IN THE STACK
 * -----------------
 * This Worker is the intelligent layer between the customer's form
 * and the PHP mail relay on Dreamhost. It handles everything that
 * requires logic or validation, so PHP can be a simple, dumb mail relay.
 *
 * Execution order on every form submission:
 *
 *   1.  Identify the customer from the Host header
 *   2.  Parse the form body
 *   3.  Parse redirect field immediately — used on ALL exit paths from here
 *   4.  Validate the field set — no unexpected fields allowed
 *   5.  Validate required fields are present and non-empty
 *   6.  Validate email address format (RFC 5322)
 *   7.  Validate email domain has MX records (DNS lookup)
 *   8.  Scan name and message for spam / malicious content
 *   9.  POST clean data to PHP relay with shared secret header
 *   10. Handle PHP response and redirect browser accordingly
 *
 * CUSTOMER CONFIGURATION
 * ----------------------
 * Add or remove customers in the CUSTOMERS object below.
 * Domain keys must be lowercase and without www prefix.
 * Redeployment via Git push is required after any change:
 *   1. Edit CUSTOMERS object
 *   2. Commit and push via Git Desktop
 *   3. Add WAF Managed Challenge rule in customer's Cloudflare dashboard:
 *        Expression: http.request.uri.path eq "/mailform"
 *                    and http.request.method eq "POST"
 *        Action: Managed Challenge
 *   4. Add route www.customer.com/mailform → rr-shared-contact
 *   5. Point form action to https://www.customer.com/mailform
 *      and confirm form submits as a traditional POST
 *
 * SECRETS
 * -------
 * The shared secret sent to PHP in the X-WAF-Secret header is stored
 * as a Cloudflare Worker secret set in the Cloudflare dashboard:
 *   Workers & Pages → rr-shared-contact → Settings → Variables and Secrets
 * It is accessible in code as env.FORM_SECRET.
 * It must match the value configured in .htaccess on Dreamhost.
 *
 * DEBUGGING
 * ---------
 * Set DEBUG = true to enable verbose logging in Cloudflare Workers logs.
 * Set DEBUG = false for production — no log overhead, no sensitive data exposure.
 * After changing, commit and push via Git Desktop to redeploy.
 *
 * ROUTE BINDING
 * -------------
 * Each customer domain needs one route in their Cloudflare dashboard:
 *   www.customer.com/mailform  →  rr-shared-contact
 */


// ============================================================
// DEBUG FLAG
// ============================================================

/**
 * Set to true to enable verbose step-by-step logging in Cloudflare Workers logs.
 * Set to false for production — skips all debug logging entirely.
 * Change this, commit, and push to toggle without touching any other code.
 */
const DEBUG = false;


// ============================================================
// CUSTOMER CONFIGURATION
// ============================================================

/**
 * Maps each customer domain to their configuration.
 * Domain keys must be lowercase and without www prefix.
 *
 * Fields:
 *   recipient — Email address where contact form submissions are delivered.
 *               Must be a valid, monitored mailbox.
 */
const CUSTOMERS = {
    "richardsonresources.com": {
        recipient: "mdr6273@gmail.com"
    },
    "krystenezehnder.com": {
        recipient: "mdr6273@gmail.com"
    }
    // Add customers here following the pattern above
};


// ============================================================
// CONSTANTS
// ============================================================

/**
 * The PHP relay endpoint that sends the email.
 * All validated submissions are forwarded here.
 */
const PHP_ENDPOINT = "https://customertools.richardsonresources.com/formactions/shared-contact.php";

/**
 * Allowed form field names. Any submission containing fields outside
 * this set is treated as a bot or probe — fake success, discard.
 *
 * recaptchaResponse  — Added by Nicepage automatically when using Email submit
 * cf-turnstile-response — Added by Cloudflare Turnstile if used in future
 */
const ALLOWED_FIELDS = new Set([
    "name",
    "email",
    "message",
    "redirect",
    "recaptchaResponse",
    "cf-turnstile-response"
]);

/**
 * Fields that must be present and non-empty on every submission.
 */
const REQUIRED_FIELDS = ["name", "email", "message"];

/**
 * The fallback redirect target used only when no form data is available
 * (steps 1 and 2) and a redirect field cannot yet be parsed.
 */
const ROOT_REDIRECT = { path: "/", anchor: "" };

/**
 * User-facing messages.
 * Legitimate success and silent rejection use ui-msgtype=success but differ
 * subtly so you can verify spam filtering is working during testing.
 */
const MESSAGES = {
    success:      "Your message has been sent.",
    silentReject: "Your message has been sent !!!",
    failure:      "Something went wrong. Reference: "
};


// ============================================================
// MAIN HANDLER
// ============================================================

export default {

    /**
     * fetch() is the entry point Cloudflare calls for every HTTP request
     * that matches this Worker's route.
     *
     *   request — The incoming HTTP request from the browser
     *   env     — Environment bindings including secrets (env.FORM_SECRET)
     *   ctx     — Execution context (not used here)
     */
    async fetch(request, env, ctx) {

        debug("Worker fired:", request.method, request.url);

        const url      = new URL(request.url);
        const hostname = url.hostname.replace(/^www\./, "");

        debug("hostname resolved to:", hostname);

        // --------------------------------------------------------
        // STEP 1 — Identify the customer
        // --------------------------------------------------------
        // Look up the hostname in the customer config. If not found,
        // this request came from an unknown domain — return fake success.
        // Falls back to ROOT_REDIRECT because we have no form data yet.

        const customer = CUSTOMERS[hostname];

        debug("customer lookup result:", customer ? "found" : "NOT FOUND");

        if (!customer) {
            debug("exiting — unknown domain");
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // Validate the recipient address format before we do anything else.
        // This catches config typos early.
        const recipientValid = isValidEmailFormat(customer.recipient);
        debug("recipient format valid:", recipientValid, "—", customer.recipient);

        if (!recipientValid) {
            console.error(`[shared-contact] Invalid recipient format for domain: ${hostname} — check CUSTOMERS config`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 2 — Parse the form body
        // --------------------------------------------------------
        // Nicepage submits forms as application/x-www-form-urlencoded.
        // Falls back to ROOT_REDIRECT on failure — still no form data.

        let formData;

        try {
            const body = await request.formData();
            formData = Object.fromEntries(body.entries());
            debug("form parsed OK, fields received:", Object.keys(formData).join(", "));
        } catch (e) {
            console.error(`[shared-contact] Failed to parse form body: ${e.message}`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 3 — Parse redirect field
        // --------------------------------------------------------
        // Parse immediately after we have form data. From this point on,
        // every exit path uses this validated redirect target rather than
        // falling back to root.

        const redirectTarget = parseRedirect((formData.redirect ?? "").trim());
        debug("redirect target:", JSON.stringify(redirectTarget));

        // --------------------------------------------------------
        // STEP 4 — Validate the field set
        // --------------------------------------------------------
        // Any field not in ALLOWED_FIELDS means this is not coming from
        // one of our forms — bots often add extra fields when probing.

        for (const key of Object.keys(formData)) {
            if (!ALLOWED_FIELDS.has(key)) {
                debug("exiting — unexpected field detected:", key);
                return fakeSuccess(url, redirectTarget);
            }
        }

        debug("field set valid");

        // --------------------------------------------------------
        // STEP 5 — Validate required fields
        // --------------------------------------------------------

        const name    = (formData.name    ?? "").trim();
        const email   = (formData.email   ?? "").trim();
        const message = (formData.message ?? "").trim();

        debug("name:", name ? "present" : "MISSING");
        debug("email:", email ? "present" : "MISSING");
        debug("message:", message ? "present" : "MISSING");

        for (const field of REQUIRED_FIELDS) {
            if (!formData[field] || !formData[field].trim()) {
                debug("exiting — missing required field:", field);
                return fakeSuccess(url, redirectTarget);
            }
        }

        debug("required fields all present");

        // --------------------------------------------------------
        // STEP 6 — Validate email format
        // --------------------------------------------------------

        const emailFormatValid = isValidEmailFormat(email);
        debug("email format valid:", emailFormatValid, "—", email);

        if (!emailFormatValid) {
            debug("exiting — invalid email format");
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 7 — Validate email domain has MX records
        // --------------------------------------------------------

        const emailDomain = email.split("@")[1];
        debug("checking MX records for domain:", emailDomain);

        const mxValid = await hasMxRecords(emailDomain);
        debug("MX records found:", mxValid);

        if (!mxValid) {
            debug("exiting — no MX records for:", emailDomain);
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 8 — Spam and malicious content check
        // --------------------------------------------------------
        // Field-appropriate rules — name permits apostrophes (O'Brien).
        // Both block URLs only — the real deliverability concern.

        const nameSpam    = isSpamOrMaliciousName(name);
        const messageSpam = isSpamOrMaliciousMessage(message);

        debug("name spam check:", nameSpam ? "FLAGGED" : "clean");
        debug("message spam check:", messageSpam ? "FLAGGED" : "clean");

        if (nameSpam || messageSpam) {
            debug("exiting — spam or malicious content detected");
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 9 — POST to PHP relay
        // --------------------------------------------------------
        // X-WAF-Secret header authenticates the request — .htaccess on
        // Dreamhost blocks anything without the correct secret before
        // PHP even loads.

        debug("all checks passed — posting to PHP...");

        let phpResponse;

        try {
            phpResponse = await fetch(PHP_ENDPOINT, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-WAF-Secret": env.FORM_SECRET,
                },
                body: JSON.stringify({
                    recipient: customer.recipient,
                    domain:    hostname,
                    name:      name,
                    email:     email,
                    message:   message,
                }),
            });
            debug("PHP response status:", phpResponse.status);
        } catch (e) {
            console.error(`[shared-contact] Network error reaching PHP endpoint: ${e.message}`);
            return failRedirect(url, redirectTarget, generateRef());
        }

        // --------------------------------------------------------
        // STEP 10 — Handle PHP response and redirect browser
        // --------------------------------------------------------

        let phpRawBody;
        let phpData;

        try {
            phpRawBody = await phpResponse.text();
            debug("PHP raw response:", phpRawBody.substring(0, 200));
            phpData = JSON.parse(phpRawBody);
            debug("PHP response body:", JSON.stringify(phpData));
        } catch (e) {
            console.error(`[shared-contact] Could not parse PHP response: ${e.message}`);
            console.error(`[shared-contact] Raw body was: ${phpRawBody ? phpRawBody.substring(0, 200) : "empty"}`);
            return failRedirect(url, redirectTarget, generateRef());
        }

        if (phpData.success) {
            debug("success — redirecting with success message");
            return successRedirect(url, redirectTarget);
        } else {
            debug("PHP reported failure, ref:", phpData.ref);
            return failRedirect(url, redirectTarget, phpData.ref ?? generateRef());
        }
    }
};


// ============================================================
// DEBUG HELPER
// ============================================================

/**
 * debug()
 *
 * Logs a message to Cloudflare Workers logs only when DEBUG is true.
 * In production (DEBUG = false) this function is a no-op — zero overhead.
 * All arguments are passed through to console.log as-is.
 *
 * Usage: debug("label:", value);
 */
function debug(...args) {
    if (DEBUG) console.log("[debug]", ...args);
}


// ============================================================
// REDIRECT HELPERS
// ============================================================

/**
 * buildRedirectUrl()
 *
 * Constructs the final redirect URL from its components.
 * Always uses https:// and www. prefix.
 * Query string is appended before anchor.
 *
 * Example:
 *   hostname: "acmeplumbing.com", path: "/thank-you", anchor: "contact"
 *   → https://www.acmeplumbing.com/thank-you?ui-msgtype=success&ui-msgdata=...#contact
 */
function buildRedirectUrl(url, path, params, anchor) {
    const host  = url.hostname.startsWith("www.")
        ? url.hostname
        : "www." + url.hostname;
    const query = new URLSearchParams(params).toString();
    let redirectUrl = `https://${host}${path}?${query}`;
    if (anchor) {
        redirectUrl += `#${anchor}`;
    }
    return redirectUrl;
}

/**
 * successRedirect()
 * Redirects with ui-msgtype=success and the real success message.
 * Used when the email was sent successfully.
 */
function successRedirect(url, redirectTarget) {
    const target = buildRedirectUrl(
        url,
        redirectTarget.path,
        {
            "ui-msgtype": "success",
            "ui-msgdata": MESSAGES.success,
        },
        redirectTarget.anchor
    );
    return Response.redirect(target, 302);
}

/**
 * fakeSuccess()
 *
 * Returns a redirect that looks like success but is a silent rejection.
 * Used for spam, invalid fields, unknown domains, and any other case
 * where we want the submitter to believe it worked.
 *
 * Uses redirectTarget if available, ROOT_REDIRECT only in steps 1 and 2
 * before form data has been parsed.
 *
 * The subtle message difference ("sent." vs "sent !!!") lets you verify
 * spam filtering is working during testing.
 */
function fakeSuccess(url, redirectTarget) {
    const target = buildRedirectUrl(
        url,
        redirectTarget.path,
        {
            "ui-msgtype": "success",
            "ui-msgdata": MESSAGES.silentReject,
        },
        redirectTarget.anchor
    );
    return Response.redirect(target, 302);
}

/**
 * failRedirect()
 *
 * Redirects with ui-msgtype=fail and a reference ID for genuine failures.
 * Used only for real system failures (SMTP down, PHP unreachable, etc.).
 * The reference ID appears in both the user-facing message and the PHP log.
 */
function failRedirect(url, redirectTarget, ref) {
    const target = buildRedirectUrl(
        url,
        redirectTarget.path,
        {
            "ui-msgtype": "fail",
            "ui-msgdata": MESSAGES.failure + ref,
        },
        redirectTarget.anchor
    );
    return Response.redirect(target, 302);
}


// ============================================================
// REDIRECT PARSING
// ============================================================

/**
 * parseRedirect()
 *
 * Validates and parses the optional redirect form field.
 * Returns { path, anchor } — falls back to root if invalid or empty.
 *
 * Valid:    /                  → { path: "/",          anchor: "" }
 * Valid:    /thank-you         → { path: "/thank-you", anchor: "" }
 * Valid:    /thank-you#contact → { path: "/thank-you", anchor: "contact" }
 * Valid:    #contact           → { path: "/",          anchor: "contact" }
 * Valid:    /#contact          → { path: "/",          anchor: "contact" }
 * Invalid:  https://...        → { path: "/",          anchor: "" }
 * Invalid:  //evil.com         → { path: "/",          anchor: "" }
 * Invalid:  ?query=string      → { path: "/",          anchor: "" }
 * Empty:    ""                 → { path: "/",          anchor: "" }
 */
function parseRedirect(redirect) {
    const fallback = { path: "/", anchor: "" };
    if (!redirect) return fallback;

    // Anchor-only e.g. "#contact" → root path with anchor
    if (redirect.startsWith("#")) {
        return { path: "/", anchor: sanitizeAnchor(redirect.slice(1)) };
    }

    if (!redirect.startsWith("/"))      return fallback;
    if (redirect.includes("://"))       return fallback;
    if (redirect.startsWith("//"))      return fallback;
    if (redirect.includes("?"))         return fallback;

    const hashIndex = redirect.indexOf("#");
    if (hashIndex === -1) return { path: redirect, anchor: "" };

    return {
        path:   redirect.slice(0, hashIndex) || "/",
        anchor: sanitizeAnchor(redirect.slice(hashIndex + 1)),
    };
}

/**
 * sanitizeAnchor()
 *
 * Strips characters that aren't valid in HTML fragment identifiers.
 * Prevents injection of unexpected characters into the redirect URL.
 */
function sanitizeAnchor(anchor) {
    return anchor.replace(/[^a-zA-Z0-9\-_\.]/g, "");
}


// ============================================================
// VALIDATION HELPERS
// ============================================================

/**
 * isValidEmailFormat()
 *
 * Checks that a string looks like a valid email address (format only).
 * MX record validation happens separately in hasMxRecords().
 */
function isValidEmailFormat(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    return re.test(email);
}

/**
 * hasMxRecords()
 *
 * Checks whether a domain has MX records via Cloudflare DNS-over-HTTPS.
 * Uses 1.1.1.1 — always available from within a Cloudflare Worker.
 * Returns false on any error — fails conservatively.
 */
async function hasMxRecords(domain) {
    try {
        const response = await fetch(
            `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
            { headers: { "Accept": "application/dns-json" } }
        );
        if (!response.ok) return false;
        const data = await response.json();
        return data.Status === 0
            && Array.isArray(data.Answer)
            && data.Answer.length > 0;
    } catch (e) {
        console.error(`[shared-contact] MX lookup failed for ${domain}: ${e.message}`);
        return false;
    }
}

/**
 * isSpamOrMaliciousName()
 *
 * Checks a name field for spam or malicious content.
 * Apostrophes are permitted for names like O'Brien, D'Angelo.
 *
 * Blocks:
 *   - http:// and https:// URLs
 *   - www. patterns
 *   - HTML tags
 */
function isSpamOrMaliciousName(value) {
    const checks = [
        /https?:\/\//i, // http:// or https:// URLs
        /www\./i,        // www. URLs without protocol
        /<[^>]+>/,       // HTML tags
    ];
    return checks.some(pattern => pattern.test(value));
}

/**
 * isSpamOrMaliciousMessage()
 *
 * Checks a message field for clickable links that could harm
 * unsuspecting email recipients. Intentionally narrow — we only
 * block content that would be dangerous in a plain text email.
 *
 * HTML tags are not blocked because PHP sends plain text email
 * so tags arrive literally and cannot be rendered or clicked.
 *
 * Blocks:
 *   - http:// and https:// URLs (render as clickable links in email)
 *   - www. patterns (render as clickable links in most email clients)
 *
 * Does NOT block:
 *   - Bare domain patterns (too many false positives)
 *   - HTML tags (no execution context in plain text email)
 *   - SQL/script keywords (no execution context in email)
 *   - Spam keywords (too aggressive, catches legitimate messages)
 */
function isSpamOrMaliciousMessage(value) {
    const checks = [
        /https?:\/\//i, // http:// or https:// URLs
        /www\./i,        // www. URLs without protocol
    ];
    return checks.some(pattern => pattern.test(value));
}


// ============================================================
// UTILITY HELPERS
// ============================================================

/**
 * generateRef()
 *
 * Generates a short reference ID for error tracking.
 * Format: REF-YYYYMMDD-XXXX where XXXX is 4 random hex characters.
 * Matches the format used by PHP so references are consistent
 * whether the error originates in the Worker or in PHP.
 *
 * Example output: REF-20260504-A3F7
 */
function generateRef() {
    const now  = new Date();
    const date = now.toISOString().slice(0, 10).replace(/-/g, "");
    const rand = Math.floor(Math.random() * 0xFFFF)
                     .toString(16)
                     .toUpperCase()
                     .padStart(4, "0");
    return `REF-${date}-${rand}`;
}
