/**
 * worker.js — Shared contact form Worker
 *
 * Deployed to: Cloudflare Workers
 * Handles route: www.[customer].com/mailform
 *
 * ROLE IN THE STACK
 * -----------------
 * This Worker is the intelligent layer between the customer's Nicepage
 * form and the PHP mail relay on Dreamhost. It handles everything that
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
 * REDIRECT BEHAVIOUR
 * ------------------
 * The redirect field is parsed as early as possible (step 3) so that
 * every subsequent exit path — including silent rejections — uses the
 * validated redirect target rather than falling back to root.
 *
 * Only steps 1 and 2 fall back to root, because no form data has been
 * successfully parsed yet at those points.
 *
 * CUSTOMER CONFIGURATION
 * ----------------------
 * Add or remove customers in the CUSTOMERS object below.
 * Each entry maps a domain to a recipient email address.
 * Redeployment via Wrangler is required after any change:
 *   wrangler deploy
 *
 * SECRETS
 * -------
 * The shared secret sent to PHP in the X-WAF-Secret header is stored
 * as a Cloudflare Worker secret — never in this source file.
 * Set it once with:
 *   wrangler secret put FORM_SECRET
 *
 * It is accessible in code as env.FORM_SECRET.
 *
 * ROUTE BINDING
 * -------------
 * Each customer domain needs one route in their Cloudflare dashboard:
 *   www.customer.com/mailform  →  this Worker
 *
 * RESPONSE BEHAVIOUR
 * ------------------
 * All paths end in a browser redirect with two query parameters:
 *   ui-msgtype  — "success" or "fail"
 *   ui-msgdata  — Short message for display to the user
 *
 * Spam and validation failures return ui-msgtype=success with a
 * subtly different message so attackers believe their attempt worked:
 *   Legitimate success:  "Your message has been sent."
 *   Silent rejection:    "Your message has been sent !!!"
 *   Genuine failure:     "Something went wrong. Reference: REF-XXXXXXXX"
 *
 * Redirect target is determined by the optional "redirect" form field.
 * See parseRedirect() for full redirect rules.
 */


// ============================================================
// CUSTOMER CONFIGURATION
// ============================================================

/**
 * Maps each customer domain to their configuration.
 * Domain keys must be lowercase and without www prefix.
 *
 * Fields:
 *   recipient  — Email address where contact form submissions are delivered.
 *                Must be a valid, monitored mailbox. Validated for format
 *                here — delivery failures surface as errors in PHP logs.
 *
 * To add a customer:
 *   1. Add an entry here
 *   2. Run: wrangler deploy
 *   3. Add route www.customer.com/mailform in their Cloudflare dashboard
 *      pointing at this Worker
 *
 * To remove a customer:
 *   1. Remove the entry here
 *   2. Run: wrangler deploy
 *   3. Remove the route from their Cloudflare dashboard
 */
const CUSTOMERS = {
    "example.com": {
        recipient: "owner@example.com"
    },
    "ceincsd.com": {
        recipient: "owner@ceincsd.com"
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
 * "redirect" is optional but must be in this list to be accepted.
 */
const ALLOWED_FIELDS = new Set(["name", "email", "message", "redirect"]);

/**
 * Fields that must be present and non-empty on every submission.
 */
const REQUIRED_FIELDS = ["name", "email", "message"];

/**
 * The fallback redirect target used only when no form data is available
 * (steps 1 and 2) and a redirect field cannot yet be parsed.
 * All subsequent steps use the parsed redirect from the form.
 */
const ROOT_REDIRECT = { path: "/", anchor: "" };

/**
 * User-facing messages. Keeping these here makes them easy to find
 * and update without hunting through the logic below.
 */
const MESSAGES = {
    success:      "Your message has been sent.",
    silentReject: "Your message has been sent !!!",   // Spam / validation failure — looks like success
    failure:      "Something went wrong. Reference: " // Appended with REF-XXXXXXXX
};


// ============================================================
// MAIN HANDLER
// ============================================================

export default {

    /**
     * fetch() is the entry point Cloudflare calls for every HTTP request
     * that matches this Worker's route. The three parameters are:
     *
     *   request — The incoming HTTP request from the browser
     *   env     — Environment bindings including secrets (env.FORM_SECRET)
     *   ctx     — Execution context (not used here)
     */
    async fetch(request, env, ctx) {

        // Extract the hostname from the request URL and strip any www. prefix
        // so it matches the keys in CUSTOMERS regardless of how the domain
        // is configured. e.g. "www.acmeplumbing.com" → "acmeplumbing.com"
        const url      = new URL(request.url);
        const hostname = url.hostname.replace(/^www\./, "");

        // --------------------------------------------------------
        // STEP 1 — Identify the customer
        // --------------------------------------------------------
        // Look up the hostname in the customer config. If not found,
        // this request came from an unknown domain — return fake success.
        //
        // Falls back to ROOT_REDIRECT because we have no form data yet
        // and cannot parse a redirect field at this point.

        const customer = CUSTOMERS[hostname];

        if (!customer) {
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // Validate the recipient address format before we do anything else.
        // This catches config typos early. A malformed recipient here means
        // something is wrong with the CUSTOMERS config — log it clearly.
        if (!isValidEmailFormat(customer.recipient)) {
            console.error(`[shared-contact] Invalid recipient format for domain: ${hostname} — check CUSTOMERS config`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 2 — Parse the form body
        // --------------------------------------------------------
        // Nicepage submits forms as application/x-www-form-urlencoded
        // (standard HTML form encoding). We parse this into a plain object.
        //
        // Falls back to ROOT_REDIRECT on failure because we still have
        // no form data and cannot parse a redirect field.

        let formData;

        try {
            const body = await request.formData();
            formData = Object.fromEntries(body.entries());
        } catch (e) {
            // Couldn't parse the body — not a valid form submission
            console.error(`[shared-contact] Failed to parse form body: ${e.message}`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 3 — Parse redirect field
        // --------------------------------------------------------
        // Parse the redirect field immediately after we have form data.
        // From this point on, every exit path — including all fake success
        // responses — uses this validated redirect target rather than
        // falling back to root. This ensures the user always lands where
        // the form designer intended, even on rejected submissions.

        const redirectTarget = parseRedirect((formData.redirect ?? "").trim());

        // --------------------------------------------------------
        // STEP 4 — Validate the field set
        // --------------------------------------------------------
        // Check that every field in the submission is in ALLOWED_FIELDS.
        // Any unexpected field means this is not coming from one of our
        // forms — bots often add extra fields when probing endpoints.

        for (const key of Object.keys(formData)) {
            if (!ALLOWED_FIELDS.has(key)) {
                return fakeSuccess(url, redirectTarget);
            }
        }

        // --------------------------------------------------------
        // STEP 5 — Validate required fields
        // --------------------------------------------------------
        // All three required fields must be present and non-empty
        // after trimming whitespace.

        const name    = (formData.name    ?? "").trim();
        const email   = (formData.email   ?? "").trim();
        const message = (formData.message ?? "").trim();

        for (const field of REQUIRED_FIELDS) {
            if (!formData[field] || !formData[field].trim()) {
                return fakeSuccess(url, redirectTarget);
            }
        }

        // --------------------------------------------------------
        // STEP 6 — Validate email format
        // --------------------------------------------------------
        // Check the submitted email address looks like a real email.
        // This is a format check only — MX validation follows in Step 7.

        if (!isValidEmailFormat(email)) {
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 7 — Validate email domain has MX records
        // --------------------------------------------------------
        // Look up the domain part of the email address in DNS to confirm
        // it has MX records (i.e. it can actually receive email).
        // Uses Cloudflare's own DNS-over-HTTPS resolver (1.1.1.1).
        // e.g. "john@notarealdomain.xyz" would fail this check.

        const emailDomain = email.split("@")[1];

        if (!await hasMxRecords(emailDomain)) {
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 8 — Spam and malicious content check
        // --------------------------------------------------------
        // Scan name and message for spam and malicious content using
        // field-appropriate rules. Name uses a more lenient check that
        // permits apostrophes (O'Brien, D'Angelo). Message uses a fuller
        // check including spam keywords. Both treat any match as a silent
        // fake success — the submitter believes their message was sent.

        if (isSpamOrMaliciousName(name) || isSpamOrMaliciousMessage(message)) {
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 9 — POST to PHP relay
        // --------------------------------------------------------
        // Send the validated, clean data to the PHP endpoint as JSON.
        // The X-WAF-Secret header authenticates this request — .htaccess
        // on Dreamhost blocks anything without the correct secret before
        // PHP even loads.

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
        } catch (e) {
            // Network error reaching PHP — Dreamhost may be down
            console.error(`[shared-contact] Network error reaching PHP endpoint: ${e.message}`);
            return failRedirect(url, redirectTarget, generateRef());
        }

        // --------------------------------------------------------
        // STEP 10 — Handle PHP response and redirect browser
        // --------------------------------------------------------
        // PHP returns JSON with { success: true } or
        // { success: false, ref: "REF-XXXXXXXX" }.
        // Build the final redirect URL and send the browser there.

        let phpData;

        try {
            phpData = await phpResponse.json();
        } catch (e) {
            // PHP returned something we can't parse — unexpected
            console.error(`[shared-contact] Could not parse PHP response: ${e.message}`);
            return failRedirect(url, redirectTarget, generateRef());
        }

        if (phpData.success) {
            return successRedirect(url, redirectTarget);
        } else {
            return failRedirect(url, redirectTarget, phpData.ref ?? generateRef());
        }
    }
};


// ============================================================
// REDIRECT HELPERS
// ============================================================

/**
 * buildRedirectUrl()
 *
 * Constructs the final redirect URL from its components.
 *
 * Rules (as agreed):
 *   - Always uses https://
 *   - Always uses www. prefix (added if not already present)
 *   - Path defaults to "/" if empty
 *   - Query string appended to path before anchor
 *   - Anchor appended after query string
 *
 * Example:
 *   hostname:  "acmeplumbing.com"
 *   path:      "/thank-you"
 *   params:    { ui-msgtype: "success", ui-msgdata: "Your message..." }
 *   anchor:    "contact"
 *
 *   Result: https://www.acmeplumbing.com/thank-you?ui-msgtype=success&ui-msgdata=Your+message...#contact
 *
 * @param {URL}    url     Original request URL (used for hostname)
 * @param {string} path    Validated URL path e.g. "/thank-you" or "/"
 * @param {Object} params  Key/value pairs for query string
 * @param {string} anchor  Fragment identifier without # (may be empty)
 * @returns {string}       Complete redirect URL
 */
function buildRedirectUrl(url, path, params, anchor) {

    // Always www. — add it if not already present
    const host = url.hostname.startsWith("www.")
        ? url.hostname
        : "www." + url.hostname;

    // Build query string from params object
    const query = new URLSearchParams(params).toString();

    // Assemble: scheme + host + path + ? + query + # + anchor
    let redirectUrl = `https://${host}${path}?${query}`;

    if (anchor) {
        redirectUrl += `#${anchor}`;
    }

    return redirectUrl;
}

/**
 * successRedirect()
 *
 * Redirects the browser with ui-msgtype=success and the standard
 * success message. Used when the email was sent successfully.
 *
 * @param {URL}    url            Original request URL
 * @param {Object} redirectTarget { path, anchor } from parseRedirect()
 * @returns {Response}            302 redirect response
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
 * Returns a redirect that looks like success but indicates a silent
 * rejection. Used for spam, invalid fields, unknown domains, and any
 * other case where we want the submitter to believe it worked.
 *
 * Accepts a redirectTarget so the user lands where the form designer
 * intended even on rejected submissions. Falls back to ROOT_REDIRECT
 * only when called before form data has been parsed (steps 1 and 2).
 *
 * The subtle difference from a real success ("Your message has been sent."
 * vs "Your message has been sent !!!") lets you verify the filter is
 * working during testing without alarming legitimate users.
 *
 * @param {URL}    url            Original request URL
 * @param {Object} redirectTarget { path, anchor } from parseRedirect()
 * @returns {Response}            302 redirect response
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
 * Redirects the browser with ui-msgtype=fail and a user-friendly error
 * message containing a reference ID. Used only for genuine system
 * failures (SMTP down, PHP unreachable, etc.).
 *
 * The reference ID appears in both the user-facing message and the PHP
 * log entry so you can find the full error detail from a user report.
 *
 * @param {URL}    url            Original request URL
 * @param {Object} redirectTarget { path, anchor } from parseRedirect()
 * @param {string} ref            Reference ID e.g. "REF-20260504-A3F7"
 * @returns {Response}            302 redirect response
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
 *
 * Valid values are URI paths only — no protocol, no domain, no query string.
 * An anchor fragment is allowed and will be separated from the path.
 *
 * Rules:
 *   Valid:    /                  → { path: "/",          anchor: "" }
 *   Valid:    /thank-you         → { path: "/thank-you", anchor: "" }
 *   Valid:    /thank-you#contact → { path: "/thank-you", anchor: "contact" }
 *   Valid:    #contact           → { path: "/",          anchor: "contact" }
 *   Valid:    /#contact          → { path: "/",          anchor: "contact" }
 *   Invalid:  https://...        → { path: "/",          anchor: "" }
 *   Invalid:  //evil.com         → { path: "/",          anchor: "" }
 *   Invalid:  ?query=string      → { path: "/",          anchor: "" }
 *   Empty:    ""                 → { path: "/",          anchor: "" }
 *
 * Any invalid value falls back to root with no anchor.
 *
 * @param  {string} redirect  Raw value of the redirect form field
 * @returns {{ path: string, anchor: string }}
 */
function parseRedirect(redirect) {

    const fallback = { path: "/", anchor: "" };

    if (!redirect) {
        return fallback;
    }

    // Special case: anchor-only value with no path e.g. "#contact"
    // Treat as root path with that anchor: { path: "/", anchor: "contact" }
    if (redirect.startsWith("#")) {
        const anchor = redirect.slice(1); // Strip the leading #
        return { path: "/", anchor: sanitizeAnchor(anchor) };
    }

    // Must start with / — anything else (protocol, domain, query) is invalid
    if (!redirect.startsWith("/")) {
        return fallback;
    }

    // Must not contain a protocol indicator or double slash
    if (redirect.includes("://") || redirect.startsWith("//")) {
        return fallback;
    }

    // Must not contain a query string — we are adding our own
    if (redirect.includes("?")) {
        return fallback;
    }

    // Split path and anchor at the # character
    const hashIndex = redirect.indexOf("#");

    if (hashIndex === -1) {
        // No anchor — path is the whole value
        return { path: redirect, anchor: "" };
    }

    // Separate path and anchor
    const path   = redirect.slice(0, hashIndex) || "/"; // Default to "/" if path before # is empty
    const anchor = redirect.slice(hashIndex + 1);       // Everything after #

    return {
        path:   path,
        anchor: sanitizeAnchor(anchor),
    };
}

/**
 * sanitizeAnchor()
 *
 * Strips anything from an anchor value that isn't a valid HTML fragment
 * identifier character. Allows letters, numbers, hyphens, underscores,
 * and periods. Anything else is removed.
 *
 * This prevents an attacker from injecting unexpected characters into
 * the redirect URL via a crafted anchor value.
 *
 * @param  {string} anchor  Raw anchor value (without #)
 * @returns {string}        Sanitized anchor value
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
 * Checks that a string looks like a valid email address.
 * This is a format check only — not a deliverability check.
 * MX record validation happens separately in hasMxRecords().
 *
 * The regex covers the vast majority of real-world email addresses
 * without being so strict it rejects legitimate unusual formats.
 *
 * @param  {string} email  Email address to check
 * @returns {boolean}
 */
function isValidEmailFormat(email) {
    // Must have exactly one @ with non-empty local and domain parts,
    // domain must have at least one dot, and TLD must be 2+ characters.
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    return re.test(email);
}

/**
 * hasMxRecords()
 *
 * Queries Cloudflare's DNS-over-HTTPS resolver to check whether
 * the given domain has MX records, confirming it can receive email.
 *
 * Uses 1.1.1.1 (Cloudflare's public DNS resolver) which is always
 * available from within a Cloudflare Worker.
 *
 * Returns false on any error (DNS failure, network error, etc.) so
 * that a lookup failure is treated conservatively as no MX found.
 *
 * @param  {string} domain  Domain part of the email address e.g. "gmail.com"
 * @returns {Promise<boolean>}
 */
async function hasMxRecords(domain) {
    try {
        const response = await fetch(
            `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=MX`,
            {
                headers: { "Accept": "application/dns-json" }
            }
        );

        if (!response.ok) {
            return false;
        }

        const data = await response.json();

        // DNS response status 0 = NOERROR
        // Answer array present and non-empty = MX records exist
        return data.Status === 0
            && Array.isArray(data.Answer)
            && data.Answer.length > 0;

    } catch (e) {
        // DNS lookup failed — treat conservatively as no MX
        console.error(`[shared-contact] MX lookup failed for ${domain}: ${e.message}`);
        return false;
    }
}

/**
 * isSpamOrMaliciousName()
 *
 * Checks a name field for spam or malicious content.
 *
 * More lenient than the message check — names legitimately contain
 * apostrophes (O'Brien, D'Angelo) so single quotes are not flagged.
 * Names should never contain URLs, HTML, or injection characters
 * beyond an apostrophe.
 *
 * @param  {string} value  The name field value to check
 * @returns {boolean}      true if spam or malicious content detected
 */
function isSpamOrMaliciousName(value) {

    const checks = [
        /https?:\/\//i,                                               // http:// or https:// URLs
        /www\./i,                                                      // www. URLs without protocol
        /<[^>]+>/,                                                     // HTML tags
        /\b(select|insert|update|delete|drop|union|exec|script)\b/i,  // SQL / script keywords
        /[<>"`;]/,                                                     // Injection characters — note: single quote excluded for O'Brien etc.
        /(\!{3,}|\?{3,}|\${3,})/,                                     // Repeated punctuation (!!!, ???, $$$)
    ];

    return checks.some(pattern => pattern.test(value));
}

/**
 * isSpamOrMaliciousMessage()
 *
 * Checks a message field for spam or malicious content.
 *
 * More thorough than the name check — messages are longer and more
 * likely to contain spam content. Single quotes are still excluded
 * since legitimate messages commonly contain apostrophes ("I'd like
 * to know...", "can't find..."). Backtick and semicolon are flagged
 * as they have no place in a genuine contact form message.
 *
 * @param  {string} value  The message field value to check
 * @returns {boolean}      true if spam or malicious content detected
 */
function isSpamOrMaliciousMessage(value) {

    const checks = [
        /https?:\/\//i,                                                                    // http:// or https:// URLs
        /www\./i,                                                                           // www. URLs without protocol
        /<[^>]+>/,                                                                          // HTML tags
        /\b(select|insert|update|delete|drop|union|exec|script)\b/i,                       // SQL / script keywords
        /[<>"`;]/,                                                                          // Injection characters — single quote excluded for apostrophes
        /(\!{3,}|\?{3,}|\${3,})/,                                                          // Repeated punctuation (!!!, ???, $$$)
        /\b(viagra|cialis|casino|lottery|winner|prize|click here|buy now|free money)\b/i,  // Spam keywords
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
 *
 * Matches the format used by PHP so references are consistent
 * whether generated by the Worker or by PHP.
 *
 * Used when the Worker encounters an error before reaching PHP,
 * or when PHP's response cannot be parsed.
 *
 * Example output: REF-20260504-A3F7
 *
 * @returns {string}
 */
function generateRef() {
    const now  = new Date();
    const date = now.toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
    const rand = Math.floor(Math.random() * 0xFFFF)
                     .toString(16)
                     .toUpperCase()
                     .padStart(4, "0");
    return `REF-${date}-${rand}`;
}
