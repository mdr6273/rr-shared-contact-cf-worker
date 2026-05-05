/**
 * worker.js — Shared contact form Worker
 *
 * Deployed to: Cloudflare Workers
 * Handles route: www.[customer].com/mailform
 *
 * NOTE: This version includes debug logging throughout for troubleshooting.
 * Once the issue is resolved, debug log lines should be removed.
 * Debug lines are marked with [debug] prefix for easy identification.
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
 * Redeployment via Git push is required after any change.
 *
 * SECRETS
 * -------
 * The shared secret sent to PHP in the X-WAF-Secret header is stored
 * as a Cloudflare Worker secret set in the Cloudflare dashboard:
 *   Workers & Pages → rr-shared-contact → Settings → Variables and Secrets
 * It is accessible in code as env.FORM_SECRET.
 *
 * ROUTE BINDING
 * -------------
 * Each customer domain needs one route in their Cloudflare dashboard:
 *   www.customer.com/mailform  →  rr-shared-contact
 */


// ============================================================
// CUSTOMER CONFIGURATION
// ============================================================

const CUSTOMERS = {
    "richardsonresources.com": {
        recipient: "mdr6273@gmail.com"
    },
    "ceincsd.com": {
        recipient: "customerservice@ceincsd.com"
    }
    // Add customers here following the pattern above
};


// ============================================================
// CONSTANTS
// ============================================================

const PHP_ENDPOINT  = "https://customertools.richardsonresources.com/formactions/shared-contact.php";
const ALLOWED_FIELDS = new Set(["name", "email", "message", "redirect", "recaptchaResponse", "cf-turnstile-response"]);
const REQUIRED_FIELDS = ["name", "email", "message"];
const ROOT_REDIRECT  = { path: "/", anchor: "" };

const MESSAGES = {
    success:      "Your message has been sent.",
    silentReject: "Your message has been sent !!!",
    failure:      "Something went wrong. Reference: "
};


// ============================================================
// MAIN HANDLER
// ============================================================

export default {

    async fetch(request, env, ctx) {

        console.log("[debug] Worker fired:", request.method, request.url);

        const url      = new URL(request.url);
        const hostname = url.hostname.replace(/^www\./, "");

        console.log("[debug] hostname resolved to:", hostname);

        // --------------------------------------------------------
        // STEP 1 — Identify the customer
        // --------------------------------------------------------

        const customer = CUSTOMERS[hostname];

        console.log("[debug] customer lookup result:", customer ? "found" : "NOT FOUND");

        if (!customer) {
            console.log("[debug] exiting — unknown domain");
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        const recipientValid = isValidEmailFormat(customer.recipient);
        console.log("[debug] recipient format valid:", recipientValid, "—", customer.recipient);

        if (!recipientValid) {
            console.error(`[shared-contact] Invalid recipient format for domain: ${hostname}`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 2 — Parse the form body
        // --------------------------------------------------------

        let formData;

        try {
            const body = await request.formData();
            formData = Object.fromEntries(body.entries());
            console.log("[debug] form parsed OK, fields received:", Object.keys(formData).join(", "));
        } catch (e) {
            console.error(`[shared-contact] Failed to parse form body: ${e.message}`);
            return fakeSuccess(url, ROOT_REDIRECT);
        }

        // --------------------------------------------------------
        // STEP 3 — Parse redirect field
        // --------------------------------------------------------

        const redirectTarget = parseRedirect((formData.redirect ?? "").trim());
        console.log("[debug] redirect target:", JSON.stringify(redirectTarget));

        // --------------------------------------------------------
        // STEP 4 — Validate the field set
        // --------------------------------------------------------

        for (const key of Object.keys(formData)) {
            if (!ALLOWED_FIELDS.has(key)) {
                console.log("[debug] exiting — unexpected field detected:", key);
                return fakeSuccess(url, redirectTarget);
            }
        }

        console.log("[debug] field set valid");

        // --------------------------------------------------------
        // STEP 5 — Validate required fields
        // --------------------------------------------------------

        const name     = (formData.name     ?? "").trim();
        const email    = (formData.email    ?? "").trim();
        const message  = (formData.message  ?? "").trim();

        console.log("[debug] name:", name ? "present" : "MISSING");
        console.log("[debug] email:", email ? "present" : "MISSING");
        console.log("[debug] message:", message ? "present" : "MISSING");

        for (const field of REQUIRED_FIELDS) {
            if (!formData[field] || !formData[field].trim()) {
                console.log("[debug] exiting — missing required field:", field);
                return fakeSuccess(url, redirectTarget);
            }
        }

        console.log("[debug] required fields all present");

        // --------------------------------------------------------
        // STEP 6 — Validate email format
        // --------------------------------------------------------

        const emailFormatValid = isValidEmailFormat(email);
        console.log("[debug] email format valid:", emailFormatValid, "—", email);

        if (!emailFormatValid) {
            console.log("[debug] exiting — invalid email format");
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 7 — Validate email domain has MX records
        // --------------------------------------------------------

        const emailDomain = email.split("@")[1];
        console.log("[debug] checking MX records for domain:", emailDomain);

        const mxValid = await hasMxRecords(emailDomain);
        console.log("[debug] MX records found:", mxValid);

        if (!mxValid) {
            console.log("[debug] exiting — no MX records for:", emailDomain);
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 8 — Spam and malicious content check
        // --------------------------------------------------------

        const nameSpam    = isSpamOrMaliciousName(name);
        const messageSpam = isSpamOrMaliciousMessage(message);

        console.log("[debug] name spam check:", nameSpam ? "FLAGGED" : "clean");
        console.log("[debug] message spam check:", messageSpam ? "FLAGGED" : "clean");

        if (nameSpam || messageSpam) {
            console.log("[debug] exiting — spam or malicious content detected");
            return fakeSuccess(url, redirectTarget);
        }

        // --------------------------------------------------------
        // STEP 9 — POST to PHP relay
        // --------------------------------------------------------

        console.log("[debug] all checks passed — posting to PHP...");

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
            console.log("[debug] PHP response status:", phpResponse.status);
        } catch (e) {
            console.error(`[shared-contact] Network error reaching PHP endpoint: ${e.message}`);
            return failRedirect(url, redirectTarget, generateRef());
        }

        // --------------------------------------------------------
        // STEP 10 — Handle PHP response and redirect browser
        // --------------------------------------------------------

        let phpData;



		let phpRawBody;
        try {
            phpRawBody = await phpResponse.text();
            console.log("[debug] PHP raw response:", phpRawBody.substring(0, 200));
            phpData = JSON.parse(phpRawBody);
            console.log("[debug] PHP response body:", JSON.stringify(phpData));
        } catch (e) {
            console.error(`[shared-contact] Could not parse PHP response: ${e.message}`);
            console.error(`[shared-contact] Raw body was: ${phpRawBody ? phpRawBody.substring(0, 200) : "empty"}`);
            return failRedirect(url, redirectTarget, generateRef());
        }





        if (phpData.success) {
            console.log("[debug] success — redirecting with success message");
            return successRedirect(url, redirectTarget);
        } else {
            console.log("[debug] PHP reported failure, ref:", phpData.ref);
            return failRedirect(url, redirectTarget, phpData.ref ?? generateRef());
        }
    }
};


// ============================================================
// REDIRECT HELPERS
// ============================================================

/**
 * buildRedirectUrl()
 * Constructs the final redirect URL from its components.
 * Always uses https:// and www. prefix.
 * Query string is appended before anchor.
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
 * Returns a redirect that looks like success but is a silent rejection.
 * Uses the validated redirectTarget if available, ROOT_REDIRECT if not.
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
 * Redirects with ui-msgtype=fail and a reference ID for genuine failures.
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
 * Validates and parses the optional redirect form field.
 * Returns { path, anchor } — falls back to root if invalid.
 *
 * Valid:    /                  → { path: "/",          anchor: "" }
 * Valid:    /thank-you         → { path: "/thank-you", anchor: "" }
 * Valid:    /thank-you#contact → { path: "/thank-you", anchor: "contact" }
 * Valid:    #contact           → { path: "/",          anchor: "contact" }
 * Invalid:  https://...        → { path: "/",          anchor: "" }
 * Empty:    ""                 → { path: "/",          anchor: "" }
 */
function parseRedirect(redirect) {
    const fallback = { path: "/", anchor: "" };
    if (!redirect) return fallback;

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
 * Strips characters that aren't valid in HTML fragment identifiers.
 */
function sanitizeAnchor(anchor) {
    return anchor.replace(/[^a-zA-Z0-9\-_\.]/g, "");
}


// ============================================================
// VALIDATION HELPERS
// ============================================================

/**
 * isValidEmailFormat()
 * Checks that a string looks like a valid email address (format only).
 */
function isValidEmailFormat(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    return re.test(email);
}

/**
 * hasMxRecords()
 * Checks whether a domain has MX records via Cloudflare DNS-over-HTTPS.
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
/**
 * isSpamOrMaliciousName()
 *
 * Checks a name field for spam or malicious content.
 * Names should never contain URLs or HTML tags.
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
 * Generates a short reference ID for error tracking.
 * Format: REF-YYYYMMDD-XXXX
 * Matches the format used by PHP for consistency.
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