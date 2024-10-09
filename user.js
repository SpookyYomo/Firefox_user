//
/*********************************************************************
*
* Name: user.js | brainfucksec
* Descr.: Mozilla Firefox configuration file: `user.js`
* Version: 0.21.1
* Date: 2024-07-14
* URL: https://gist.github.com/brainfucksec/68e79da1c965aeaa4782914afd8f7fa2
* Maintainer: brainf+ck
*
* Info:
* Set preferences for the selected profile when Firefox start.
* Copy this file on Firefox Profile folder.  You should create a new profile
* to be used with this file.
*
* See:
* Create, remove or switch Firefox profiles:
* https://support.mozilla.org/en-US/kb/profile-manager-create-remove-switch-firefox-profiles?redirectslug=profile-manager-create-and-remove-firefox-profiles&redirectlocale=en-US
*
* Back up and restore information in Firefox profiles:
* https://support.mozilla.org/en-US/kb/back-and-restore-information-firefox-profiles
*
* For more information how to use this file see:
* https://kb.mozillazine.org/User.js_file
* https://github.com/arkenfox/user.js/wiki/1.1-Overview
*
* For "about:config" entries see:
* https://searchfox.org/mozilla-release/source/modules/libpref/init/all.js
*
* OPTION FORMAT:
*   user_pref("<entry>", <boolean> || <number> || "<string>");
*
* Thanks to:
* arkenfox/user.js: https://github.com/arkenfox/user.js
* LibreWolf: https://librewolf.net/
*
**********************************************************************/


/*********************************************************************
 *
 * SECTIONS:
 * =========
 *    - StartUp Settings
 *    - Geolocation
 *    - Language / Locale
 *    - Auto-updates / Recommendations
 *    - Telemetry
 *    - Studies
 *    - Crash Reports
 *    - Captive Portal Detection / Network Checks
 *    - Safe Browsing
 *    - Network: DNS, Proxy, IPv6
 *    - Search Bar: Suggestions, Autofill
 *    - Passwords
 *    - Disk Cache / Memory
 *    - HTTPS / SSL/TLS / OSCP / CERTS
 *    - Headers / Referers
 *    - Audio/Video: WebRTC, WebGL, DRM
 *    - Downloads
 *    - Cookies
 *    - UI Features
 *    - Extensions
 *    - Shutdown Settings
 *    - Fingerprinting (RFP)
 *
 *********************************************************************/

/*********************************************************************
 * StartUp Settings
 *********************************************************************/

// Disable about:config warning
user_pref("browser.aboutConfig.showWarning", false);

// Disable default browser check
user_pref("browser.shell.checkDefaultBrowser", false);

/*
 * Set startup home page:
 *    0 = blank
 *    1 = home
 *    2 = last visited page
 *    3 = resume previous session
 */
user_pref("browser.startup.page",  3);
// user_pref("browser.startup.homepage", "about:home");

// disable activity stream on new windows and tab pages
// user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtab.preload", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false); // disable telemetry
user_pref("browser.newtabpage.activity-stream.telemetry", false); // disable telemetry
// user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
// user_pref("browser.newtabpage.activity-stream.feeds.discoverystreamfeed", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false); // Pocket -> Sponsored Stories
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false); // Sponsored Shortcuts
// user_pref("browser.newtabpage.activity-stream.default.sites", "");


/*********************************************************************
 * Geolocation
 *********************************************************************/

// use Mozilla geolocation service instead of Google if permission is granted
// user_pref("geo.provider.network.url", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");

// disable using the OS’s geolocation service
// user_pref("geo.provider.ms-windows-location", false); // Windows
// user_pref("geo.provider.use_corelocation", false);    // macOS
user_pref("geo.provider.use_gpsd", false);              // Linux
user_pref("geo.provider.use_geoclue", false);           // Linux

// Disable region updates
user_pref("browser.region.network.url", "");
user_pref("browser.region.update.enabled", false);


/*********************************************************************
 * Language / Locale
 *********************************************************************/

// Set language for displaying web pages:
user_pref("intl.accept_languages", "en-US, en");
user_pref("javascript.use_us_english_locale", true); // [HIDDEN PREF]


/*********************************************************************
 * Auto-updates / Recommendations
 *********************************************************************/

// Disable auto-installing Firefox updates
// user_pref("app.update.background.scheduling.enabled", false); // Windows
user_pref("app.update.auto", false);                            // Non-Windows

// Disable addons recommendations (use Google Analytics)
user_pref("extensions.getAddons.showPane", false); // [HIDDEN PREF]
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);


/*********************************************************************
 * Telemetry
 *********************************************************************/

// Disable telemetry
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("toolkit.telemetry.enabled", false); // Default: false
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true); // [HIDDEN PREF]
user_pref("toolkit.coverage.opt-out", true); // [HIDDEN PREF]
user_pref("toolkit.coverage.endpoint.base.", "");
user_pref("browser.ping-centre.telemetry", false);
user_pref("beacon.enabled", false);

// Firefox 128 PPA garbage
lockPref("dom.private-attribution.submission.enabled", false);

/*********************************************************************
 * Studies
 *********************************************************************/

// Disable studies
user_pref("app.shield.optoutstudies.enabled", false);

// Disable normandy/shield
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");


/*********************************************************************
 * Crash Reports
 *********************************************************************/

// Disable crash reports
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);


/*********************************************************************
 * Captive Portal Detection / Network Checks
 *********************************************************************/

// Disable captive portal detection
user_pref("captivedetect.canonicalURL", "");
user_pref("network.captive-portal-service.enabled", false);

// Disable network connections checks
user_pref("network.connectivity-service.enabled", false);


/*********************************************************************
 * Safe Browsing
 *********************************************************************/

// Disable safe browsing service
// user_pref("browser.safebrowsing.malware.enabled", false);
// user_pref("browser.safebrowsing.phishing.enabled", false);

// Disable list of blocked URI
// user_pref("browser.safebrowsing.blockedURIs.enabled", false);

// Disable fetch of updates
user_pref("browser.safebrowsing.provider.google4.gethashURL", "");
user_pref("browser.safebrowsing.provider.google4.updateURL", "");
user_pref("browser.safebrowsing.provider.google.gethashURL", "");
user_pref("browser.safebrowsing.provider.google.updateURL", "");
user_pref("browser.safebrowsing.provider.google4.dataSharingURL", "");

// Disable checks for downloads
// user_pref("browser.safebrowsing.downloads.enabled", false);
// user_pref("browser.safebrowsing.downloads.remote.enabled", false);
// user_pref("browser.safebrowsing.downloads.remote.url", "");

// Disable checks for unwanted software
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);

// Disable bypasses the block of safe browsing with a click for current session
user_pref("browser.safebrowsing.allowOverride", false);


/*********************************************************************
 * Network: DNS, Proxy, IPv6
 *********************************************************************/

// Disable link prefetching
user_pref("network.prefetch-next", false);

// Disable DNS prefetching
user_pref("network.dns.disablePrefetch", true);

// Disable predictor
user_pref("network.predictor.enabled", false);

// Disable link-mouseover opening connection to linked server
user_pref("network.http.speculative-parallel-limit", 0);

// Disable mousedown speculative connections on bookmarks and history
user_pref("browser.places.speculativeConnect.enabled", false);

// Disable IPv6
user_pref("network.dns.disableIPv6", true);

// Disable "GIO" protocols as a potential proxy bypass vectors
user_pref("network.gio.supported-protocols", ""); // [HIDDEN PREF]

// Disable using UNC (Uniform Naming Convention) paths (prevent proxy bypass)
user_pref("network.file.disable_unc_paths", true); // [HIDDEN PREF]

// Remove special permissions for certain mozilla domains
user_pref("permissions.manager.defaultsUrl", "");

// Use Punycode in Internationalized Domain Names to eliminate possible spoofing
user_pref("network.IDN_show_punycode", true);


/*********************************************************************
 * Search Bar: Suggestions, Autofill
 *********************************************************************/

// Disable location bar contextual suggestions:
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);

// Disable search suggestions
// user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);

// Disable urlbar trending search suggestions
user_pref("browser.urlbar.trending.featureGate", false);

// Disable urlbar suggestions
user_pref("browser.urlbar.addons.featureGate", false);
user_pref("browser.urlbar.mdn.featureGate", false);
user_pref("browser.urlbar.pocket.featureGate", false);
user_pref("browser.urlbar.weather.featureGate", false);

// Disable location bar domain guessing
user_pref("browser.fixup.alternate.enabled", false);

// Display all parts of the url in the bar
user_pref("browser.urlbar.trimURLs", false);

// Disable location bar making speculative connections
// user_pref("browser.urlbar.speculativeConnect.enabled", false);

// Disable form autofill
user_pref("browser.formfill.enable", false); // form history
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.available", "off");
user_pref("extensions.formautofill.creditCards.enabled", false);


/*********************************************************************
 * Passwords
 *********************************************************************/

// Disable saving passwords
// user_pref("signon.rememberSignons", false);

// Disable autofill login and passwords
// user_pref("signon.autofillForms", false);

// Disable formless login capture for Password Manager
user_pref("signon.formlessCapture.enabled", false);

/*
 * Hardens against potential credentials phishing:
 *    0 = don't allow sub-resources to open HTTP authentication credentials dialogs
 *    1 = don't allow cross-origin sub-resources to open HTTP authentication credentials dialogs
 *    2 = allow sub-resources to open HTTP authentication credentials dialogs (default)
 */
user_pref("network.auth.subresource-http-auth-allow", 1);


/*********************************************************************
 * Disk Cache / Memory
 *********************************************************************/

// Disable disk cache
// user_pref("browser.cache.disk.enable", false);

// Disable media cache from writing to disk in Private Browsing
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);

/*
 * Disable storing extra session data:
 *    0 = everywhere
 *    1 = unencrypted sites
 *    2 = nowhere
 */
// user_pref("browser.sessionstore.privacy_level", 2);

// Disable resuming session from crash
// user_pref("browser.sessionstore.resume_from_crash", false);

// Disable automatic Firefox start and session restore after reboot [Windows]
// user_pref("toolkit.winRegisterApplicationRestart", false);

// Disable page thumbnail collection
// user_pref("browser.pagethumbnails.capturing_disabled", true); // [HIDDEN PREF]

// Disable favicons in shortcuts [Windows]
user_pref("browser.shell.shortcutFavicons", false);

// Delete temporary files opened with external apps
user_pref("browser.download.start_downloads_in_tmp_dir", true);
user_pref("browser.helperApps.deleteTempFileOnExit", true);


/*********************************************************************
 * HTTPS (SSL/TLS, OSC, CERTS)
 *********************************************************************/

// Enable HTTPS-Only mode in all windows
user_pref("dom.security.https_only_mode", true);

// Disable sending HTTP request for checking HTTPS support by the server
user_pref("dom.security.https_only_mode_send_http_background_request", false);

// Display advanced information on Insecure Connection warning pages
user_pref("browser.xul.error_pages.expert_bad_cert", true);

// Disable TLS 1.3 0-RTT (round-trip time)
user_pref("security.tls.enable_0rtt_data", false);

// Set OCSP to terminate the connection when a CA isn't validate
// user_pref("security.OCSP.require", true);

/*
 * Enable strict PKP (Public Key Pinning):
 *    0 = disabled
 *    1 = allow user MiTM (i.e. your Antivirus)
 *    2 = strict
 */
user_pref("security.cert_pinning.enforcement_level", 2);

/*
 * Enable CRLite
 *    0 = disabled
 *    1 = consult CRLite but only collect telemetry
 *    2 = consult CRLite and enforce both "Revoked" and "Not Revoked" results
 *    3 = consult CRLite and enforce "Not Revoked" results, but defer to OCSP for "Revoked" (default)
 */
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);


/*********************************************************************
 * Headers / Referers
 *********************************************************************/

/*
 * Control when to send a referer:
 *    0 = always (default)
 *    1 = only if base domains match
 *    2 = only if hosts match
 */
user_pref("network.http.referer.XOriginPolicy", 2);

/*
 * Control amount of information to send:
 *    0 = send full URI (default):  https://example.com:8888/foo/bar.html?id=1234
 *    1 = scheme+host+port+path:    https://example.com:8888/foo/bar.html
 *    2 = scheme+host+port:         https://example.com:8888
 */
user_pref("network.http.referer.XOriginTrimmingPolicy", 1);


/*********************************************************************
 * Audio/Video: WebRTC, WebGL
 *********************************************************************/

// Disable WebRTC
user_pref("media.peerconnection.enabled", false);

// Force WebRTC inside the proxy
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);

// Force a single network interface for ICE candidates generation
user_pref("media.peerconnection.ice.default_address_only", true);

// Force exclusion of private IPs from ICE candidates
user_pref("media.peerconnection.ice.no_host", true);

// Disable WebGL (Web Graphics Library):
user_pref("webgl.disabled", true);

// Disable DRM Content
user_pref("media.eme.enabled", false);


/*********************************************************************
 * Downloads
 *********************************************************************/

// Always ask you where to save files:
user_pref("browser.download.useDownloadDir", false);

// Disable adding downloads to system's "recent documents" list
user_pref("browser.download.manager.addToRecentDocs", false);

// instead of asking for dialog for new file type, just save
user_pref("browser.download.always_ask_before_handling_new_types", false);

// download to a tmp dir first
user_pref("browser.cache.disk.parent_directory", "/dev/shm");
user_pref("browser.cache.disk.enable", true);
user_pref("browser.download.start_downloads_in_tmp_dir", true);


/*********************************************************************
 * Cookies
 *********************************************************************/

/*
 * Enable ETP (Enhanced Tracking Protection)
 * ETP strict mode enables Total Cookie Protection (TCP)
 */
user_pref("browser.contentblocking.category", "strict");


/*********************************************************************
 * UI Features
 *********************************************************************/

// Block popup windows
user_pref("dom.disable_open_during_load", true);

// Limit events that can cause a popup
user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");

// Disable Pocket extension
user_pref("extensions.pocket.enabled", false);

// Disable Screenshots extension
// user_pref("extensions.screenshots.disabled", true);

// Disable PDFJS scripting
user_pref("pdfjs.enableScripting", false);

// Enable Containers and show the UI settings
user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);


/*********************************************************************
 * Extensions
 *********************************************************************/

/*
 * Set extensions to work on restricted domains, and their scope
 * is set to profile+applications.
 * See: https://mike.kaply.com/2012/02/21/understanding-add-on-scopes/
 */
// user_pref("extensions.enabledScopes", 5); // [HIDDEN PREF]
// user_pref("extensions.webextensions.restrictedDomains", "");

// Display always the installation prompt
user_pref("extensions.postDownloadThirdPartyPrompt", false);


/*********************************************************************
 * Shutdown Settings
 *********************************************************************/

// Clear history, cookies and site data when Firefox closes
// user_pref("network.cookie.lifetimePolicy", 2);
// user_pref("privacy.sanitize.sanitizeOnShutdown", true);
// user_pref("privacy.clearOnShutdown.cache", true);
// user_pref("privacy.clearOnShutdown.cookies", true);
// user_pref("privacy.clearOnShutdown.downloads", true);
// user_pref("privacy.clearOnShutdown.formdata", true);
// user_pref("privacy.clearOnShutdown.history", true);
// user_pref("privacy.clearOnShutdown.offlineApps", true);
// user_pref("privacy.clearOnShutdown.sessions", true);
// user_pref("privacy.clearOnShutdown.sitesettings", true);
// user_pref("privacy.sanitize.timeSpan", 0);


/*********************************************************************
 * Fingerprinting (RFP)
 *********************************************************************/

/*
 * RFP (Resist Fingerprinting):
 *
 * Can cause some website breakage: mainly canvas, use a site
 * exception via the urlbar.
 *
 * RFP also has a few side effects: mainly timezone is UTC0, and
 * websites will prefer light theme.
 * [1] https://bugzilla.mozilla.org/418986
 *
 * See: https://support.mozilla.org/en-US/kb/firefox-protection-against-fingerprinting
 */

// Enable RFP
user_pref("privacy.resistFingerprinting", true);
// user_pref("privacy.resistFingerprinting.letterbox", true);

// Set new window size rounding max values
user_pref("privacy.window.InnerWidth", 1600);
user_pref("privacy.window.InnerHeight", 900);
user_pref("privacy.window.maxInnerWidth", 1600);
user_pref("privacy.window.maxInnerHeight", 900);

// Disable mozAddonManager Web API
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true); // [HIDDEN PREF]

// Disable showing about:blank page when possible at startup
// user_pref("browser.startup.blankWindow", false);

// Disable using system colors
//user_pref("browser.display.use_system_colors", false); // Default: false (Non-Windows)

// allow for chrome/userChrome.css
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);

/*********************************************************************
 * DoH
 *********************************************************************/

user_pref("network.trr.custom_uri", "9.9.9.9, 149.112.112.112");
user_pref("network.trr.uri", "9.9.9.9, 149.112.112.112");
user_pref("network.trr.mode", 2);

// user_pref("browser.newtabpage.activity-stream.newtabWallpapers.enabled", true);

// to disable Pocket, uncomment the following lines
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
