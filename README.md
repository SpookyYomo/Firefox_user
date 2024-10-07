# Firefox user.js
This is a Firefox user.js that tries to modify from https://gist.github.com/brainfucksec/68e79da1c965aeaa4782914afd8f7fa2.

## Keeping track with upstream
`git remote add upstream git@gist.github.com:68e79da1c965aeaa4782914afd8f7fa2.git`,
then perform the diff's as necessary, with
`git difftool (-d) upstream/master:user.js user.js`.

## System-wide user.js
TBD!

## Discord
Sometimes we find a need to access Discord via a browser because electron is really great!
Within each user's profile, the user.js needs to be
```
user_pref("media.peerconnection.enabled", true);
```

Some other useless tried settings were:
```
/*********************************************************************
 * Audio/Video: WebRTC, WebGL
 *********************************************************************/

// force WebRTC inside the proxy
// pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);

// force a single network interface for ICE candidates generation
// pref("media.peerconnection.ice.default_address_only", true);

// force exclusion of private IPs from ICE candidates
// pref("media.peerconnection.ice.no_host", true);

// disable WebGL (Web Graphics Library):
// pref("webgl.disabled", false);  // discord fox

/*
 * disable autoplay of HTML5 media, You can set exceptions under site
 * permissions.
 *    0 = allow all
 *    1 = block non-muted media (default)
 *    5 = block all
 */
// pref("media.autoplay.default", 5);

// disable DRM Content
// pref("media.eme.enabled", false);
```
