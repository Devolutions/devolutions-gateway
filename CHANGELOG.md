# Changelog

This document provides a list of notable changes introduced in Devolutions Gateway service, installer and Jetsocat.

## 2024.3.5 (2024-11-12)

### Bug Fixes

- _webapp_: the initial 401 error is shown when it should not ([#1102](https://github.com/Devolutions/devolutions-gateway/issues/1102)) ([b54a666776](https://github.com/Devolutions/devolutions-gateway/commit/b54a666776420106bb694d08700e7ae234b9ab51)) ([DGW-226](https://devolutions.atlassian.net/browse/DGW-226)) 

## 2024.3.4 (2024-11-8)

### Features

- _jetsocat_: make doctor returns links to x509.io ([#1059](https://github.com/Devolutions/devolutions-gateway/issues/1059)) ([ce68fdd1d3](https://github.com/Devolutions/devolutions-gateway/commit/ce68fdd1d3b5257654df7f38743a0d875677960b)) 

  Returns a link to x509.io Certificate Viewer in order to inspect the
  certification chain conveniently.

- _dgw_: shadowing player web-component ([#1075](https://github.com/Devolutions/devolutions-gateway/issues/1075)) ([5169f60622](https://github.com/Devolutions/devolutions-gateway/commit/5169f6062231b92b87236ec38b6987f18659dfdf)) 

- _dgw_: /jet/jrec/delete endpoint for mass deletion ([#1093](https://github.com/Devolutions/devolutions-gateway/issues/1093)) ([341d455f6c](https://github.com/Devolutions/devolutions-gateway/commit/341d455f6c3440f6e98f75fa70e765a0fa59dffe)) ([DGW-219](https://devolutions.atlassian.net/browse/DGW-219)) 

  A new endpoint not taking any parameter via the request path.
  Instead, a list of session IDs is provided in the request body.

### Improvements

- _dgw_: disallow SCOPE tokens missing the jti claim ([#1082](https://github.com/Devolutions/devolutions-gateway/issues/1082)) ([78396b5e14](https://github.com/Devolutions/devolutions-gateway/commit/78396b5e14e4fe463c15ef09cf1fb902ef751658)) 

  DVLS generates this claim since its version 2022.1.9.
  This version is almost three years old, and already completely phased
  out, as such it’s more than reasonable to stop supporting this kind
  of token.

### Bug Fixes

- _dgw_: the recording policy wasn't set for RDP via web ([#1044](https://github.com/Devolutions/devolutions-gateway/issues/1044)) ([01fb589311](https://github.com/Devolutions/devolutions-gateway/commit/01fb589311fb25cf6e5c5f27e4b7a55708af5ae7)) 

- _dgw_: support for .cast files that have two slices with the same timestamp in recording player ([#1054](https://github.com/Devolutions/devolutions-gateway/issues/1054)) ([8ed5163f3a](https://github.com/Devolutions/devolutions-gateway/commit/8ed5163f3a6cf64d789cc43734f10503db88705f)) 

- _dgw_: allow any header to be set in browser JavaScript HTTP requests ([#1083](https://github.com/Devolutions/devolutions-gateway/issues/1083)) ([0a7c80898a](https://github.com/Devolutions/devolutions-gateway/commit/0a7c80898a998827ba42831b6adaa07b70f974ef)) 

  We don’t expose any header particularly sensitive from the Devolutions
  Gateway, and the future HTTP bridge will always require a token which
  is only issued on a per-need basis. In fact, in such cases we actually
  want to allow virtually any header to be used for web-based integration
  of various web services (e.g.: VMware dashboard).
  The restriction imposed by the token requirement is strong enough.

- _dgw_: better custom recording paths handling in heartbeat endpoint ([#1097](https://github.com/Devolutions/devolutions-gateway/issues/1097)) ([c1d047c190](https://github.com/Devolutions/devolutions-gateway/commit/c1d047c1907c95cc2b2198b66f623ddbd8cc66bd)) ([DGW-218](https://devolutions.atlassian.net/browse/DGW-218)) 

  On Windows, the std::fs::canonicalize function returns
  Windows NT UNC paths, but our code detecting the mount point does not
  understand that.
  We use dunce to handle that for us instead.

## 2024.3.3 (2024-10-02)

### Features

- _pedm_: add context menu icon resource ([#990](https://github.com/Devolutions/devolutions-gateway/issues/990)) ([263de985cc](https://github.com/Devolutions/devolutions-gateway/commit/263de985cc7eec51cb906d8e0d3669d827e1dfcc)) 

- _agent_: devolutions-session bootstrap ([#997](https://github.com/Devolutions/devolutions-gateway/issues/997)) ([f8b291d908](https://github.com/Devolutions/devolutions-gateway/commit/f8b291d9080c5c541f85c434e5fd23a39319f6b5)) 

- _jetsocat_: Windows named pipes and Unix sockets ([#1022](https://github.com/Devolutions/devolutions-gateway/issues/1022)) ([b13caba5b6](https://github.com/Devolutions/devolutions-gateway/commit/b13caba5b6a3481861e5cf1595c33e3d0968c93c)) 

- _jetsocat_: new doctor subcommand for diagnostics ([#1030](https://github.com/Devolutions/devolutions-gateway/issues/1030)) ([6ed8591b38](https://github.com/Devolutions/devolutions-gateway/commit/6ed8591b3865de82c6b3984ded2e335880f2b379)) 

### Bug Fixes

- _pwsh_: trace more info when importing Certificate from PFX ([#992](https://github.com/Devolutions/devolutions-gateway/issues/992)) ([5de155738a](https://github.com/Devolutions/devolutions-gateway/commit/5de155738a872dcdba922ea54354121277b27c93)) 

- _dgw_: set dwShareMode for recording files on Windows ([#1007](https://github.com/Devolutions/devolutions-gateway/issues/1007)) ([4df3c854ca](https://github.com/Devolutions/devolutions-gateway/commit/4df3c854cae6642f6c771621c68ef79c478db796)) 

  On Windows, the default default share_mode set when opening a new file
  is `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
  
  We now override the share_mode and set it to `FILE_SHARE_READ`.
  
  This makes the recording process more robust by ensuring no other
  process can write or delete the files while the Devolutions Gateway
  is actively writing it.

- _jetsocat,dgw_: add backpressure in JMUX proxy ([41ea3ee3f0](https://github.com/Devolutions/devolutions-gateway/commit/41ea3ee3f03254c1415624d2344dd9b2dca38d65)) 

  The memory consumption of the JMUX proxy was unbounded because we used
  an unbounded mpsc channel for message passing.
  
  Here is a `jetsocat-bench.nu` run against master:

- _dgw_: start the recording player immediately when tab is open ([#1024](https://github.com/Devolutions/devolutions-gateway/issues/1024)) ([6506b08ee2](https://github.com/Devolutions/devolutions-gateway/commit/6506b08ee2e604867bc73c46c08b6b42ba716745)) ([RDMW-16402](https://devolutions.atlassian.net/browse/RDMW-16402)) 

## 2024.3.2 (2024-08-20)

### Features

- _agent_: initial PEDM implementation ([1ed573ae54](https://github.com/Devolutions/devolutions-gateway/commit/1ed573ae546d17582e6cb1209d588d21e8b47236)) 

### Improvements

- _dgw_: log KDC domain when throwing the error ([#963](https://github.com/Devolutions/devolutions-gateway/issues/963)) ([873217c804](https://github.com/Devolutions/devolutions-gateway/commit/873217c8042167bf378613f812b3db2a399d256a)) 

  We now print the name of the requested domain when the requested
  domain didn't match the authorized (expected) domain.

- _dgw_: accept subject name even if it does not match the hostname ([1f40b45bae](https://github.com/Devolutions/devolutions-gateway/commit/1f40b45baed4c4aca71344de30d826b354029086)) 

  Configurations where the certificate subject name does not match the
  hostname are now accepted.
  Instead, a few warning and debug log records are added to help
  discover configuration issues in case of problem.
  The problem with the strict approach we had previously is that we
  may reject valid configurations where the hostname was actually
  matched by one of the subject alternative names in the certificate.

### Performance

- _jetsocat_: use a larger buffer for plain forwarding ([#968](https://github.com/Devolutions/devolutions-gateway/issues/968)) ([6c18ff1fc1](https://github.com/Devolutions/devolutions-gateway/commit/6c18ff1fc133ecf7bb00ff0a235494988f479e19)) 

  By increasing the size of the intermediate buffer from 8k to 16k,
  performance of raw TCP forwarding is increased by ~19.4%.
  
  Performance was measured using `iperf` on local network.

- _jetsocat,dgw_: major throughput improvement for JMUX proxy (Devolutions Gateway Tunnel) ([#973](https://github.com/Devolutions/devolutions-gateway/issues/973)) ([32de1d50de](https://github.com/Devolutions/devolutions-gateway/commit/32de1d50de509559e2b8f2d6c7e1259c0db85cb1)) ([#975](https://github.com/Devolutions/devolutions-gateway/issues/975)) ([8ebfd2316d](https://github.com/Devolutions/devolutions-gateway/commit/8ebfd2316d2bcc1355e9dadd3d379b635c74bb23)) ([#976](https://github.com/Devolutions/devolutions-gateway/issues/976)) ([11efaa5cfe](https://github.com/Devolutions/devolutions-gateway/commit/11efaa5cfe1a87d3880c82a27e37a4da9d38ed4e)) ([#977](https://github.com/Devolutions/devolutions-gateway/issues/977)) ([6b77a993ab](https://github.com/Devolutions/devolutions-gateway/commit/6b77a993abdfb9022babf35194b66c135c06fa53)) ([DGW-202](https://devolutions.atlassian.net/browse/DGW-202)) ([#980](https://github.com/Devolutions/devolutions-gateway/issues/980)) ([53af6fa7c7](https://github.com/Devolutions/devolutions-gateway/commit/53af6fa7c7bab58498b8b0e82d5f7998efe0c368))

  See [JMUX-proxy-performance.md](./docs/JMUX-proxy-performance.md).

### Build

- _dgw_: update cryptography dependencies ([787027cbf9](https://github.com/Devolutions/devolutions-gateway/commit/787027cbf96c19a440a401512f9b351b340632e6)) 

  We keep using ring as our crypto provider for now.

## 2024.3.1 (2024-08-01)

### Features

- _dgw_: dynamically load XMF native lib on startup ([#939](https://github.com/Devolutions/devolutions-gateway/issues/939)) ([86dee2631a](https://github.com/Devolutions/devolutions-gateway/commit/86dee2631a210cf89e07727bec52cc773f23e8e8)) 

  The `DGATEWAY_LIB_XMF_PATH` environment variable can be used optionally to specify the path to
  the XMF native library.

- _dgw_: remux webm files when video recording ends ([#943](https://github.com/Devolutions/devolutions-gateway/issues/943)) ([cc787ef691](https://github.com/Devolutions/devolutions-gateway/commit/cc787ef69195cc55dbd001159b19a61d70fe6404)) 

### Bug Fixes

- _dgw_: fix recording player parsing problem ([#937](https://github.com/Devolutions/devolutions-gateway/issues/937)) ([cdf08a3e2c](https://github.com/Devolutions/devolutions-gateway/commit/cdf08a3e2cd3357af5a68573aa5ba7fe3ad07862)) ([DPS-11197](https://devolutions.atlassian.net/browse/DPS-11197)) 

  - Remove usage of btoa, it fails on different charset.

  - Add 1 millisecond if the time of previous event is the same at the next event.
    Otherwise, the player will throw an error.

- _webapp_: fix RDP connection form - set pre connection blob as not required ([#950](https://github.com/Devolutions/devolutions-gateway/issues/950)) ([c684994fce](https://github.com/Devolutions/devolutions-gateway/commit/c684994fcec84b376a716725a72c8e856e59ecac)) 

- _webapp_: add tooltip ellipsis for long netscan service names ([#946](https://github.com/Devolutions/devolutions-gateway/issues/946)) ([5e4b3080d6](https://github.com/Devolutions/devolutions-gateway/commit/5e4b3080d6f6ce8525bf36d3fff2da8d56782276)) ([DGW-204](https://devolutions.atlassian.net/browse/DGW-204))

- _dgw_: [**breaking**] jet_rec claim is now a string ([#957](https://github.com/Devolutions/devolutions-gateway/issues/957)) ([59bb0af249](https://github.com/Devolutions/devolutions-gateway/commit/59bb0af249ad99a616e2b6308db7bbab84b55068)) 

  Possible values are:
  
  - `none`: No policy to enforce (recording is optional)
  
  - `stream`: An external application (e.g.: RDM) must push the
    recording stream via a separate websocket connection
  
  - `proxy`: Session must be recorded directly at Devolutions Gateway
    level (not implemented yet)

  Note: Up until now, Devolutions Gateway was rejecting sessions when this claim was found because it couldn’t upheld
  the policy. It’s effectively not breaking anything which wasn’t already broken previously.

## 2024.3.0 (2024-07-24)

### Features

- _agent_: Devolutions Gateway service updater ([#889](https://github.com/Devolutions/devolutions-gateway/issues/889)) ([92f86bf51b](https://github.com/Devolutions/devolutions-gateway/commit/92f86bf51b072699a86173affda5b54cced1fc07)) 

- _dgw_: add API to trigger Devolutions Gateway update ([#890](https://github.com/Devolutions/devolutions-gateway/issues/890)) ([799e518c15](https://github.com/Devolutions/devolutions-gateway/commit/799e518c154db18d8895b96a08eec336ff70edcb)) 

- _dgw_: support .cast terminal recording files ([#900](https://github.com/Devolutions/devolutions-gateway/issues/900)) ([d1f7559a3e](https://github.com/Devolutions/devolutions-gateway/commit/d1f7559a3ee422c3e0696ed9f1ccc02eb17f9e7d)) 

  The .cast extension is used for "asciicast" files, i.e.: asciinema cast files.
  This is a widely used terminal playback format.

### Bug Fixes

- _dgw_: preserve DGW access URI base in recording player ([#899](https://github.com/Devolutions/devolutions-gateway/issues/899)) ([92f87c8cea](https://github.com/Devolutions/devolutions-gateway/commit/92f87c8ceac7f16e5f25cc68578474e7a4a17ee9)) 

  This is notably important for DVLS side by side setups.

- _dgw_: fix cast file not working in recording player page ([#904](https://github.com/Devolutions/devolutions-gateway/issues/904)) ([c6985152a2](https://github.com/Devolutions/devolutions-gateway/commit/c6985152a297c7a9b949781e6efc1f6b36be85d0)) 

- _dgw_: enforce recording policy ([#906](https://github.com/Devolutions/devolutions-gateway/issues/906)) ([13ed397eee](https://github.com/Devolutions/devolutions-gateway/commit/13ed397eeea965e696bf811ef774cfaf1e2bb8ac)) ([DGW-86](https://devolutions.atlassian.net/browse/DGW-86)) 

  When recording flag is set and recording stream is closed, the associated
  session is killed within 10 seconds.

- _dgw_: support for `jet_rec` claim in JMUX tokens ([#909](https://github.com/Devolutions/devolutions-gateway/issues/909)) ([8b0c3eb80b](https://github.com/Devolutions/devolutions-gateway/commit/8b0c3eb80b631307995a168d3839118874466fc8)) 

- _dgw_: recording player now scales with the size of the window ([#922](https://github.com/Devolutions/devolutions-gateway/issues/922)) ([4cb95a5e0c](https://github.com/Devolutions/devolutions-gateway/commit/4cb95a5e0c19a92909df99894796e5f818cb7e1b)) ([DGW-198](https://devolutions.atlassian.net/browse/DGW-198)) 

## 2024.2.3 (2024-06-18)

### Bug Fixes

- _installer_: fix parsing errors with configuration check ([#893](https://github.com/Devolutions/devolutions-gateway/issues/893)) ([4f89688316](https://github.com/Devolutions/devolutions-gateway/commit/4f8968831698bb82afe06eb69421c6d984c7b062))

- _installer_: package web player ([#894](https://github.com/Devolutions/devolutions-gateway/issues/894)) ([bbee301682](https://github.com/Devolutions/devolutions-gateway/commit/bbee301682dbdb8191a678a5853d92586eb883ff))

## 2024.2.2 (2024-06-18)

### Features

- _installer_: add a basic configuration check ([#888](https://github.com/Devolutions/devolutions-gateway/issues/888)) ([2c3877e802](https://github.com/Devolutions/devolutions-gateway/commit/2c3877e8023ea8bfa590dfd4d29a5d164ddb02b7)) 

### Bug Fixes

- _dgw_: IP restrictions fallback for ngrok TCP listeners ([#881](https://github.com/Devolutions/devolutions-gateway/issues/881)) ([c2635ec6dc](https://github.com/Devolutions/devolutions-gateway/commit/c2635ec6dca3c9820c909d7e3337311481a0376d)) ([DGW-193](https://devolutions.atlassian.net/browse/DGW-193)) 

  Now properly fallbacks to disabling IP restriction rules for TCP
  listeners as well.

- _dgw_: rework network interface DTO definition ([#871](https://github.com/Devolutions/devolutions-gateway/issues/871)) ([bc2cb96f9d](https://github.com/Devolutions/devolutions-gateway/commit/bc2cb96f9ddf6f36d3a89f9b4db4bccfb39227fa)) ([DGW-133](https://devolutions.atlassian.net/browse/DGW-133)) 

## 2024.2.1 (2024-05-22)

### Bug Fixes

- _installer_: use Win32 to set file permissions ([#869](https://github.com/Devolutions/devolutions-gateway/issues/869)) ([813fc7f3bc](https://github.com/Devolutions/devolutions-gateway/commit/813fc7f3bc2c96793f2c4a6c99f7a8067402381e)) 

## 2024.2.0 (2024-05-21)

### Features

- _webapp_: allow ssh client to use encrypted ssh keys ([#856](https://github.com/Devolutions/devolutions-gateway/issues/856)) ([6424c40ecb](https://github.com/Devolutions/devolutions-gateway/commit/6424c40ecbb975bbca05be476e11164a1e7b76c9)) 

### Improvements

- _webapp_: fix netscan result duplicate and performance improvement ([#845](https://github.com/Devolutions/devolutions-gateway/issues/845)) ([f447381294](https://github.com/Devolutions/devolutions-gateway/commit/f44738129446f3d609956d09674440b8efa7155e)) ([DGW-184](https://devolutions.atlassian.net/browse/DGW-184))

### Bug Fixes

- _webapp_: new version button is available even when a more recent version is used ([#846](https://github.com/Devolutions/devolutions-gateway/issues/846)) ([2b92c9ab3b](https://github.com/Devolutions/devolutions-gateway/commit/2b92c9ab3b7dc94007746be4eff5434fc3b1de64)) ([DGW-182](https://devolutions.atlassian.net/browse/DGW-182))

- _webapp_: fix misaligned "Fill form" buttons when the hostname is too long ([#844](https://github.com/Devolutions/devolutions-gateway/issues/844)) ([1b8a6ebe9c](https://github.com/Devolutions/devolutions-gateway/commit/1b8a6ebe9c57469ce690380b480ce081842a3271)) ([DGW-180](https://devolutions.atlassian.net/browse/DGW-180))

- _webapp_: fix force rescan button ([#847](https://github.com/Devolutions/devolutions-gateway/issues/847)) ([a08dd3159e](https://github.com/Devolutions/devolutions-gateway/commit/a08dd3159eb6ee5000d9214ac1f2664531b2e78d)) ([DGW-185](https://devolutions.atlassian.net/browse/DGW-185)) 

- _webapp_: add tooltip to menu warning icon when session is closed ([#852](https://github.com/Devolutions/devolutions-gateway/issues/852)) ([b4ed845695](https://github.com/Devolutions/devolutions-gateway/commit/b4ed8456956917521a37e5ac24bae10742705175)) ([DGW-145](https://devolutions.atlassian.net/browse/DGW-145)) 

- _webapp_: prevent suspicious "e" console logs ([#851](https://github.com/Devolutions/devolutions-gateway/issues/851)) ([cbf9bd360e](https://github.com/Devolutions/devolutions-gateway/commit/cbf9bd360e6dd2afe75de511e966ce748e129ca6)) ([DGW-164](https://devolutions.atlassian.net/browse/DGW-164)) 

  Downgrade the Primeng package as the log was introduced in version 16.5.0.

- _webapp_: connect session button stays grayed out intermittently ([#855](https://github.com/Devolutions/devolutions-gateway/issues/855)) ([3fdce898e5](https://github.com/Devolutions/devolutions-gateway/commit/3fdce898e55c19e0217816020cb1ed3316b067f0)) ([DGW-183](https://devolutions.atlassian.net/browse/DGW-183)) 

- _dgw_: write new JRL into a temporary file, and swap on success ([#857](https://github.com/Devolutions/devolutions-gateway/issues/857)) ([d91f1cfb6a](https://github.com/Devolutions/devolutions-gateway/commit/d91f1cfb6a982be7c49e3fbdc31ce46a4ce4e20b)) ([DGW-104](https://devolutions.atlassian.net/browse/DGW-104)) 

  It’s preferable to proceed like this to avoid losing current JRL file
  if the file is truncated without being rewritten successfully immediately.

- _pwsh_: fix reading .pem files from PowerShell runspace ([#859](https://github.com/Devolutions/devolutions-gateway/issues/859)) ([98437f6f4e](https://github.com/Devolutions/devolutions-gateway/commit/98437f6f4e836d4cdaa3fdce79d70aeda977c1bf)) 

- _webapp_: format the error backtrace to show line breaks ([#860](https://github.com/Devolutions/devolutions-gateway/issues/860)) ([7e50a04dbd](https://github.com/Devolutions/devolutions-gateway/commit/7e50a04dbdba2e2d33dd9fa18dd6a06d7189624c)) ([DGW-169](https://devolutions.atlassian.net/browse/DGW-169)) 

- _webapp_: menu icon does not update on error for RDP, ARD, VNC ([#861](https://github.com/Devolutions/devolutions-gateway/issues/861)) ([235e3a72f5](https://github.com/Devolutions/devolutions-gateway/commit/235e3a72f511a035b4666f3a721b77a377d4a591)) ([DGW-168](https://devolutions.atlassian.net/browse/DGW-168)) 

- _webapp_: tooltip for the selected protocol is always set to RDP ([#862](https://github.com/Devolutions/devolutions-gateway/issues/862)) ([717d53e149](https://github.com/Devolutions/devolutions-gateway/commit/717d53e1494cfe796ed2978c1aa2757753ef0c95)) ([DGW-187](https://devolutions.atlassian.net/browse/DGW-187)) 

- _dgw_: prevent error traces caused by browser behavior ([#864](https://github.com/Devolutions/devolutions-gateway/issues/864)) ([25b86ea1b3](https://github.com/Devolutions/devolutions-gateway/commit/25b86ea1b3ff63c692eacceed6abb43248ca85f2)) ([DGW-128](https://devolutions.atlassian.net/browse/DGW-128)) 

  Since those are not actual errors, this was creating noise in the logs.

### Performance

- _dgw_: keep HTTP connections open for 10 minutes ([#863](https://github.com/Devolutions/devolutions-gateway/issues/863)) ([245e2cfb26](https://github.com/Devolutions/devolutions-gateway/commit/245e2cfb26ae4a6e39e865c506cd557e551a67c6)) 

  Most browsers will keep HTTP connections open to increase throughput
  when performing subsequent transactions.
  For simplicity, we don’t distinguish between idle and non-idle
  connections.

### Build

- _webapp_: build using production profile ([#853](https://github.com/Devolutions/devolutions-gateway/issues/853)) ([fbbcbbe96c](https://github.com/Devolutions/devolutions-gateway/commit/fbbcbbe96ce901b9103d32d89ead5a54284bd02b)) 

## 2024.1.6 (2024-05-06)

### Features

- _webapp_: add ssh key authentication ([#796](https://github.com/Devolutions/devolutions-gateway/issues/796)) ([a884cbb8ff](https://github.com/Devolutions/devolutions-gateway/commit/a884cbb8ff313496fb3d4072e67ef75350c40c03)) 

- _dgw_: add /jet/jrec/play endpoint ([#806](https://github.com/Devolutions/devolutions-gateway/issues/806)) ([3e7aa30da7](https://github.com/Devolutions/devolutions-gateway/commit/3e7aa30da7b6f6771cf63c8e714ea851d54c4475)) ([DGW-111](https://devolutions.atlassian.net/browse/DGW-111)) 

- _webapp_: network scanning ([#826](https://github.com/Devolutions/devolutions-gateway/issues/826)) ([1e4a18a23c](https://github.com/Devolutions/devolutions-gateway/commit/1e4a18a23c3a2921bbaa174d4c9c7fbcb3bef83b)) ([DGW-119](https://devolutions.atlassian.net/browse/DGW-119))

- _dgw_: return disk space available for recordings ([#827](https://github.com/Devolutions/devolutions-gateway/issues/827)) ([c0776d43de](https://github.com/Devolutions/devolutions-gateway/commit/c0776d43de0da63aa7a40ef40ae3ba456f8aedac)) ([DGW-100](https://devolutions.atlassian.net/browse/DGW-100)) 

  The total and available space used for storing recordings is now
  returned inside the heartbeat response.
  
  If the system does not support this operation, the fields are
  excluded from the response.

- _dgw_: add `/jet/jrec/delete/<ID>` endpoint ([#834](https://github.com/Devolutions/devolutions-gateway/issues/834)) ([0965f4e2a7](https://github.com/Devolutions/devolutions-gateway/commit/0965f4e2a7f5b39a1f3f93a1f8a1f2c0c77aa961)) ([DGW-96](https://devolutions.atlassian.net/browse/DGW-96)) 

  This new endpoint is used for deleting recordings and allow the
  service provider (e.g.: DVLS) to delete them according to its
  policy.

- _dgw_: add `recording_storage_is_writeable` in heartbeat ([#835](https://github.com/Devolutions/devolutions-gateway/issues/835)) ([a209dc6933](https://github.com/Devolutions/devolutions-gateway/commit/a209dc6933a03c0e57e5f6ce65f966e765741d88)) ([DGW-175](https://devolutions.atlassian.net/browse/DGW-175)) 

- _dgw_: WebM player for remote desktop recordings ([#832](https://github.com/Devolutions/devolutions-gateway/issues/832)) ([58362b9c4a](https://github.com/Devolutions/devolutions-gateway/commit/58362b9c4a7ea7a8752a8921e6b65c6390524d2f)) ([DGW-110](https://devolutions.atlassian.net/browse/DGW-110)) 

  Adds a video and xterm player at the `GET /jet/jrec/play` endpoint which
  supports multiple videos and builds the page dynamically based on the
  type of recording.

### Improvements

- _webapp_: update IronVNC to 0.2.2 ([#808](https://github.com/Devolutions/devolutions-gateway/issues/808)) ([1fc0242eee](https://github.com/Devolutions/devolutions-gateway/commit/1fc0242eeef8971f2f4e270253ae3c6b6cc09eb7)) ([DGW-138](https://devolutions.atlassian.net/browse/DGW-138)) 

  - Improve MVS codec performance by about 60%
  - Re-enable MVS codec

- _webapp_: add analytics ([#813](https://github.com/Devolutions/devolutions-gateway/issues/813)) ([55d3749e3f](https://github.com/Devolutions/devolutions-gateway/commit/55d3749e3fa94e0d2ee70bfb71bb0b07ee92cf13)) 

### Bug Fixes

- _dgw_: error code on service startup failure ([#816](https://github.com/Devolutions/devolutions-gateway/issues/816)) ([66e7ce2599](https://github.com/Devolutions/devolutions-gateway/commit/66e7ce2599f2950d0e845e76628f7bb0edbfbdb1)) ([DGW-174](https://devolutions.atlassian.net/browse/DGW-174)) 

  Instead of panicking when failing to start the service, we instead
  attempt to log the error to the log file and return an error code.

- _webapp_: login screen not shown when opening /jet/webapp/client/ ([#839](https://github.com/Devolutions/devolutions-gateway/issues/839)) ([b58b03832f](https://github.com/Devolutions/devolutions-gateway/commit/b58b03832ff8a1c4402447707665127b5258d8b9)) ([DGW-176](https://devolutions.atlassian.net/browse/DGW-176)) 

- _installer_: [**breaking**] install Gateway service as NetworkService ([#838](https://github.com/Devolutions/devolutions-gateway/issues/838)) ([1c8a7d2e0a](https://github.com/Devolutions/devolutions-gateway/commit/1c8a7d2e0a7a7498ecc8cf3a5cd37dcd71dee6c3)) 

### Performance

- _dgw_: use a buffer of 1k bytes for ARD VNC sessions ([#809](https://github.com/Devolutions/devolutions-gateway/issues/809)) ([5697097561](https://github.com/Devolutions/devolutions-gateway/commit/5697097561d5569cea91d497ddb70e9c460da741)) ([DGW-138](https://devolutions.atlassian.net/browse/DGW-138)) 

  Apple ARD uses the so-called MVS video codec.
  It is a tricky codec: Apple didn't implement proper congestion control, so it's basically just TCP controlling the flow (not by much).
  Our MVS implementation for the web client is obviously not as fast as the native one, and can’t keep up when there are too much data in transit.
  To reduce the amount of data in transit, we reduced the size of the copy buffer when using web socket forwarding endpoint and if the application protocol of the session is set to ARD.

### Build

- Bump Rust toolchain to 1.77.2 ([#828](https://github.com/Devolutions/devolutions-gateway/issues/828)) ([8898dfcce4](https://github.com/Devolutions/devolutions-gateway/commit/8898dfcce4fd7757f78943159e026d959d3269e1)) 

- Set content type on macOS jetsocat binary ([#800](https://github.com/Devolutions/devolutions-gateway/issues/800)) ([6e878d8db0](https://github.com/Devolutions/devolutions-gateway/commit/6e878d8db0dd1c42ede7e3fd0cbb9327969c767c)) 

## 2024.1.5 (2024-04-04)

### Bug Fixes

- _installer_: prevent possible prompt for firewall access in Windows installer ([f9760f2a1b](https://github.com/Devolutions/devolutions-gateway/commit/f9760f2a1b70cb000a63780eef2d279ce17a3ec7)) 

## 2024.1.4 (2024-03-22)

### Bug Fixes

- _installer_: add webapp client frontend to .deb package ([#770](https://github.com/Devolutions/devolutions-gateway/issues/770)) ([9832a6ad3b](https://github.com/Devolutions/devolutions-gateway/commit/9832a6ad3b566e5389f5375972831b074283f0ef)) 

- _dgw_: resolve web frontend on Linux ([#772](https://github.com/Devolutions/devolutions-gateway/issues/772)) ([dff788c56b](https://github.com/Devolutions/devolutions-gateway/commit/dff788c56b0770b38fefb34f822f3da94adfc055)) 

### Build

- _jetsocat_: build jetsocat for linux-arm64 target ([#765](https://github.com/Devolutions/devolutions-gateway/issues/765)) ([1ccfd690e0](https://github.com/Devolutions/devolutions-gateway/commit/1ccfd690e0030a976bb0d6a0f1fd9b508026d05e)) 

## 2024.1.3 (2024-03-08)

### Features

- _webapp_: version number at the bottom of the app menu ([#752](https://github.com/Devolutions/devolutions-gateway/issues/752)) ([e46b4fc5a9](https://github.com/Devolutions/devolutions-gateway/commit/e46b4fc5a9eb237dd49d6f30650866be0323630b)) 

- _webapp_: check if a new version is available ([#757](https://github.com/Devolutions/devolutions-gateway/issues/757)) ([d2d8811c36](https://github.com/Devolutions/devolutions-gateway/commit/d2d8811c3688de3ef675599412db20b06a63bd3e)) 

- _webapp_: bump iron-remote-gui-vnc to 0.2.1 ([#754](https://github.com/Devolutions/devolutions-gateway/issues/754)) ([6c3df0c18e](https://github.com/Devolutions/devolutions-gateway/commit/6c3df0c18e71dd11cb72c4fc3cb54f989eaa6682)) 

  - Support for client-side rendered hardware-accelerated cursors

### Improvements

- _webapp_: improve the error catching for VNC and ARD ([#739](https://github.com/Devolutions/devolutions-gateway/issues/739)) ([d34e188aba](https://github.com/Devolutions/devolutions-gateway/commit/d34e188aba0e0a1ace4747bc9dbeaf7ca3e26824)) ([DGW-157](https://devolutions.atlassian.net/browse/DGW-157)) 

### Bug Fixes

- _webapp_: update IronVNC to 0.1.6 ([#749](https://github.com/Devolutions/devolutions-gateway/issues/749)) ([ffc4427dca](https://github.com/Devolutions/devolutions-gateway/commit/ffc4427dca1504e1180c7401e7d086e10adddc5c)) 

  - fix connection not shut down properly

- _webapp_: shutdown not called when closing from left menu ([#750](https://github.com/Devolutions/devolutions-gateway/issues/750)) ([ace64d3eb6](https://github.com/Devolutions/devolutions-gateway/commit/ace64d3eb6dcf5dc3e646937288708f0c1f39d49)) ([DGW-167](https://devolutions.atlassian.net/browse/DGW-167)) 

- _installer_: properly write ARP InstallLocation on fresh installs ([270c4e981d](https://github.com/Devolutions/devolutions-gateway/commit/270c4e981d689bc25b681c4b76b535eb38a79c41)) 

- _webapp_: show error backtrace for VNC, ARD and RDP clients ([#751](https://github.com/Devolutions/devolutions-gateway/issues/751)) ([c5caf5ab25](https://github.com/Devolutions/devolutions-gateway/commit/c5caf5ab25d16e1cae2b04600a0366e5f759f5a0)) ([DGW-162](https://devolutions.atlassian.net/browse/DGW-162)) 

## 2024.1.2 (2024-03-05)

### Bug Fixes

- _webapp_: authentication list state is not preserved on error ([#735](https://github.com/Devolutions/devolutions-gateway/issues/735)) ([f2852d99ad](https://github.com/Devolutions/devolutions-gateway/commit/f2852d99adc1f108a4fdf9b80bf6504d1c81d592)) ([DGW-147](https://devolutions.atlassian.net/browse/DGW-147)) 

- _webapp_: fix web form controls data submission ([#736](https://github.com/Devolutions/devolutions-gateway/issues/736)) ([d2f793b71f](https://github.com/Devolutions/devolutions-gateway/commit/d2f793b71f8aa0e5713de6347d0e846c4f649e21)) ([DGW-151](https://devolutions.atlassian.net/browse/DGW-151)) 

- _webapp_: add favicon ([#738](https://github.com/Devolutions/devolutions-gateway/issues/738)) ([2fe051369d](https://github.com/Devolutions/devolutions-gateway/commit/2fe051369d4525054063bdecdec9bb2004c81e25)) 

- _webapp_: configure angular production build ([#737](https://github.com/Devolutions/devolutions-gateway/issues/737)) ([52b58b92bd](https://github.com/Devolutions/devolutions-gateway/commit/52b58b92bd3fadbff74a4bd9879f9d7889828207)) ([DGW-144](https://devolutions.atlassian.net/browse/DGW-144)) 

- _webapp_: web form UI - fix spinner for autocomplete ([#740](https://github.com/Devolutions/devolutions-gateway/issues/740)) ([8649bd3eac](https://github.com/Devolutions/devolutions-gateway/commit/8649bd3eacdd66cfa492f3840dfd413b07be6786)) 

- _webapp_: bump IronVNC and IronRDP packages ([#744](https://github.com/Devolutions/devolutions-gateway/issues/744)) ([6677ed0a41](https://github.com/Devolutions/devolutions-gateway/commit/6677ed0a4178908ed6d398939010a958c229fd6d)) 

  - RDP: fix performance flags
  - VNC: better error status codes on authentication
  - VNC: fix initial screen state not being properly painted

- _pwsh_: support for non-PEM, binary certificate files ([#745](https://github.com/Devolutions/devolutions-gateway/issues/745)) ([6f7589f598](https://github.com/Devolutions/devolutions-gateway/commit/6f7589f59834c10ef302de8735f0c9900bcf2c75)) ([DGW-135](https://devolutions.atlassian.net/browse/DGW-135)) 

- _webapp_: update fontscdn link ([#729](https://github.com/Devolutions/devolutions-gateway/issues/729)) ([989e5b98fc](https://github.com/Devolutions/devolutions-gateway/commit/989e5b98fc2be511fde9fd40fd3af1f2b1916b38)) 

## 2024.1.1 (2024-02-29)

### Features

- _webapp_: bump IronVNC and IronRDP packages ([#730](https://github.com/Devolutions/devolutions-gateway/issues/730)) ([dd46b48559](https://github.com/Devolutions/devolutions-gateway/commit/dd46b4855901176407384023fc7abf8d720e81e6)) 

  - RDP: enable performance flags
  - VNC: disable MVS codec for ARD
  - VNC: clipboard support

### Bug Fixes

- _installer_: layout tweaks for better HiDPI support ([#724](https://github.com/Devolutions/devolutions-gateway/issues/724)) ([dd864ba80e](https://github.com/Devolutions/devolutions-gateway/commit/dd864ba80ec7cb7799584a168fbfd747e067c333)) 

- _webapp_: disable debug logging by default ([#726](https://github.com/Devolutions/devolutions-gateway/issues/726)) ([27d70c9af4](https://github.com/Devolutions/devolutions-gateway/commit/27d70c9af44581567b78652b32b7a6e57da76e79)) 

  Remove console.logs and turn off debugwasm for IronRDP and IronVNC.

- _webapp_: UI issues in sidebar menu and web form ([#727](https://github.com/Devolutions/devolutions-gateway/issues/727)) ([6b605780c3](https://github.com/Devolutions/devolutions-gateway/commit/6b605780c3119c7e91b6e01db02d3c94e812a439)) 

- _dgw_: fix Linux issues with network scanner ([#715](https://github.com/Devolutions/devolutions-gateway/issues/715)) ([0c6f644724](https://github.com/Devolutions/devolutions-gateway/commit/0c6f6447247883cb125df6d568ebe37e3106451c)) 

- _webapp_: update SSH and Telnet packages ([#728](https://github.com/Devolutions/devolutions-gateway/issues/728)) ([5bc14ec9c7](https://github.com/Devolutions/devolutions-gateway/commit/5bc14ec9c7da9404dd9ec134af7a471c13525c9b)) 

  Fixes a bug when the hostname is incorrect where the connection to the Gateway was being lost, and close session elegantly.

### Documentation

- _pwsh_: update PSGallery tags ([#725](https://github.com/Devolutions/devolutions-gateway/issues/725)) ([edd9fcff6b](https://github.com/Devolutions/devolutions-gateway/commit/edd9fcff6bbdc51789b67b8efa440882c8ca5f0c)) 

## 2024.1.0 (2024-02-26)

### Features

- _dgw_: standalone web application V1 :tada:

- _installer_: new Windows installer built using WixSharp

- _pwsh_: add powershell user management with argon2 password hashing ([#658](https://github.com/Devolutions/devolutions-gateway/issues/658)) ([7157ad6082](https://github.com/Devolutions/devolutions-gateway/commit/7157ad608278278d63096297ae1d6c04b768a984)) 

- _installer_: add ngrok configuration support ([#669](https://github.com/Devolutions/devolutions-gateway/issues/669)) ([2caeabab2e](https://github.com/Devolutions/devolutions-gateway/commit/2caeabab2ed8e9827ce2507fa21dca81745d64c1)) 

- _dgw_: debug option to set the webapp path ([#663](https://github.com/Devolutions/devolutions-gateway/issues/663)) ([7da20760f1](https://github.com/Devolutions/devolutions-gateway/commit/7da20760f1e57772d5f95f19f86872131e4bf3c9)) 

  The `DGATEWAY_WEBAPP_PATH` env variable is conserved.
  A new stable and documented configuration key is added: `WebApp.StaticRootPath`.
  The environment variable will be checked first, then the key in the config file,
  and if nothing is specified, we fall back to a `webapp` folder along the executable.

- _dgw_: network scan HTTP API ([#689](https://github.com/Devolutions/devolutions-gateway/issues/689)) ([846f21d660](https://github.com/Devolutions/devolutions-gateway/commit/846f21d660db5e65341511c916cfd3a4ee15ad7f)) 

### Improvements

- _dgw_: use all resolved addresses when connecting ([#601](https://github.com/Devolutions/devolutions-gateway/issues/601)) ([fe4dc63e40](https://github.com/Devolutions/devolutions-gateway/commit/fe4dc63e409f1da1b0307b94af07bf2168ac0bbb)) ([DGW-125](https://devolutions.atlassian.net/browse/DGW-125)) 

  This patch ensures Devolutions Gateway does not immediately discard
  resolved addresses which are not emitted first by Tokio’s `lookup_host`.
  
  Typically, the first address is enough and there is no need to try
  subsequent ones. Therefore, it is not expected for this change to
  cause any additional latence in the the vast majority of the cases.
  However, just to be on the safe side and enable easier troubleshooting,
  a WARN-level log is emitted when failing at connecting to a resolved
  address. If latence were to be introduced by this patch, we can
  easily be made aware of the problem and investigate further (network
  configuration, etc).
  
  If this proves to be a problem in the future, we can add filtering
  options. For instance, on a network where IPv4 is not supported or
  disabled, we may want to filter out all the IPv4 addresses which may
  be resolved by the Devolutions Gateway.

- _dgw_: improve logs quality for JMUX proxy ([abaa7b23bb](https://github.com/Devolutions/devolutions-gateway/commit/abaa7b23bbe4cd753dcc6f089c978e3f154dab6a)) 

  Notably, status codes like ECONNRESET or ECONNABORTED are not
  considered anymore as actual errors, and will be logged accordingly.

- _dgw_: improve JMUX proxy error display in logs ([#666](https://github.com/Devolutions/devolutions-gateway/issues/666)) ([a42b9d6395](https://github.com/Devolutions/devolutions-gateway/commit/a42b9d63959583e8e7dc64e0f75199428e3343a0)) 

### Bug Fixes

- _dgw_: upgrade Windows store resolve error log ([#617](https://github.com/Devolutions/devolutions-gateway/issues/617)) ([4c4df605d0](https://github.com/Devolutions/devolutions-gateway/commit/4c4df605d0dfb6379bd2bcbbac3ae4034f740d9b)) 

  This can help with troubleshooting configuration problems with
  Windows system certificate store.

- _dgw_: better status code for unreachable KDC server ([#618](https://github.com/Devolutions/devolutions-gateway/issues/618)) ([d0cbd7f6db](https://github.com/Devolutions/devolutions-gateway/commit/d0cbd7f6dbd9aff097af3ae0fb986c6584ab0357)) 

- _dgw_: spurious warning when using a wildcard certificate ([#647](https://github.com/Devolutions/devolutions-gateway/issues/647)) ([b2244a9ab4](https://github.com/Devolutions/devolutions-gateway/commit/b2244a9ab46309c8ac1c3a93d584ca6e635c6645)) 

- _dgw_: ensure the hostname matches TLS certificate ([#648](https://github.com/Devolutions/devolutions-gateway/issues/648)) ([6ebee46634](https://github.com/Devolutions/devolutions-gateway/commit/6ebee466344a365f90a270d47c31145741b457f2)) 

  Warning logs are ignored at this point (logger not yet initialized),
  so it doesn’t really help. Since specifying a hostname not matching the
  TLS subject name is a configuration error, we now return an error upon
  loading the configuration.Log warnings are ignored at this point, so it
  doesn’t really help.

- _dgw_: better support for ngrok free plan ([#718](https://github.com/Devolutions/devolutions-gateway/issues/718)) ([dc58835e20](https://github.com/Devolutions/devolutions-gateway/commit/dc58835e203d598426a789051918c8dee818348c)) ([DGW-134](https://devolutions.atlassian.net/browse/DGW-134)) 

  Our installer is allowing the 0.0.0.0/0 CIDR by default because
  premium plans need the IP restrictions to be configured or just
  all external traffic. However this doesn’t play well with the free
  plan. This patch is using a dirty trick to detect the free plan
  and ignores the IP restriction configuration when it is detected.

### Build

- _dgw_: eliminate openssl link dependency on Linux ([#707](https://github.com/Devolutions/devolutions-gateway/issues/707)) ([8ffb181995](https://github.com/Devolutions/devolutions-gateway/commit/8ffb181995f49c205722cb9548e5e90372be2610)) 

## 2023.3.0 (2023-10-30)

### Features

- _pwsh_: add (Get|Set|Reset)-DGatewayConfigPath cmdlets ([#572](https://github.com/Devolutions/devolutions-gateway/issues/572)) ([d162015843](https://github.com/Devolutions/devolutions-gateway/commit/d162015843a34e933ae76110edb1a40b124c63df)) ([DGW-113](https://devolutions.atlassian.net/browse/DGW-113)) 

- _pwsh_: verbosity profile, ngrok tunnel configuration ([#577](https://github.com/Devolutions/devolutions-gateway/issues/577)) ([51c4d9cee3](https://github.com/Devolutions/devolutions-gateway/commit/51c4d9cee3c989fac19f37ee007abac97767c1ef)) ([DGW-112](https://devolutions.atlassian.net/browse/DGW-112))

- _dgw_: support for Windows Certificate Store ([#576](https://github.com/Devolutions/devolutions-gateway/issues/576)) ([913f9fad03](https://github.com/Devolutions/devolutions-gateway/commit/913f9fad030d46d7db2e5651008c19391e9c908c)) ([DGW-105](https://devolutions.atlassian.net/browse/DGW-105))

  New configuration keys:
  
  - `TlsCertificateSource`: Source for the TLS certificate (`External` or `System`).
  - `TlsCertificateSubjectName`: Subject name of the certificate.
  - `TlsCertificateStoreName`: Name of the System Certificate Store.
  - `TlsCertificateStoreLocation`: Location of the System Certificate Store.

- _pwsh_: add new TLS configuration options ([#581](https://github.com/Devolutions/devolutions-gateway/issues/581)) ([3c12469989](https://github.com/Devolutions/devolutions-gateway/commit/3c124699891472403d0f3b6c96d360304476ffba)) ([DGW-120](https://devolutions.atlassian.net/browse/DGW-120)) 

- _dgw_: support for PFX files ([#583](https://github.com/Devolutions/devolutions-gateway/issues/583)) ([9ab145d7ea](https://github.com/Devolutions/devolutions-gateway/commit/9ab145d7eaf800167d97620f372e67ae58b4dfdb)) ([DGW-121](https://devolutions.atlassian.net/browse/DGW-121)) 

  PFX files may now be specified in the `TlsCertificateFile` option.
  Furthermore, a new optional option is added: `TlsPrivateKeyPassword`.
  This option may be used when the PFX file is encrypted using a passkey.

### Improvements

- _dgw_: [**breaking**] adjust ngrok options ([#575](https://github.com/Devolutions/devolutions-gateway/issues/575)) ([c30de99d5b](https://github.com/Devolutions/devolutions-gateway/commit/c30de99d5b833dc876aca4197482297cb0fc134e)) 

  Some ngrok options are not making much sense for Devolutions Gateway
  and were removed:
  
  - PROXY protocol: we do not handle PROXY protocol in Devolutions Gateway
    and instead make use of Conn::peer_addr to find the original client IP.
  - Basic Authentication: we have our own way to handle the authentication
    using Json Web Tokens.
  - Schemes: only HTTPS should be used when exposing a Devolutions Gateway
    on internet.
  
  The `Authtoken` key was also renamed to `AuthToken` for readability.

### Documentation

- Update README.md + COOKBOOK.md ([#582](https://github.com/Devolutions/devolutions-gateway/issues/582)) ([4da466553e](https://github.com/Devolutions/devolutions-gateway/commit/4da466553e88da296752649646a0f5512d3ba7fd)) 

## 2023.2.4 (2023-10-16)

### Features

- _dgw_: new `VerbosityProfile` option ([#570](https://github.com/Devolutions/devolutions-gateway/issues/570)) ([969c42f7a7](https://github.com/Devolutions/devolutions-gateway/commit/969c42f7a75e66fe9cfd6d77ba365be58c842291)) 

  This adds a stable option to configure log verbosity.

### Improvements

- _dgw_: add support for more X.509 cert PEM labels ([#519](https://github.com/Devolutions/devolutions-gateway/issues/519)) ([67e9a483a2](https://github.com/Devolutions/devolutions-gateway/commit/67e9a483a26a45020da066fbad080f25944b1d82)) 

  Devolutions Gateway will now recognize `X509 CERTIFICATE` and
  `TRUSTED CERTIFICATE` as valid PEM labels for X.509 certificates.

- _dgw_: more trace records for RDP extension ([#518](https://github.com/Devolutions/devolutions-gateway/issues/518)) ([84134481f2](https://github.com/Devolutions/devolutions-gateway/commit/84134481f2c36502d1cfee948eaf0c9d2ca327cd)) 

  This will help when troubleshooting web client issues.

- _dgw_: improve logs quality ([#557](https://github.com/Devolutions/devolutions-gateway/issues/557)) ([fb1ffd07f7](https://github.com/Devolutions/devolutions-gateway/commit/fb1ffd07f7e0e814e61436d5667eb02e389bcfe0)) ([#528](https://github.com/Devolutions/devolutions-gateway/issues/528)) ([433e25382e](https://github.com/Devolutions/devolutions-gateway/commit/433e25382edcd99ea2de9a1a0c4fe099463fc85c)) 

  - Records additional info on running sessions
  - Improves file rotation

### Bug Fixes

- _dgw_: proper timeout for HTTP listeners ([#561](https://github.com/Devolutions/devolutions-gateway/issues/561)) ([90a0725651](https://github.com/Devolutions/devolutions-gateway/commit/90a0725651587cbbf51c8b53d9465f0a2243e2ce)) 

- _dgw_: shutdown streams gracefully after forwarding ([#562](https://github.com/Devolutions/devolutions-gateway/issues/562)) ([6902137ad8](https://github.com/Devolutions/devolutions-gateway/commit/6902137ad80bdfaa11718829d570125f53985128)) 

### Build

- Update Rust toolchain to 1.73.0 ([#560](https://github.com/Devolutions/devolutions-gateway/issues/560)) ([375ec71cf9](https://github.com/Devolutions/devolutions-gateway/commit/375ec71cf91fdf1b996f74b17dfbd2ace42b53e0)) 

## 2023.2.3 (2023-08-15)

### Bug Fixes

- _dgw_: error 500 when recording folder is missing ([#502](https://github.com/Devolutions/devolutions-gateway/issues/502)) ([3b1992e647](https://github.com/Devolutions/devolutions-gateway/commit/3b1992e647bc2b3b17fc328df091956766f8fdfe)) ([DGW-99](https://devolutions.atlassian.net/browse/DGW-99)) 

  When listing the recordings, if the recording directory does not exist,
  it means that there is no recording yet (and the folder will be created
  later). However, Devolutions Gateway is attempting to read this folder
  anyway and the HTTP error 500 (Internal Server Error) is returned. This
  patch fixes this by returning an empty list as appropriate.

- _dgw_: typo in TLS forward route ([#510](https://github.com/Devolutions/devolutions-gateway/issues/510)) ([7cea3c055a](https://github.com/Devolutions/devolutions-gateway/commit/7cea3c055ade2a86aaa76ac6fe534d9fe0ecd1a1)) ([DGW-102](https://devolutions.atlassian.net/browse/DGW-102)) 

  The name of the endpoint was wrong, and thus /jet/fwd/tls was
  returning the 404 Not Found status.
  Furthermore, the `with_tls` option was not properly set.

### Documentation

- _dgw_: stabilize `RecordingPath` and `Ngrok` options ([#489](https://github.com/Devolutions/devolutions-gateway/issues/489)) ([013569884e](https://github.com/Devolutions/devolutions-gateway/commit/013569884ef4b86f62331ba725c6b6f5e6574220)) 

## 2023.2.2 (2023-06-27)

### Features

- _pwsh_: initial devolutions gateway updater tool ([#472](https://github.com/Devolutions/devolutions-gateway/issues/472)) ([d1f5e2053f](https://github.com/Devolutions/devolutions-gateway/commit/d1f5e2053fb001d80c569ab8be10c45e71fecfa7)) 

### Improvements

- _dgw_: durations in seconds in ngrok config ([#485](https://github.com/Devolutions/devolutions-gateway/issues/485))

  Previously, a Duration was deserialized from a string
  using the `humantime_serde` crate. With this patch, the duration
  is specified in seconds using an integer.

  In other words, this code:
  ```rust
  #[serde(default, skip_serializing_if = "Option::is_none", with = "humantime_serde")]
  pub heartbeat_interval: Option<Duration>,
  ```

  Is changed into this:
  ```rust
  #[serde(skip_serializing_if = "Option::is_none")]
  pub heartbeat_interval: Option<u64>,
  ```

- _dgw_: make Ngrok listeners appear in configuration diagnostic ([#485](https://github.com/Devolutions/devolutions-gateway/issues/485))

### Bug Fixes

- _dgw_: truncated payload after PCB reading ([#483](https://github.com/Devolutions/devolutions-gateway/issues/483)) ([875967f15b](https://github.com/Devolutions/devolutions-gateway/commit/875967f15bb3577e3ce211def9f8d42df3776b0e)) ([DGW-97](https://devolutions.atlassian.net/browse/DGW-97)) 

  Too many bytes are consumed when PCB string is missing the
  null-terminator.
  
  Indeed, until now the number of bytes to consume was found by computing
  the size of the previously decoded PCB when re-encoded.
  IronRDP will always encode PCB string with a null-terminator (just like
  mstcs client). This is generally correct, but will cause payload
  truncation when the received PCB string did not originally contain
  the null-terminator.
  
  This patch is changing this. The "cursor API" is used instead, and
  cursor position after reading the PCB can be used to find the number of
  bytes actually read (even if re-encoding the PDU would give a different
  result).

## 2023.2.1 (2023-06-09)

### Improvements

- _jetsocat_: JETSOCAT_LOG instead of RUST_LOG ([db06a3d32](https://github.com/Devolutions/devolutions-gateway/commit/db06a3d32461d9dc4b386538ba61432492a4f277))

### Bug Fixes

- _jetsocat / dgw_: ignore case for hosts and schemes ([6666623219](https://github.com/Devolutions/devolutions-gateway/commit/6666623219a39117bc46f4128910f12b7e4407cf)) 

  Case is irrelevant when comparing hostnames and schemes.
  Note: using eq_ignore_ascii_case is okay because we don’t
  really expect unicode in such context.

- _dgw_: KDC proxy auth using token in path ([2173ecec4d](https://github.com/Devolutions/devolutions-gateway/commit/2173ecec4d86818c8850559a7b7bf40a47877f26)) ([DGW-94](https://devolutions.atlassian.net/browse/DGW-94))

## 2023.2.0 (2023-05-31)

### Features

- _dgw_: `/jet/jrec` endpoint for session recording ([#404](https://github.com/Devolutions/devolutions-gateway/issues/404)) ([bbc0c41941](https://github.com/Devolutions/devolutions-gateway/commit/bbc0c41941798ae06eed7de26f1f5cee51363d66)) ([DGW-64](https://devolutions.atlassian.net/browse/DGW-64)) ([#408](https://github.com/Devolutions/devolutions-gateway/issues/408)) ([51355a1ac4](https://github.com/Devolutions/devolutions-gateway/commit/51355a1ac4bac02775aa7e4f7080c09991958978)) ([#410](https://github.com/Devolutions/devolutions-gateway/issues/410)) ([8a28a44d5d](https://github.com/Devolutions/devolutions-gateway/commit/8a28a44d5d3955f5212542a6185b695dc5090300)) ([#417](https://github.com/Devolutions/devolutions-gateway/issues/417)) ([56578f8785](https://github.com/Devolutions/devolutions-gateway/commit/56578f87850d1df26cd839b428ced0c41ff3b902)) ([1816b9586f](https://github.com/Devolutions/devolutions-gateway/commit/1816b9586f71076aea182703d78b177bebd273dd))

  Adds new JREC token type for session recording.
  Adds new `jet_rft` (recording file type) private claim.
  Handles `/jet/jrec` route for WSS to file streaming.

- _dgw_: `/jet/heartbeat` endpoint ([#406](https://github.com/Devolutions/devolutions-gateway/issues/406)) ([605d3871de](https://github.com/Devolutions/devolutions-gateway/commit/605d3871de7a744a8fa2449479e50b12841828e8)) 

  The `/jet/heartbeat` endpoint requires a scope token for the
  "gateway.heartbeat.read" scope. It is very similar to `/jet/health`, but
  returns additional information that should not be publicly available
  such as the current number of running sessions.

- _dgw_: `/jet/jrec/list` endpoint ([#412](https://github.com/Devolutions/devolutions-gateway/issues/412)) ([332c86fc5e](https://github.com/Devolutions/devolutions-gateway/commit/332c86fc5effefab1718d10a3cfe6bb52aba178a)) 

- _dgw_: `/jet/jrec/pull/{id}/{filename}` endpoint ([#416](https://github.com/Devolutions/devolutions-gateway/issues/416)) ([8187f8bb2e](https://github.com/Devolutions/devolutions-gateway/commit/8187f8bb2ee9af4ba3c6c216a1bd71a863faf028)) ([#431](https://github.com/Devolutions/devolutions-gateway/issues/431)) ([66dc4e3009](https://github.com/Devolutions/devolutions-gateway/commit/66dc4e3009e8355faf6bf61aee364c7df73a9b7a))

  Recording files can be fetched using this new endpoint and a
  JREC token with the `jet_rop` operation set to `pull`.

- _dgw_: ngrok tunnel support ([711164010a](https://github.com/Devolutions/devolutions-gateway/commit/711164010a6660f2946efb99a24ccb1a4cd47ba1)) ([9e29a1d3ce](https://github.com/Devolutions/devolutions-gateway/commit/9e29a1d3cea8182ca0343a45fed0a5e6d5d93196))

- _dgw_: add ldap, ldaps application protocols ([#432](https://github.com/Devolutions/devolutions-gateway/issues/432)) ([bdb34ef27e](https://github.com/Devolutions/devolutions-gateway/commit/bdb34ef27ed39253a3893c1d07852b67f02b8b3b)) 

- _dgw_: add known application protocol "tunnel" ([c3142870f2](https://github.com/Devolutions/devolutions-gateway/commit/c3142870f2ec4ab3bfced9fab3f6cee7c6869bab)) ([ARC-142](https://devolutions.atlassian.net/browse/ARC-142)) 

  This is known as Devolutions Gateway Tunnel on RDM side.

### Improvements

- _dgw_: [**breaking**] move `jet/{tcp,tls}` endpoints under `/jet/fwd` (#407)

  That is:

  - `/jet/tcp` → `/jet/fwd/tcp`
  - `/jet/tls` → `/jet/fwd/tls`

  This is a breaking change, but these routes were not yet used by any other Devolutions product
  until `2023.2.x` releases, so it is safe to change this at this point.

- _jetsocat_: default port in WebSocket URLs ([#413](https://github.com/Devolutions/devolutions-gateway/issues/413)) ([354e097d4e](https://github.com/Devolutions/devolutions-gateway/commit/354e097d4e0085f151b6228a458841a012c55b3c)) 

  With this change, port may be omitted from the WebSocket URL.
  In such case, the default port will be used (either 80 or 443).

- _dgw_: log version on start ([#414](https://github.com/Devolutions/devolutions-gateway/issues/414)) ([7391114a4d](https://github.com/Devolutions/devolutions-gateway/commit/7391114a4dd1d8b654a290df5d4a9f3f03c00c77)) 

  Useful when troubleshooting issues using user’s logs.

- _dgw_: improve HTTP error reporting ([#415](https://github.com/Devolutions/devolutions-gateway/issues/415)) ([ad19a2fa7c](https://github.com/Devolutions/devolutions-gateway/commit/ad19a2fa7cba97a1d4187c003907aa339ea3b5cb)) 

- _pwsh_: use .NET 6 RSA APIs when available ([#435](https://github.com/Devolutions/devolutions-gateway/issues/435)) ([974d8ee1da](https://github.com/Devolutions/devolutions-gateway/commit/974d8ee1da05014e8304835db3fce8df77c98fe1)) 

  Use .NET 6 RSA public/private key APIs when available.

- _dgw_: graceful shutdown ([ef1d12d468](https://github.com/Devolutions/devolutions-gateway/commit/ef1d12d4680107bc7e055234b45d4f7a6e73c096)) 

- _dgw_: do not enforce scheme in `/jet/fwd` routes ([#430](https://github.com/Devolutions/devolutions-gateway/issues/430)) ([54e467f803](https://github.com/Devolutions/devolutions-gateway/commit/54e467f803d94d348aa8b17f6ed6a7ad4a8694ba)) 

  This was inconsistent with other routes such as `/jet/jmux` where
  `dst_hst` will have the `http` or `https` scheme, but this is
  simply used as a filter policy and Devolutions Gateway will not
  wrap the stream further into an "`https` protocol layer".
  
  Instead, we rely on the requested URI to choose between plain TCP
  and TLS wrapping at proxy level (i.e.: `/jet/fwd/tcp` vs `/jet/fwd/tls`).

### Performance

- _dgw_: re-use TLS client config ([#433](https://github.com/Devolutions/devolutions-gateway/issues/433)) ([b6ebb01aad](https://github.com/Devolutions/devolutions-gateway/commit/b6ebb01aadb398de1ca815d1adee140d4bca3521)) 

  As of rustls 0.21, it’s possible to disable the TLS resumption that is
  not supported by some services such as CredSSP.
  
  This allow us to reuse the same TLS client config and connector for
  all proxy-based TLS connections.
  (TlsConnector is just a wrapper around the config providing the
  `connect` method.)
  
  > Making one of these can be expensive, and should be once per process
  > rather than once per connection.
  
  [source](https://docs.rs/rustls/0.21.1/rustls/client/struct.ClientConfig.html)

### Bug Fixes

- _jetsocat_: gracefully handle invalid native root certificates

  In `tokio-tungstenite` crate, the `rustls::RootCertStore::add` method was used
  to add all the root certificates found by `rustls_native_certs` crate.
  This is a problem when an ancient or invalid certificate is present
  in the native root store. `rustls` documentation says the following:

  > This is suitable for a small set of root certificates that
  > are expected to parse successfully. For large collections of
  > roots (for example from a system store) it is expected that
  > some of them might not be valid according to the rules `rustls`
  > implements. As long as a relatively limited number of certificates
  > are affected, this should not be a cause for concern. Use
  > `RootCertStore::add_parsable_certificates` in order to add as many
  > valid roots as possible and to understand how many certificates have
  > been diagnosed as malformed.

  It has been updated to use `RootCertStore::add_parsable_certificates`
  instead for maximal compability with system store.

  > Parse the given DER-encoded certificates and add all that can be
  > parsed in a best-effort fashion.
  >
  > This is because large collections of root certificates often include
  > ancient or syntactically invalid certificates.

## 2023.1.3 (2023-03-16)

### Bug Fixes

- _installer_: fix command execution and add validation ([#401](https://github.com/Devolutions/devolutions-gateway/issues/401)) ([456f802962](https://github.com/Devolutions/devolutions-gateway/commit/456f802962a6ce1279e45f2e119eb1fa335edf40)) ([DGW-84](https://devolutions.atlassian.net/browse/DGW-84))

### Features

- _dgw_: WebSocket-TCP endpoint (/jet/tcp) ([#399](https://github.com/Devolutions/devolutions-gateway/issues/399)) ([265f0dbe3f](https://github.com/Devolutions/devolutions-gateway/commit/265f0dbe3f20132a214d68c790aecd525a3828f2)) ([DGW-82](https://devolutions.atlassian.net/browse/DGW-82)) 

- _dgw_: WebSocket-TLS endpoint (/jet/tls) ([#400](https://github.com/Devolutions/devolutions-gateway/issues/400)) ([46368f6d43](https://github.com/Devolutions/devolutions-gateway/commit/46368f6d43bd83177a8f983229e6a17eb6684c53)) ([DGW-83](https://devolutions.atlassian.net/browse/DGW-83)) 

## 2023.1.2 (2023-03-13)

### Improvements

- _dgw_: size-based log rotation ([#393](https://github.com/Devolutions/devolutions-gateway/issues/393)) ([e3acafcfcd](https://github.com/Devolutions/devolutions-gateway/commit/e3acafcfcd323af09b3b596c7d3cf1785db5d6d5)) ([DGW-34](https://devolutions.atlassian.net/browse/DGW-34)) 

  Set a maximum size of 3 MB for each file and a maximum of 10 log files.
  With this change, Devolutions Gateway should never consume more than 30 MB for its logs.

- _pwsh_: sort certification chain from leaf to root ([#394](https://github.com/Devolutions/devolutions-gateway/issues/394)) ([f7ff93c6df](https://github.com/Devolutions/devolutions-gateway/commit/f7ff93c6dfeccf34792eab5e5af3db0dce70330b)) ([DGW-80](https://devolutions.atlassian.net/browse/DGW-80)) 

- _installer_: improved error handling in Windows installer ([#397](https://github.com/Devolutions/devolutions-gateway/issues/397)) ([2766e5fffe](https://github.com/Devolutions/devolutions-gateway/commit/2766e5fffedc6ddf200faedfd90422352c045b8e)) ([DGW-78](https://devolutions.atlassian.net/browse/DGW-78))

  PowerShell configuration commands are now executed as custom actions instead of WixSilentExec.
  Errors are tracked and, if the installer is running with UI, an appropriate error message is shown to the user.

  PowerShell command output is redirected to a temporary file; in the case of an error we provide the user the path to that file.
  A general command execution error will display a string error value. 

  Custom actions are refactored slightly for consistency and readability:
  
  - Internal functions now only return `void`, `BOOL`, or `HRESULT` where possible. Errors are always handled as `HRESULT` and other results (e.g. Win32 error codes, `LSTATUS`, null references) are converted to `HRESULT` and handled with the different WiX macros (e.g. `ExitOnWin32Error`).
  - Consolidate on `WixGetProperty` instead of `MsiGetProperty` and be careful to release the resulting strings (`ReleaseStr`)
  - Consolidate on `nullptr` instead of `NULL`

- _installer_: rollback on error in Windows installer ([#397](https://github.com/Devolutions/devolutions-gateway/issues/397)) ([2766e5fffe](https://github.com/Devolutions/devolutions-gateway/commit/2766e5fffedc6ddf200faedfd90422352c045b8e)) ([DGW-76](https://devolutions.atlassian.net/browse/DGW-76))

  For first time installs, if the installation fails, files that may have been created by the configuration process are cleaned up.

## 2023.1.1 (2023-02-22)

### Improvements

- _dgw_: better TLS leaf certificate public key extracting ([#390](https://github.com/Devolutions/devolutions-gateway/pull/390)) ([a4dec08e23](https://github.com/Devolutions/devolutions-gateway/commit/a4dec08e23354a5f2bff2a31c719d8084a88da82)) 

  Use `x509-cert` crate to extract the public key from the leaf
  TLS certificate. `x509-cert` supports more certificates.

### Build

- Update dependencies ([ef1e889bac](https://github.com/Devolutions/devolutions-gateway/commit/ef1e889bac8b1e19db0e619f9c390b32d48f3afe)) 

- _jetsocat_: set execute permission in binary ([#388](https://github.com/Devolutions/devolutions-gateway/issues/388)) ([e08fd2300c](https://github.com/Devolutions/devolutions-gateway/commit/e08fd2300c7fddf9c1648847b7a26b36cc23f688)) 

## 2023.1.0 (2023-02-14)

### Features

- _dgw_: clean path PDU extension for RDP ([3bc0643818](https://github.com/Devolutions/devolutions-gateway/commit/3bc06438188920983833d6a58088a5598c4fe130)) ([ARC-109](https://devolutions.atlassian.net/browse/ARC-109))

- _installer_: show *.cer when browsing for certificate files ([#383](https://github.com/Devolutions/devolutions-gateway/issues/383)) ([2de4a3880d](https://github.com/Devolutions/devolutions-gateway/commit/2de4a3880dd86660e4d1ddceeb8f2c9baef1669a))

  .cer is another popular extension for certificate files.

- _jetsocat_: file-based pipes ([#385](https://github.com/Devolutions/devolutions-gateway/issues/385)) ([62394d3b48](https://github.com/Devolutions/devolutions-gateway/commit/62394d3b480a5166d81060c82b30dd18c61782ea))

  - `write-file://<PATH>`: write file at the specified location
  - `read-file://<PATH>`: read wile at the specified location

- _dgw_: add service version to health check JSON response ([d9f5472120](https://github.com/Devolutions/devolutions-gateway/commit/d9f5472120b87bcd8e3e1d356a435b0b1061c2cd))

### Bug Fixes

- _jetsocat_: use rustls-native-certs on macOS and Linux ([#382](https://github.com/Devolutions/devolutions-gateway/issues/382)) ([7305ce42be](https://github.com/Devolutions/devolutions-gateway/commit/7305ce42befcc0be6ce36928ad3533310cf36768))

  Let rustls use the platform’s native certificate store.

### Build

- Update Rust toolchain to 1.67.0 ([f581e9bdc7](https://github.com/Devolutions/devolutions-gateway/commit/f581e9bdc7fa91377603443da48d22939661e470))

- _jetsocat_: enable hardened runtime on macOS ([#378](https://github.com/Devolutions/devolutions-gateway/issues/378)) ([84b5c33b47](https://github.com/Devolutions/devolutions-gateway/commit/84b5c33b47a6599fe7a2aaabb6393175fe66906b))

## 2022.3.4 (2023-01-16)

### Bug Fixes

- _pwsh_: nil UUID when creating an empty DGatewayConfig ([#372](https://github.com/Devolutions/devolutions-gateway/issues/372)) ([370ed02947](https://github.com/Devolutions/devolutions-gateway/commit/370ed0294791fb9198e0c078ed984d4aa0fa165b)) ([DGW-73](https://devolutions.atlassian.net/browse/DGW-73))

  Without this patch, the nil UUID is used as the "missing" value instead of $null.

- _installer_: ensure default config on install, properly set access URI host ([a506c871ee](https://github.com/Devolutions/devolutions-gateway/commit/a506c871eeb5f8875fbce3314c80b51695490903)) ([DGW-72](https://devolutions.atlassian.net/browse/DGW-72))

  Ensures a default config is created using the Devolutions Gateway binary before applying "Configure now".

- _installer_: avoid Unicode char literals ([#376](https://github.com/Devolutions/devolutions-gateway/issues/376)) ([8d94f94b81](https://github.com/Devolutions/devolutions-gateway/commit/8d94f94b81a7f01840063d08664460a2e6df4e5c)) ([DGW-74](https://devolutions.atlassian.net/browse/DGW-74))

  Unicode character literals in source files can be problematic, depending on the editor and encoding.
  Instead, avoid the issue by masking the character with an asterisk instead of a Unicode "bullet".

### Build

- Update Rust toolchain to 1.66 ([561dcbbc46](https://github.com/Devolutions/devolutions-gateway/commit/561dcbbc4609559a42d4d4a96fc251c3f6bc813e)) 

### Documentation

- _pwsh_: fix links in PowerShell module manifest ([#369](https://github.com/Devolutions/devolutions-gateway/issues/369)) ([03e26cbbca](https://github.com/Devolutions/devolutions-gateway/commit/03e26cbbca0972bd64b60f61090e9611241b22b4)) 

### Features

- _dgw_: add Telnet protocol variant ([b89d553095](https://github.com/Devolutions/devolutions-gateway/commit/b89d5530952bb49e052f616ef0a7a96b97e74ae8)) ([DGW-70](https://devolutions.atlassian.net/browse/DGW-70))

  This change is making possible to omit the port in the target host
  field. The Telnet default port will be inferred as appropriate.

## 2022.3.3 (2022-12-12)

### Improvements

- _dgw_: set default TCP port to 8181 ([#364](https://github.com/Devolutions/devolutions-gateway/issues/364)) ([9df3a0e6d0](https://github.com/Devolutions/devolutions-gateway/commit/9df3a0e6d0b675043b1d4fcd46848701d03e27c1)) ([DGW-66](https://devolutions.atlassian.net/browse/DGW-66))

- Normalize file extensions ([#367](https://github.com/Devolutions/devolutions-gateway/issues/367)) ([5d26d7338f](https://github.com/Devolutions/devolutions-gateway/commit/5d26d7338fad9bbb5acfb6f267f7ae6a1051ca42)) ([DGW-67](https://devolutions.atlassian.net/browse/DGW-67))

  By convention:

  - .pem -> public key
  - .key -> private key
  - .crt -> certificate

  Note that this is merely a convention, not a standard, and file openers
  should be able to select a .key file when choosing a public key (through
  the drop-down menu typically)

- _installer_: start the Gateway service at install time ([#363](https://github.com/Devolutions/devolutions-gateway/issues/363)) ([b07ccd4ed9](https://github.com/Devolutions/devolutions-gateway/commit/b07ccd4ed9b9beabeb3fcac803705cc4d74837fe))

### Bug Fixes

- _dgw_: Accept header parsing in health route ([#366](https://github.com/Devolutions/devolutions-gateway/issues/366)) ([136cfb040b](https://github.com/Devolutions/devolutions-gateway/commit/136cfb040b72ae09a26e9bc470a4767222154cbf)) ([DGW-68](https://devolutions.atlassian.net/browse/DGW-68))

## 2022.3.2 (2022-11-25)

### Improvements

- _installer_: install service as "Local Service" again (fewer permissions) ([#353](https://github.com/Devolutions/devolutions-gateway/pull/353), [#354](https://github.com/Devolutions/devolutions-gateway/pull/354))
- _jetsocat_: automatically clean old log files ([#346](https://github.com/Devolutions/devolutions-gateway/pull/346)) ([d0325307e7](https://github.com/Devolutions/devolutions-gateway/commit/d0325307e7c5c8d38b05ebf5218729e0d21795a2))
- _dgw_: IPv6 support ([#350](https://github.com/Devolutions/devolutions-gateway/pull/350)) ([d591085a69](https://github.com/Devolutions/devolutions-gateway/commit/d591085a6974f1a9c59bf66a094a09cd3d4d9f3e))
- _dgw_: support for full TLS certificate chain ([#359](https://github.com/Devolutions/devolutions-gateway/pull/359)) ([ee1f560fd5](https://github.com/Devolutions/devolutions-gateway/commit/ee1f560fd534fd19d5704da96f0138be0247abc8))

### Features

- _installer_: enable configuration of Devolutions Gateway via installer UI on Windows ([#348](https://github.com/Devolutions/devolutions-gateway/pull/348)) ([6392ed9f86](https://github.com/Devolutions/devolutions-gateway/commit/6392ed9f860e3df80adca1709bf8fda2b43d6035))

### Build

- _dgw_: disable sogar ([#355](https://github.com/Devolutions/devolutions-gateway/pull/355)) ([90d57ac4d9](https://github.com/Devolutions/devolutions-gateway/commit/90d57ac4d9d108f7196609e34d7802ecd7e8160f))

## 2022.3.1 (2022-10-03)

### Improvements

- _dgw_: improve CLI output ([#338](https://github.com/Devolutions/devolutions-gateway/pull/338)) ([d7bd9dc67c](https://github.com/Devolutions/devolutions-gateway/commit/d7bd9dc67c25dc7b67d1f10d8ce77290ec32186a))

### Features

- _dgw_: extend subkey capabilities to KDC tokens ([#334](https://github.com/Devolutions/devolutions-gateway/pull/334)) ([cdc53d0e98](https://github.com/Devolutions/devolutions-gateway/commit/cdc53d0e989b091800f02489d2ce4d5ce9763ac1))

  With this change, a subkey is allowed to sign a short-lived KDC token.

## 2022.3.0 (2022-09-21)

### Bug Fixes

- _dgw_: revert `service as "Local Service"` ([c4f8d24d5d](https://github.com/Devolutions/devolutions-gateway/commit/c4f8d24d5d3599ce7cfa73d0c3169b65296b65f7)) 

- _dgw_: Content-Type header present twice for Json responses ([#315](https://github.com/Devolutions/devolutions-gateway/pull/315)) ([c0976d85f3](https://github.com/Devolutions/devolutions-gateway/commit/c0976d85f3e0bc344cc2c7e3f97d527b343493ac)) 

  Indeed, `Content-Type` is a "singleton field": a single member is anticipated as the field value.
  
  RFC9110 says:
  
  > Although Content-Type is defined as a singleton field,
  > it is sometimes incorrectly generated multiple times,
  > resulting in a combined field value that appears to be a list.
  > Recipients often attempt to handle this error by using
  > the last syntactically valid member of the list, leading to
  > potential interoperability and security issues if different
  > implementations have different error handling behaviors.

- _jmux-proxy_: properly cancel proxy task ([#327](https://github.com/Devolutions/devolutions-gateway/pull/327)) ([f62143eb4a](https://github.com/Devolutions/devolutions-gateway/commit/f62143eb4abeef104477cabfb1380573c5f0cceb)) 

  Previously, JMUX proxy task wasn't properly shut down because tokio
  tasks are detached by default (similar to `std::thread::spawn`). This
  adds a helper wrapper to explicitely specify whether a task should be
  joined or detached.

### Features

- OpenAPI document and auto-generated C# and TypeScript clients

- _dgw_: retrieve KDC token from the path ([f9b66c11f5](https://github.com/Devolutions/devolutions-gateway/commit/f9b66c11f57028a54bbce22be443e07736d6890b)) 

- _dgw_: subkey tokens ([#287](https://github.com/Devolutions/devolutions-gateway/pull/287)) ([bebee0ed59](https://github.com/Devolutions/devolutions-gateway/commit/bebee0ed59cf0d150259f061c95e5d0c47eaa7bf)) 

- _dgw_: support for CORS calls ([#288](https://github.com/Devolutions/devolutions-gateway/pull/288)) ([388b1f6efb](https://github.com/Devolutions/devolutions-gateway/commit/388b1f6efb1f333bf0e7d6af4e6d43445914951c)) 

- _dgw_: expose gateway ID in configuration endpoint ([f15d33a072](https://github.com/Devolutions/devolutions-gateway/commit/f15d33a072cbcf534d56331b18294adf6315ea1d)) 

- _dgw_: add general claim `jet_gw_id` ([#293](https://github.com/Devolutions/devolutions-gateway/pull/293)) ([7a22ea1d0d](https://github.com/Devolutions/devolutions-gateway/commit/7a22ea1d0d2011ca83a4162d569ee78aa25d1dc0)) 

  When this claim is specified, a given token can only be used on a Gateway with the very same ID.

- _dgw_: wildcard scope tokens ([#294](https://github.com/Devolutions/devolutions-gateway/pull/294)) ([1c98c151f9](https://github.com/Devolutions/devolutions-gateway/commit/1c98c151f93179a84873c74eba369bac3827410e)) 

- _dgw_: config pushing endpoint ([8ff1ebed0d](https://github.com/Devolutions/devolutions-gateway/commit/8ff1ebed0dc5c91180eeeba55ec1adf3ff803143)) 

- _dgw_: lossless and simpler config DTO ([ba6830144d](https://github.com/Devolutions/devolutions-gateway/commit/ba6830144dd4f1bf4e1da9a84a0580d13aeb93b8)) 

- _dgw_: subscriber API ([a80282ebd7](https://github.com/Devolutions/devolutions-gateway/commit/a80282ebd71992ee7ee32e90e2943e836c9985ba)) 

- _dgw_: add --config-init-only cli option ([89cd2b775e](https://github.com/Devolutions/devolutions-gateway/commit/89cd2b775e6a39b3b6d8da51ba8f2ea6ac27b720)) 

- _dgw_: limit JMUX wildcard addresses ([#302](https://github.com/Devolutions/devolutions-gateway/pull/302)) ([8a95130e51](https://github.com/Devolutions/devolutions-gateway/commit/8a95130e515d5625d76d1cb699c7b12d402b0266)) 

  The same port must be used.

- _dgw_: `jet/health` endpoint now returns Gateway identity

  The `Accept` HTTP header must be set to `application/json` for this.

- _powershell_: update module ([71e15a4d52](https://github.com/Devolutions/devolutions-gateway/commit/71e15a4d52c876a7ca35fcf8794ded6e4f624eca)) 

  - Deprecate `PrivateKeyFile` and `CertificateFile` in favor of
  `TlsPrivateKeyFile` and `TlsCertificateFile`.  This change is backward
  compatible (older naming are recognized by cmdlets).
  
  - Add `Id`, `Subscriber` and `SubProvisionerPublicKey` to config class.
  
  - Allow `Set-DGatewayConfig` to set `Id`, `Subscriber` and
  `SubProvisionerPublicKey` values.

- _dgw_: forced session termination support ([16c119b025](https://github.com/Devolutions/devolutions-gateway/commit/16c119b025620e5ebd3a9a2e877a9aab8533abba)) 

  This adds the endpoint `POST /jet/session/<id>/terminate`.
  This is similar to what we had back in Wayk Bastion except it’s not P2P.

- _dgw_: maximum session lifetime enforcing ([9b801624fc](https://github.com/Devolutions/devolutions-gateway/commit/9b801624fc4eeaef34da822287f4ee814d9e63e6)) 

  This adds a new claim `jet_ttl` specifying the maximum lifetime for a
  given session. Devolutions Gateway will kill the session if it is still
  running after the deadline.

- _jetsocat_: HTTP proxy listener ([04bd6da206](https://github.com/Devolutions/devolutions-gateway/commit/04bd6da206b71b130f8b535804b94771dcdd5f4f)) 

  HTTP proxy listener now handles both HTTPS (tunneling) proxy requests
  and HTTP (regular forwarding).

### Security

- _dgw_: Smaller token reuse interval for RDP sessions ([832d00b6c1](https://github.com/Devolutions/devolutions-gateway/commit/832d00b6c10680a50faa0e77c2db27a86f798741)) 

  With this change, we do not allow reuse for RDP sessions more than a few
  seconds following the previous use. The interval is 10 seconds which is
  expected to give plenty of time to RDP handshake and negotiations. Once
  this interval is exceeded, we consider the RDP session is fully started
  and the same token can't be reused anymore.
  
  Two reasons why this is beneficial:
  
  - Security wise: the reuse interval is considerably shortened
  - Feature wise: more efficient forced RDP session termination
  
  Regarding the second point: Windows’ mstsc will keep alive the session
  by re-opening it immediately. Because we allow token reuse in a limited
  fashion for RDP, as long as the association token is not expired,
  the terminate action has effectively no visible effect (besides that
  multiple sessions occurred). Reducing the reuse interval greatly
  improves the situation.

## 2022.2.2 (2022-06-14)

- Update dependencies with CVE reports

- *pwsh*: update token generation cmdlet

- *dgw*: remove unused `/jet/sessions/count` route

- *dgw*: lossless unknown application strings

  With this change, unknown application protocols will display session information as well.
  Previously, any unknown value was just treated as the "unknown" string.

## 2022.2.1 (2022-05-30)

- Migrate logging infrastructure to `tracing`

- *dgw*: duplicate `/jmux` and `/KdcProxy` endpoints under `/jet`

- *dgw*: log files are now rotated on a daily basis (old log files are deleted automatically)

- *dgw*: new `LogDirective` config option

- *dgw*: downgrade health route logs to debug level

- *dgw*: JMUX filtering through claims (`*` is used to generate an "allow all" rule)

- *dgw*: optional application protocol claim in JMUX tokens to find good default ports

- *dgw*: PowerShell via SSH application protocol has been renamed from `pwsh` to `ssh-pwsh`

- *dgw*: new known application protocols

  - PowerShell via WinRM (`winrm-http-pwsh`, `winrm-https-pwsh`)
  - VNC (`vnc`)
  - SCP (`scp`)
  - HTTP (`http`)
  - HTTPS (`https`)

- *jetsocat*: process watcher option (`--watch-parent`, `--watch-process`)

- *jetsocat*: pipe timeout option (`--pipe-timeout`)

- *jetsocat*: HTTP(S) tunneling (proxy) listener for JMUX proxy (`http-listen://<BINDING_ADDRESS>`)

## 2022.1.1 (2022-03-09)

- `diagnostics/configuration` endpoint now also returns Gateway's version

- New `diagnostics/clock` endpoint to troubleshoot clock drift

- Initial KDC proxy implementation

- Windows installer (MSI) now installs Gateway service as "Local Service" (fewer permissions)

## 2021.1.7 (2021-12-07)

- JMUX multiplexing protocol implementation for `jetsocat` and gateway server

- Improve various startup validations and diagnostics

- Support for generic plain TCP forwarding (e.g.: raw `SSH` forwarding)

  This requires sending a preconnection PDU containing an appropriate token

- Duplicate root HTTP endpoints under /jet (this help simplifying routing configurations)

- Support for alternative hosts to try in successive order

- Token reuse mitigation based on IP address (RDP protocol requires to connect multiple times
  and previously used token can't just be rejected)

## 2021.1.6 (2021-08-11)

- `jetsocat` now builds for Apple Silicon (aarch64-apple-darwin)

- Update SOGAR and replace sogar-cli with sogar-core

- Authorization improvements (PR#174, PR#175)

- Add an endpoint to retrieve logs (GET /diagnostics/logs)

- Add an endpoint to retrieve configuration (GET /diagnostics/configuration)

- Add an endpoint to list sessions (GET /sessions)

## 2021.1.5 (2021-06-22)

- `jetsocat` tool has been rewritten and CLI overhauled

- SOGAR registry support

  - Recorded sessions can be pushed to a registry
  - Devolutions Gateway itself can be used as a registry

## 2021.1.4 (2021-05-04)

- Add logs to track all HTTP requests received and processed

- Add Linux service registration support in debian package

- Add Install/Uninstall package commands in PowerShell module

## 2021.1.3 (2021-04-13)

- Fix infinite loop issue when the precondition pdu was not completely received

- Fix possible stability issue with protocol peeking

## 2021.1.2 (2021-03-26)

- Fix broken Linux container image (missing executable)

- Add PowerShell module .zip/.nupkg to release artifacts

- Add experimental session recording plugin architecture

## 2021.1.1 (2021-02-19)

- Fix missing internal version number update

## 2021.1.0 (2021-02-19)

- Internal upgrade from futures 0.1 to 0.3

- TCP listener now routes both RDP and JET

- Remove unneeded dummy HTTP listener

## 2020.3.1 (2020-12-03)

- Fix IIS ARR websocket issue (SEC_WEBSOCKET_PROTOCOL header)

- Update Devolutions Gateway to internal version 0.14.0

## 2020.3.0 (2020-10-27)

- Initial PowerShell module public release

- Update Devolutions Gateway to internal version 0.14.0

- Support file to configure the Devolutions-Gateway (gateway.json)

- Update CLI parameters to match parameters defined in file

- WAYK-2211: candidate gathering jet token restriction

## 0.12.0 (2020-08-25)

- Add Jet V3 connection test support

- Add /jet/health route alias for /health (for simplified reverse proxy rules)

## 0.11.0 (2020-05-28)

- Fix websocket connection. Enable HTTP upgrade for the hyper connection.

- Add jet instance name in health response.

## 0.10.9 (2020-05-13)

- Fix websocket listener. An error was returned by the tls acceptor. Ignore those errors.

## 0.10.8 (2020-05-12)

- Don't panic if listeners future returns an error. Just print the error and close the application

## 0.10.7 (2020-05-12)

- Exactly same as 0.10.6 (forced re-deployment)

## 0.10.6 (2020-05-12)

- Exactly same as 0.10.5 (forced re-deployment)

## 0.10.5 (2020-05-11)

- Exactly same as 0.10.4 (forced re-deployment)

## 0.10.4 (2020-05-11)

- Add module name in logs.

- Add curl to Docker container.

## 0.10.3 (2020-05-08)

- Exactly same as 0.10.2 (forced re-deployment)

## 0.10.2 (2020-05-05)

- Remove color from logs

## 0.10.1 (2020-03-26)

- Exactly same as 0.10.0 (workaround to deploy a new version in prod without issue with ACI)

## 0.10.0 (2020-03-23)

- Add provisioner public key

- DVC with GFX integration

- Fixes an issue where some associations were not removed (ghost associations).
