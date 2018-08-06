#include <rain_common.h>

const char title_string[] =
  PACKAGE_STRING
  " " TARGET_ALIAS
  " [SSL (PolarSSL)]"
  " [SSL (OpenSSL)]"
  " [SSL]"
  " [CRYPTO (PolarSSL)]"
  " [CRYPTO (OpenSSL)]"
  " [CRYPTO]"
  " [LZO (STUB)]"
  " [LZO]"
  " [EPOLL]"
  " [TAPDBG]"
  " [PKCS11]"
  " [MH]"
  " [IPv6]"
  " built on " __DATE__
;

static const char usage_message[] =
  "%s\n"
  "\n"
  "General Options:\n"
  "--config file   : Read configuration options from file.\n"
  "--help          : Show options.\n"
  "--version       : Show copyright and version information.\n"
  "\n"
  "Tunnel Options:\n"
  "--core-count n    : worker thread count\n"
  "--mempool-count n    : mempool count\n"
  "--local host    : Local host name or ip address. Implies --bind.\n"
  "--remote host [port] : Remote host name or ip address.\n"
  "--remote-random : If multiple --remote options specified, choose one randomly.\n"
  "--remote-random-hostname : Add a random string to remote DNS name.\n"
  "--mode m        : Major mode, m = 'p2p' (default, point-to-point) or 'server'.\n"
  "--proto p       : Use protocol p for communicating with peer.\n"
  "                  p = udp (default), tcp-server, or tcp-client\n"
  "--proto-force p : only consider protocol p in list of connection profiles.\n"
  "                  p = udp6, tcp6-server, or tcp6-client (ipv6)\n"
  "--connect-retry n : For --proto tcp-client, number of seconds to wait\n"
  "                    between connection retries (default=%d).\n"
  "--connect-timeout n : For --proto tcp-client, connection timeout (in seconds).\n"
  "--connect-retry-max n : Maximum connection attempt retries, default infinite.\n"
#if 0
#ifdef ENABLE_HTTP_PROXY
  "--http-proxy s p [up] [auth] : Connect to remote host\n"
  "                  through an HTTP proxy at address s and port p.\n"
  "                  If proxy authentication is required,\n"
  "                  up is a file containing username/password on 2 lines, or\n"
  "                  'stdin' to prompt from console.  Add auth='ntlm' if\n"
  "                  the proxy requires NTLM authentication.\n"
  "--http-proxy s p 'auto[-nct]' : Like the above directive, but automatically\n"
  "                  determine auth method and query for username/password\n"
  "                  if needed.  auto-nct disables weak proxy auth methods.\n"
  "--http-proxy-retry     : Retry indefinitely on HTTP proxy errors.\n"
  "--http-proxy-timeout n : Proxy timeout in seconds, default=5.\n"
  "--http-proxy-option type [parm] : Set extended HTTP proxy options.\n"
  "                                  Repeat to set multiple options.\n"
  "                  VERSION version (default=1.0)\n"
  "                  AGENT user-agent\n"
#endif
#endif
#if 0
#ifdef ENABLE_SOCKS
  "--socks-proxy s [p] [up] : Connect to remote host through a Socks5 proxy at\n"
  "                  address s and port p (default port = 1080).\n"
  "                  If proxy authentication is required,\n"
  "                  up is a file containing username/password on 2 lines, or\n"
  "                  'stdin' to prompt for console.\n"
  "--socks-proxy-retry : Retry indefinitely on Socks proxy errors.\n"
#endif
#endif
  "--resolv-retry n: If hostname resolve fails for --remote, retry\n"
  "                  resolve for n seconds before failing (disabled by default).\n"
  "                  Set n=\"infinite\" to retry indefinitely.\n"
  "--float         : Allow remote to change its IP address/port, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Run command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "--port port     : TCP/UDP port # for both local and remote.\n"
  "--lport port    : TCP/UDP port # for local (default=%d). Implies --bind.\n"
  "--rport port    : TCP/UDP port # for remote (default=%d).\n"
  "--bind          : Bind to local address and port. (This is the default unless\n"
  "                  --proto tcp-client"
#if 0
#ifdef ENABLE_HTTP_PROXY
                   " or --http-proxy"
#endif
#endif
#if 0
#ifdef ENABLE_SOCKS
                   " or --socks-proxy"
#endif
#endif
                   " is used).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : tun/tap device (X can be omitted for dynamic device.\n"
  "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
  "                  this option only if the tun/tap device used with --dev\n"
  "                  does not begin with \"tun\" or \"tap\".\n"
  "--dev-node node : Explicitly set the device node rather than using\n"
  "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
  "--lladdr hw     : Set the link layer address of the tap device.\n"
  "--topology t    : Set --dev tun topology: 'net30', 'p2p', or 'subnet'.\n"
  "--tun-ipv6      : Build tun link capable of forwarding IPv6 traffic.\n"
  "--iproute cmd   : Use this command instead of default " IPROUTE_PATH ".\n"
  "--ifconfig l rn : TUN: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a remote endpoint.  l & rn should be\n"
  "                  swapped on the other peer.  l & rn must be private\n"
  "                  addresses outside of the subnets used by either peer.\n"
  "                  TAP: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a subnet mask.\n"
  "--ifconfig-ipv6 l r : configure device to use IPv6 address l as local\n"
  "                      endpoint (as a /64) and r as remote endpoint\n"
  "--ifconfig-noexec : Don't actually execute ifconfig/netsh command, instead\n"
  "                    pass --ifconfig parms by environment to scripts.\n"
  "--ifconfig-nowarn : Don't warn if the --ifconfig option on this side of the\n"
  "                    connection doesn't match the remote side.\n"
  "--route network [netmask] [gateway] [metric] :\n"
  "                  Add route to routing table after connection\n"
  "                  is established.  Multiple routes can be specified.\n"
  "                  netmask default: 255.255.255.255\n"
  "                  gateway default: taken from --route-gateway or --ifconfig\n"
  "                  Specify default by leaving blank or setting to \"nil\".\n"
  "--route-ipv6 network/bits [gateway] [metric] :\n"
  "                  Add IPv6 route to routing table after connection\n"
  "                  is established.  Multiple routes can be specified.\n"
  "                  gateway default: taken from --route-ipv6-gateway or --ifconfig\n"
  "--max-routes n :  Specify the maximum number of routes that may be defined\n"
  "                  or pulled from a server.\n"
  "--route-gateway gw|'dhcp' : Specify a default gateway for use with --route.\n"
  "--route-metric m : Specify a default metric for use with --route.\n"
  "--route-delay n [w] : Delay n seconds after connection initiation before\n"
  "                  adding routes (may be 0).  If not specified, routes will\n"
  "                  be added immediately after tun/tap open.  On Windows, wait\n"
  "                  up to w seconds for TUN/TAP adapter to come up.\n"
  "--route-up cmd  : Run command cmd after routes are added.\n"
  "--route-pre-down cmd : Run command cmd before routes are removed.\n"
  "--route-noexec  : Don't add routes automatically.  Instead pass routes to\n"
  "                  --route-up script using environmental variables.\n"
  "--route-nopull  : When used with --client or --pull, accept options pushed\n"
  "                  by server EXCEPT for routes and dhcp options.\n"
  "--allow-pull-fqdn : Allow client to pull DNS names from server for\n"
  "                    --ifconfig, --route, and --route-gateway.\n"
  "--redirect-gateway [flags]: Automatically execute routing\n"
  "                  commands to redirect all outgoing IP traffic through the\n"
  "                  VPN.  Add 'local' flag if both  servers are directly\n"
  "                  connected via a common subnet, such as with WiFi.\n"
  "                  Add 'def1' flag to set default route using using 0.0.0.0/1\n"
  "                  and 128.0.0.0/1 rather than 0.0.0.0/0.  Add 'bypass-dhcp'\n"
  "                  flag to add a direct route to DHCP server, bypassing tunnel.\n"
  "                  Add 'bypass-dns' flag to similarly bypass tunnel for DNS.\n"
  "--redirect-private [flags]: Like --redirect-gateway, but omit actually changing\n"
  "                  the default gateway.  Useful when pushing private subnets.\n"
#if 0
#ifdef ENABLE_CLIENT_NAT
  "--client-nat snat|dnat network netmask alias : on client add 1-to-1 NAT rule.\n"
#endif
#endif
  "--push-peer-info : (client only) push client info to server.\n"
  "--setenv name value : Set a custom environmental variable to pass to script.\n"
  "--setenv FORWARD_COMPATIBLE 1 : Relax config file syntax checking to allow\n"
  "                  directives for future OpenVPN versions to be ignored.\n"
  "--ignore-unkown-option opt1 opt2 ...: Relax config file syntax. Allow\n"
  "                  these options to be ignored when unknown\n"
  "--script-security level: Where level can be:\n"
  "                  0 -- strictly no calling of external programs\n"
  "                  1 -- (default) only call built-ins such as ifconfig\n"
  "                  2 -- allow calling of built-ins and scripts\n"
  "                  3 -- allow password to be passed to scripts via env\n"
  "--shaper n      : Restrict output to peer to n bytes per second.\n"
  "--keepalive n m : Helper option for setting timeouts in server mode.  Send\n"
  "                  ping once every n seconds, restart if ping not received\n"
  "                  for m seconds.\n"
  "--inactive n [bytes] : Exit after n seconds of activity on tun/tap device\n"
  "                  produces a combined in/out byte count < bytes.\n"
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
  "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
  "                  remote address.\n"
  "--ping n        : Ping remote once every n seconds over TCP/UDP port.\n"
#if 0
#if ENABLE_IP_PKTINFO
  "--multihome     : Configure a multi-homed UDP server.\n"
#endif
#endif
  "--fast-io       : (experimental) Optimize TUN/TAP/UDP writes.\n"
  "--remap-usr1 s  : On SIGUSR1 signals, remap signal (s='SIGHUP' or 'SIGTERM').\n"
  "--persist-tun   : Keep tun/tap device open across SIGUSR1 or --ping-restart.\n"
  "--persist-remote-ip : Keep remote IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-local-ip  : Keep local IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-key   : Don't re-read key files across SIGUSR1 or --ping-restart.\n"
#if 0
#if PASSTOS_CAPABILITY
  "--passtos       : TOS passthrough (applies to IPv4 only).\n"
#endif
#endif
  "--tun-mtu n     : Take the tun/tap device MTU to be n and derive the\n"
  "                  TCP/UDP MTU from it (default=%d).\n"
  "--tun-mtu-extra n : Assume that tun/tap device might return as many\n"
  "                  as n bytes more than the tun-mtu size on read\n"
  "                  (default TUN=0 TAP=%d).\n"
  "--link-mtu n    : Take the TCP/UDP device MTU to be n and derive the tun MTU\n"
  "                  from it.\n"
  "--mtu-disc type : Should we do Path MTU discovery on TCP/UDP channel?\n"
  "                  'no'    -- Never send DF (Don't Fragment) frames\n"
  "                  'maybe' -- Use per-route hints\n"
  "                  'yes'   -- Always DF (Don't Fragment)\n"
#if 0
//#ifdef ENABLE_OCC
  "--mtu-test      : Empirically measure and report MTU.\n"
//#endif
#endif
#if 0
#ifdef ENABLE_FRAGMENT
  "--fragment max  : Enable internal datagram fragmentation so that no UDP\n"
  "                  datagrams are sent which are larger than max bytes.\n"
  "                  Adds 4 bytes of overhead per datagram.\n"
#endif
#endif
  "--mssfix [n]    : Set upper bound on TCP MSS, default = tun-mtu size\n"
  "                  or --fragment max value, whichever is lower.\n"
  "--sndbuf size   : Set the TCP/UDP send buffer size.\n"
  "--rcvbuf size   : Set the TCP/UDP receive buffer size.\n"
#if 0
#if defined(TARGET_LINUX) && HAVE_DECL_SO_MARK
  "--mark value    : Mark encrypted packets being sent with value. The mark value\n"
  "                  can be matched in policy routing and packetfilter rules.\n"
#endif
#endif
  "--txqueuelen n  : Set the tun/tap TX queue length to n (Linux only).\n"
#if 0
#ifdef ENABLE_MEMSTATS
  "--memstats file : Write live usage stats to memory mapped binary file.\n"
#endif
#endif
  "--mlock         : Disable Paging -- ensures key material and tunnel\n"
  "                  data will never be written to disk.\n"
  "--up cmd        : Run command cmd after successful tun device open.\n"
  "                  Execute as: cmd tun/tap-dev tun-mtu link-mtu \\\n"
  "                              ifconfig-local-ip ifconfig-remote-ip\n"
  "                  (pre --user or --group UID/GID change)\n"
  "--up-delay      : Delay tun/tap open and possible --up script execution\n"
  "                  until after TCP/UDP connection establishment with peer.\n"
  "--down cmd      : Run command cmd after tun device close.\n"
  "                  (post --user/--group UID/GID change and/or --chroot)\n"
  "                  (command parameters are same as --up option)\n"
  "--down-pre      : Run --down command before TUN/TAP close.\n"
  "--up-restart    : Run up/down commands for all restarts including those\n"
  "                  caused by --ping-restart or SIGUSR1\n"
  "--user user     : Set UID to user after initialization.\n"
  "--group group   : Set GID to group after initialization.\n"
  "--chroot dir    : Chroot to this directory after initialization.\n"
#if 0
#ifdef ENABLE_SELINUX
  "--setcon context: Apply this SELinux context after initialization.\n"
#endif
#endif
  "--cd dir        : Change to this directory before initialization.\n"
  "--daemon [name] : Become a daemon after initialization.\n"
  "                  The optional 'name' parameter will be passed\n"
  "                  as the program name to the system logger.\n"
  "--syslog [name] : Output to syslog, but do not become a daemon.\n"
  "                  See --daemon above for a description of the 'name' parm.\n"
  "--inetd [name] ['wait'|'nowait'] : Run as an inetd or xinetd server.\n"
  "                  See --daemon above for a description of the 'name' parm.\n"
  "--log file      : Output log to file which is created/truncated on open.\n"
  "--log-append file : Append log to file, or create file if nonexistent.\n"
  "--suppress-timestamps : Don't log timestamps to stdout/stderr.\n"
  "--writepid file : Write main process ID to file.\n"
  "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
  "--echo [parms ...] : Echo parameters to log output.\n"
  "--verb n        : Set output verbosity to n (default=%d):\n"
  "                  (Level 3 is recommended if you want a good summary\n"
  "                  of what's happening without being swamped by output).\n"
  "                : 0 -- no output except fatal errors\n"
  "                : 1 -- startup info + connection initiated messages +\n"
  "                       non-fatal encryption & net errors\n"
  "                : 2,3 -- show TLS negotiations & route info\n"
  "                : 4 -- show parameters\n"
  "                : 5 -- show 'RrWw' chars on console for each packet sent\n"
  "                       and received from TCP/UDP (caps) or tun/tap (lc)\n"
  "                : 6 to 11 -- debug messages of increasing verbosity\n"
  "--mute n        : Log at most n consecutive messages in the same category.\n"
  "--status file n : Write operational status to file every n seconds.\n"
  "--status-version [n] : Choose the status file format version number.\n"
  "                  Currently, n can be 1, 2, or 3 (default=1).\n"
#if 1
//#ifdef ENABLE_OCC
  "--disable-occ   : Disable options consistency check between peers.\n"
//#endif
#endif
#if 0
#ifdef ENABLE_DEBUG
  "--gremlin mask  : Special stress testing mode (for debugging only).\n"
#endif
#endif
#if 0
#ifdef ENABLE_LZO
  "--comp-lzo      : Use fast LZO compression -- may add up to 1 byte per\n"
  "                  packet for uncompressible data.\n"
  "--comp-noadapt  : Don't use adaptive compression when --comp-lzo\n"
  "                  is specified.\n"
#endif
#endif
#ifdef ENABLE_MANAGEMENT
  "--management ip port [pass] : Enable a TCP server on ip:port to handle\n"
  "                  management functions.  pass is a password file\n"
  "                  or 'stdin' to prompt from console.\n"
#if UNIX_SOCK_SUPPORT
  "                  To listen on a unix domain socket, specific the pathname\n"
  "                  in place of ip and use 'unix' as the port number.\n"
#endif
  "--management-client : Management interface will connect as a TCP client to\n"
  "                      ip/port rather than listen as a TCP server.\n"
  "--management-query-passwords : Query management channel for private key\n"
  "                  and auth-user-pass passwords.\n"
  "--management-query-proxy : Query management channel for proxy information.\n"
  "--management-query-remote : Query management channel for --remote directive.\n"
  "--management-hold : Start  in a hibernating state, until a client\n"
  "                    of the management interface explicitly starts it.\n"
  "--management-signal : Issue SIGUSR1 when management disconnect event occurs.\n"
  "--management-forget-disconnect : Forget passwords when management disconnect\n"
  "                                 event occurs.\n"
  "--management-up-down : Report tunnel up/down events to management interface.\n"
  "--management-log-cache n : Cache n lines of log file history for usage\n"
  "                  by the management channel.\n"
#if UNIX_SOCK_SUPPORT
  "--management-client-user u  : When management interface is a unix socket, only\n"
  "                              allow connections from user u.\n"
  "--management-client-group g : When management interface is a unix socket, only\n"
  "                              allow connections from group g.\n"
#endif
#ifdef MANAGEMENT_DEF_AUTH
  "--management-client-auth : gives management interface client the responsibility\n"
  "                           to authenticate clients after their client certificate\n"
  "			      has been verified.\n"
#endif
#ifdef MANAGEMENT_PF
  "--management-client-pf : management interface clients must specify a packet\n"
  "                         filter file for each connecting client.\n"
#endif
#endif
#if 0
#ifdef ENABLE_PLUGIN
  "--plugin m [str]: Load plug-in module m passing str as an argument\n"
  "                  to its initialization function.\n"
#endif
#endif
  "\n"
  "Multi-Client Server options (when --mode server is used):\n"
  "--server network netmask : Helper option to easily configure server mode.\n"
  "--server-ipv6 network/bits : Configure IPv6 server mode.\n"
  "--server-bridge [IP netmask pool-start-IP pool-end-IP] : Helper option to\n"
  "                    easily configure ethernet bridging server mode.\n"
  "--push \"option\" : Push a config file option back to the peer for remote\n"
  "                  execution.  Peer must specify --pull in its config file.\n"
  "--push-reset    : Don't inherit global push list for specific\n"
  "                  client instance.\n"
  "--ifconfig-pool start-IP end-IP [netmask] : Set aside a pool of subnets\n"
  "                  to be dynamically allocated to connecting clients.\n"
  "--ifconfig-pool-linear : Use individual addresses rather than /30 subnets\n"
  "                  in tun mode.  Not compatible with Windows clients.\n"
  "--ifconfig-pool-persist file [seconds] : Persist/unpersist ifconfig-pool\n"
  "                  data to file, at seconds intervals (default=600).\n"
  "                  If seconds=0, file will be treated as read-only.\n"
  "--ifconfig-ipv6-pool base-IP/bits : set aside an IPv6 network block\n"
  "                  to be dynamically allocated to connecting clients.\n"
  "--ifconfig-push local remote-netmask : Push an ifconfig option to remote,\n"
  "                  overrides --ifconfig-pool dynamic allocation.\n"
  "                  Only valid in a client-specific config file.\n"
  "--ifconfig-ipv6-push local/bits remote : Push an ifconfig-ipv6 option to\n"
  "                  remote, overrides --ifconfig-ipv6-pool allocation.\n"
  "                  Only valid in a client-specific config file.\n"
  "--iroute network [netmask] : Route subnet to client.\n"
  "--iroute-ipv6 network/bits : Route IPv6 subnet to client.\n"
  "                  Sets up internal routes only.\n"
  "                  Only valid in a client-specific config file.\n"
  "--disable       : Client is disabled.\n"
  "                  Only valid in a client-specific config file.\n"
  "--client-cert-not-required : Don't require client certificate, client\n"
  "                  will authenticate using username/password.\n"
  "--username-as-common-name  : For auth-user-pass authentication, use\n"
  "                  the authenticated username as the common name,\n"
  "                  rather than the common name from the client cert.\n"
  "--auth-user-pass-verify cmd method: Query client for username/password and\n"
  "                  run command cmd to verify.  If method='via-env', pass\n"
  "                  user/pass via environment, if method='via-file', pass\n"
  "                  user/pass via temporary file.\n"
  "--opt-verify    : Clients that connect with options that are incompatible\n"
  "                  with those of the server will be disconnected.\n"
  "--auth-user-pass-optional : Allow connections by clients that don't\n"
  "                  specify a username/password.\n"
  "--no-name-remapping : Allow Common Name and X509 Subject to include\n"
  "                      any printable character.\n"
  "--client-to-client : Internally route client-to-client traffic.\n"
  "--duplicate-cn  : Allow multiple clients with the same common name to\n"
  "                  concurrently connect.\n"
  "--client-connect cmd : Run command cmd on client connection.\n"
  "--client-disconnect cmd : Run command cmd on client disconnection.\n"
  "--client-config-dir dir : Directory for custom client config files.\n"
  "--ccd-exclusive : Refuse connection unless custom client config is found.\n"
  "--tmp-dir dir   : Temporary directory, used for --client-connect return file and plugin communication.\n"
  "--hash-size r v : Set the size of the real address hash table to r and the\n"
  "                  virtual address table to v.\n"
  "--bcast-buffers n : Allocate n broadcast buffers.\n"
  "--tcp-queue-limit n : Maximum number of queued TCP output packets.\n"
  "--tcp-nodelay   : Macro that sets TCP_NODELAY socket flag on the server\n"
  "                  as well as pushes it to connecting clients.\n"
  "--learn-address cmd : Run command cmd to validate client virtual addresses.\n"
  "--connect-freq n s : Allow a maximum of n new connections per s seconds.\n"
  "--max-clients n : Allow a maximum of n simultaneously connected clients.\n"
  "--max-routes-per-client n : Allow a maximum of n internal routes per client.\n"
  "--stale-routes-check n [t] : Remove routes with a last activity timestamp\n"
  "                             older than n seconds. Run this check every t\n"
  "                             seconds (defaults to n).\n"
#if 0
#if PORT_SHARE
  "--port-share host port [dir] : When run in TCP mode, proxy incoming HTTPS\n"
  "                  sessions to a web server at host:port.  dir specifies an\n"
  "                  optional directory to write origin IP:port data.\n"
#endif
#endif
  "\n"
  "Client options (when connecting to a multi-client server):\n"
  "--client         : Helper option to easily configure client mode.\n"
  "--auth-user-pass [up] : Authenticate with server using username/password.\n"
  "                  up is a file containing username/password on 2 lines,\n"
  "                  or omit to prompt from console.\n"
  "--pull           : Accept certain config file options from the peer as if they\n"
  "                  were part of the local config file.  Must be specified\n"
  "                  when connecting to a '--mode server' remote host.\n"
  "--auth-retry t  : How to handle auth failures.  Set t to\n"
  "                  none (default), interact, or nointeract.\n"
  "--static-challenge t e : Enable static challenge/response protocol using\n"
  "                  challenge text t, with e indicating echo flag (0|1)\n"
  "--server-poll-timeout n : when polling possible remote servers to connect to\n"
  "                  in a round-robin fashion, spend no more than n seconds\n"
  "                  waiting for a response before trying the next server.\n"
#if 1
//#ifdef ENABLE_OCC
  "--explicit-exit-notify [n] : On exit/restart, send exit signal to\n"
  "                  server/remote. n = # of retries, default=1.\n"
//#endif
#endif
  "\n"
  "Data Channel Encryption Options (must be compatible between peers):\n"
  "(These options are meaningful for both Static Key & TLS-mode)\n"
  "--secret f [d]  : Enable Static Key encryption mode (non-TLS).\n"
  "                  Use shared secret file f, generate with --genkey.\n"
  "                  The optional d parameter controls key directionality.\n"
  "                  If d is specified, use separate keys for each\n"
  "                  direction, set d=0 on one side of the connection,\n"
  "                  and d=1 on the other side.\n"
  "--auth alg      : Authenticate packets with HMAC using message\n"
  "                  digest algorithm alg (default=%s).\n"
  "                  (usually adds 16 or 20 bytes per packet)\n"
  "                  Set alg=none to disable authentication.\n"
  "--cipher alg    : Encrypt packets with cipher algorithm alg\n"
  "                  (default=%s).\n"
  "                  Set alg=none to disable encryption.\n"
  "--prng alg [nsl] : For PRNG, use digest algorithm alg, and\n"
  "                   nonce_secret_len=nsl.  Set alg=none to disable PRNG.\n"
#if 0
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  "--keysize n     : Size of cipher key in bits (optional).\n"
  "                  If unspecified, defaults to cipher-specific default.\n"
#endif
#endif
#if 0
#ifndef ENABLE_CRYPTO_POLARSSL
  "--engine [name] : Enable OpenSSL hardware crypto engine functionality.\n"
#endif
#endif
  "--no-replay     : Disable replay protection.\n"
  "--mute-replay-warnings : Silence the output of replay warnings to log file.\n"
  "--replay-window n [t]  : Use a replay protection sliding window of size n\n"
  "                         and a time window of t seconds.\n"
  "                         Default n=%d t=%d\n"
  "--no-iv         : Disable cipher IV -- only allowed with CBC mode ciphers.\n"
  "--replay-persist file : Persist replay-protection state across sessions\n"
  "                  using file.\n"
  "--test-crypto   : Run a self-test of crypto features enabled.\n"
  "                  For debugging only.\n"
#if 0
#ifdef ENABLE_PREDICTION_RESISTANCE
  "--use-prediction-resistance: Enable prediction resistance on the random\n"
  "                             number generator.\n"
#endif
#endif
  "\n"
  "TLS Key Negotiation Options:\n"
  "(These options are meaningful only for TLS-mode)\n"
  "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
  "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
  "--key-method m  : Data channel key exchange method.  m should be a method\n"
  "                  number, such as 1 (default), 2, etc.\n"
  "--ca file       : Certificate authority file in .pem format containing\n"
  "                  root certificate.\n"
#if 0
#ifndef ENABLE_CRYPTO_POLARSSL
  "--capath dir    : A directory of trusted certificates (CAs"
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
  " and CRLs).\n"
#else /* OPENSSL_VERSION_NUMBER >= 0x00907000L */
  ").\n"
  "                  WARNING: no support of CRL available with this version.\n"
#endif /* OPENSSL_VERSION_NUMBER >= 0x00907000L */
#endif /* ENABLE_CRYPTO_POLARSSL */
#endif
  "--dh file       : File containing Diffie Hellman parameters\n"
  "                  in .pem format (for --tls-server only).\n"
  "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
  "--cert file     : Local certificate in .pem format -- must be signed\n"
  "                  by a Certificate Authority in --ca file.\n"
  "--extra-certs file : one or more PEM certs that complete the cert chain.\n"
  "--key file      : Local private key in .pem format.\n"
  "--tls-version-min <version> ['or-highest'] : sets the minimum TLS version we\n"
  "    will accept from the peer.  If version is unrecognized and 'or-highest'\n"
  "    is specified, require max TLS version supported by SSL implementation.\n"
#if 0
#ifndef ENABLE_CRYPTO_POLARSSL
  "--pkcs12 file   : PKCS#12 file containing local private key, local certificate\n"
  "                  and optionally the root CA certificate.\n"
#endif
#ifdef ENABLE_X509ALTUSERNAME
  "--x509-username-field : Field used in x509 certificate to be username.\n"
  "                        Default is CN.\n"
#endif
#endif
  "--verify-hash   : Specify SHA1 fingerprint for level-1 cert.\n"
#if 0
#ifdef WIN32
  "--cryptoapicert select-string : Load the certificate and private key from the\n"
  "                  Windows Certificate System Store.\n"
#endif
#endif
  "--tls-cipher l  : A list l of allowable TLS ciphers separated by : (optional).\n"
  "                : Use --show-tls to see a list of supported TLS ciphers.\n"
  "--tls-timeout n : Packet retransmit timeout on TLS control channel\n"
  "                  if no ACK from remote within n seconds (default=%d).\n"
  "--reneg-bytes n : Renegotiate data chan. key after n bytes sent and recvd.\n"
  "--reneg-pkts n  : Renegotiate data chan. key after n packets sent and recvd.\n"
  "--reneg-sec n   : Renegotiate data chan. key after n seconds (default=%d).\n"
  "--hand-window n : Data channel key exchange must finalize within n seconds\n"
  "                  of handshake initiation by any peer (default=%d).\n"
  "--tran-window n : Transition window -- old key can live this many seconds\n"
  "                  after new key renegotiation begins (default=%d).\n"
  "--single-session: Allow only one session (reset state on restart).\n"
  "--tls-exit      : Exit on TLS negotiation failure.\n"
  "--tls-auth f [d]: Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DoS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "                  The optional d parameter controls key directionality,\n"
  "                  see --secret option for more info.\n"
  "--askpass [file]: Get PEM password from controlling tty before we daemonize.\n"
  "--auth-nocache  : Don't cache --askpass or --auth-user-pass passwords.\n"
  "--crl-verify crl ['dir']: Check peer certificate against a CRL.\n"
  "--tls-verify cmd: Run command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth subject')\n"
  "--tls-export-cert [directory] : Get peer cert in PEM format and store it \n"
  "                  in an openvpn temporary file in [directory]. Peer cert is \n"
  "                  stored before tls-verify script execution and deleted after.\n"
  "--verify-x509-name name: Accept connections only from a host with X509 subject\n"
  "                  DN name. The remote host must also pass all other tests\n"
  "                  of verification.\n"
  "--ns-cert-type t: Require that peer certificate was signed with an explicit\n"
  "                  nsCertType designation t = 'client' | 'server'.\n"
#ifdef ENABLE_X509_TRACK
  "--x509-track x  : Save peer X509 attribute x in environment for use by\n"
  "                  plugins and management interface.\n"
#endif
#if 0
#if OPENSSL_VERSION_NUMBER >= 0x00907000L || ENABLE_CRYPTO_POLARSSL
  "--remote-cert-ku v ... : Require that the peer certificate was signed with\n"
  "                  explicit key usage, you can specify more than one value.\n"
  "                  value should be given in hex format.\n"
  "--remote-cert-eku oid : Require that the peer certificate was signed with\n"
  "                  explicit extended key usage. Extended key usage can be encoded\n"
  "                  as an object identifier or OpenSSL string representation.\n"
  "--remote-cert-tls t: Require that peer certificate was signed with explicit\n"
  "                  key usage and extended key usage based on RFC3280 TLS rules.\n"
  "                  t = 'client' | 'server'.\n"
#endif				/* OPENSSL_VERSION_NUMBER || ENABLE_CRYPTO_POLARSSL */
#endif
#ifdef ENABLE_PKCS11
  "\n"
  "PKCS#11 Options:\n"
  "--pkcs11-providers provider ... : PKCS#11 provider to load.\n"
  "--pkcs11-protected-authentication [0|1] ... : Use PKCS#11 protected authentication\n"
  "                              path. Set for each provider.\n"
  "--pkcs11-private-mode hex ...   : PKCS#11 private key mode mask.\n"
  "                              0       : Try  to determind automatically (default).\n"
  "                              1       : Use Sign.\n"
  "                              2       : Use SignRecover.\n"
  "                              4       : Use Decrypt.\n"
  "                              8       : Use Unwrap.\n"
  "--pkcs11-cert-private [0|1] ... : Set if login should be performed before\n"
  "                                  certificate can be accessed. Set for each provider.\n"
  "--pkcs11-pin-cache seconds      : Number of seconds to cache PIN. The default is -1\n"
  "                                  cache until token is removed.\n"
  "--pkcs11-id-management          : Acquire identity from management interface.\n"
  "--pkcs11-id serialized-id 'id'  : Identity to use, get using standalone --show-pkcs11-ids\n"
#endif			/* ENABLE_PKCS11 */
 "\n"
  "SSL Library information:\n"
  "--show-ciphers  : Show cipher algorithms to use with --cipher option.\n"
  "--show-digests  : Show message digest algorithms to use with --auth option.\n"
  "--show-engines  : Show hardware crypto accelerator engines (if available).\n"
  "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
  "\n"
  "Generate a random key (only for non-TLS static key encryption mode):\n"
  "--genkey        : Generate a random key to be used as a shared secret,\n"
  "                  for use with the --secret option.\n"
  "--secret file   : Write key to file.\n"
  "\n"
  "Tun/tap config mode (available with linux 2.4+):\n"
  "--mktun         : Create a persistent tunnel.\n"
  "--rmtun         : Remove a persistent tunnel.\n"
  "--dev tunX|tapX : tun/tap device\n"
  "--dev-type dt   : Device type.  See tunnel options above for details.\n"
  "--user user     : User to set privilege to.\n"
  "--group group   : Group to set privilege to.\n"
#if 0
#ifdef ENABLE_PKCS11
  "\n"
  "PKCS#11 standalone options:\n"
  "--show-pkcs11-ids provider [cert_private] : Show PKCS#11 available ids.\n" 
  "                                            --verb option can be added *BEFORE* this.\n"
#endif
#endif
  "\n"
  "General Standalone Options:\n"
  "--show-gateway : Show info about default gateway.\n"
;

bool connection_list_defined (const struct options *o)
{
	bool ret = true;
	if(o){}
#if 0
	return o->connection_list != NULL;
#endif
	return ret;
}



void init_options (struct options *o,bool debug)
{
	if(debug){}

	o->mode = CLIENT;
	o->topology = TOP_NET30;
	o->ce.proto = PROTO_UDPv4;
	o->ce.connect_retry_seconds = 5;
	o->ce.connect_timeout = 10;
	o->ce.connect_retry_max = 0;
	o->ce.local_port = o->ce.remote_port = OPENVPN_PORT;


	//o->verbosity = 1;
	//o->status_file_update_freq = 60;
	//o->status_file_version = 1;
	o->ce.bind_local = true;
	o->ce.tun_mtu = TUN_MTU_DEFAULT;
	o->ce.link_mtu = LINK_MTU_DEFAULT;
	o->ce.mtu_discover_type = -1;
	o->ce.mssfix = MSSFIX_DEFAULT;


	o->route_delay_window = 30;
	o->max_routes = MAX_ROUTES_DEFAULT;
	o->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
#if 0
	o->proto_force = -1;
	o->occ = true;
#endif

#ifdef ENABLE_MANAGEMENT
	o->management_log_history_cache = 250;
	o->management_echo_buffer_size = 100;
	o->management_state_buffer_size = 100;
#endif

	o->persist_mode = 1;
	o->rcvbuf = 65536;
	o->sndbuf = 65536;
	o->txqueuelen = 100;

	o->real_hash_size = 256;
	o->virtual_hash_size = 256;
	o->n_bcast_buf = 256;
	o->tcp_queue_limit = 64;
	o->max_clients = 1024;
	o->max_routes_per_client = 256;
	o->stale_routes_check_interval = 0;
	o->ifconfig_pool_persist_refresh_freq = 600;
	o->scheduled_exit_interval = 5;
	o->server_poll_timeout = 0;
	o->ciphername = "BF-CBC";
	o->ciphername_defined = true;
	o->authname = "SHA1";
	o->authname_defined = true;
	o->prng_hash = "SHA1";
	o->prng_nonce_secret_len = 16;
#if 1
	o->replay = true;
	o->replay_window = 0;//DEFAULT_SEQ_BACKTRACK;
	o->replay_time = 0;//DEFAULT_TIME_BACKTRACK;
#endif
	o->use_iv = true;
	o->key_direction = KEY_DIRECTION_BIDIRECTIONAL;
	o->use_prediction_resistance = false;
	o->key_method = 2;
	o->tls_timeout = 2;
	o->renegotiate_seconds = 3600;
	o->handshake_window = 60;
	o->transition_window = 3600;
	o->x509_username_field = X509_USERNAME_FIELD_DEFAULT;
	o->pkcs11_pin_cache_period = -1;
	o->core = 1;
	o->mempool_cnt = 2048;
	o->tmp_dir = "/tmp";
}

void uninit_options (struct options *o)
{
	if(o){}
	//free(o);
}

#define SHOW_PARM(name, value, format) printf("  " #name " = " format, (value))
#define SHOW_STR(var)       SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'\n")
#define SHOW_INT(var)       SHOW_PARM(var, o->var, "%d\n")
#define SHOW_UINT(var)      SHOW_PARM(var, o->var, "%u\n")
#define SHOW_UNSIGNED(var)  SHOW_PARM(var, o->var, "0x%08x\n")
#define SHOW_BOOL(var)      SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s\n");

#if 0
void setenv_connection_entry (struct env_set *es, const struct connection_entry *e,const int i)
{
	setenv_str_i (es, "proto", proto2ascii (e->proto, false), i);
	setenv_str_i (es, "local", e->local, i);
	setenv_int_i (es, "local_port", e->local_port, i);
	setenv_str_i (es, "remote", e->remote, i);
	setenv_int_i (es, "remote_port", e->remote_port, i);

#ifdef ENABLE_HTTP_PROXY
	if (e->http_proxy_options)
	{
		setenv_str_i (es, "http_proxy_server", e->http_proxy_options->server, i);
		setenv_int_i (es, "http_proxy_port", e->http_proxy_options->port, i);
	}
#endif
#ifdef ENABLE_SOCKS
	if (e->socks_proxy_server)
	{
		setenv_str_i (es, "socks_proxy_server", e->socks_proxy_server, i);
		setenv_int_i (es, "socks_proxy_port", e->socks_proxy_port, i);
	}
#endif
}
#endif
#if 0
void setenv_settings (struct env_set *es, const struct options *o)
{
	setenv_str (es, "config", o->config);
	setenv_int (es, "verb", o->verbosity);
	setenv_int (es, "daemon", o->daemon);
	setenv_int (es, "daemon_log_redirect", o->log);
	setenv_unsigned (es, "daemon_start_time", time(NULL));
	setenv_int (es, "daemon_pid", getpid());

	if (o->connection_list)
	{
		int i;
		for (i = 0; i < o->connection_list->len; ++i)
			setenv_connection_entry (es, o->connection_list->array[i], i+1);
	}
	else{
		setenv_connection_entry (es, &o->ce, 1);
	}
}
#endif

in_addr_t get_ip_addr(const char *ip_string, bool *error)
{
	unsigned int flags = GETADDR_HOST_ORDER;
	bool succeeded = false;
	in_addr_t ret;
	ret = getaddr (flags, ip_string, 0, &succeeded, NULL);
	if (!succeeded && error){
		*error = true;
	}
	return ret;
}

bool get_ipv6_addr( const char * prefix_str, struct in6_addr *network, unsigned int * netbits, char ** printable_ipv6)
{
	int rc;
	char * sep, * endp;
	int bits;
	struct in6_addr t_network;

	sep = strchr( prefix_str, '/' );
	if ( sep == NULL )
	{
		bits = 64;
	}
	else
	{
		bits = strtol( sep+1, &endp, 10 );
		if ( *endp != '\0' || bits < 0 || bits > 128 )
		{
			MM("## ERR: IPv6 prefix '%s': invalid '/bits' spec ##\n", prefix_str);
			return false;
		}
	}

	if ( sep != NULL ){
		*sep = '\0';
	}

	rc = inet_pton( AF_INET6, prefix_str, &t_network );

	if ( rc == 1 && printable_ipv6 != NULL )
	{
		*printable_ipv6 = malloc(strlen(prefix_str)+1);
	}

	if ( sep != NULL ){
		*sep = '/';
	}

	if ( rc != 1 )
	{
		MM("## ERR: IPv6 prefix '%s': invalid IPv6 address ##\n", prefix_str);
		return false;
	}

	if ( netbits != NULL )
	{
		*netbits = bits;
	}
	if ( network != NULL )
	{
		*network = t_network;
	}
	return true;
}

static bool ipv6_addr_safe_hexplusbits( const char * ipv6_prefix_spec )
{
	struct in6_addr t_addr;
	unsigned int t_bits;

	return get_ipv6_addr(ipv6_prefix_spec, &t_addr, &t_bits, NULL);
}

char * string_substitute (const char *src, int from, int to)
{
	char *ret = NULL;
	char *dest = NULL;
	char c;
	ret = malloc(strlen(src)+1);
	memset(ret,0x00,strlen(src)+1);
	dest = ret;
	do
	{
		c = *src++;
		if (c == from){
			c = to;
		}
		*dest++ = c;
	}
	while (c);
	return ret;
}

uint8_t * parse_hash_fingerprint(const char *str, int nbytes)
{
	int i;
	const char *cp = str;
	uint8_t *ret = NULL;
	char term = 1;
	int byte;
	char bs[3];

	ret = malloc(nbytes);
	memset(ret,0x00,nbytes);

	for (i = 0; i < nbytes; ++i)
	{
		if (strlen(cp) < 2){
			MM("## ERR: format error in hash fingerprint: %s ##\n", str);
		}
		bs[0] = *cp++;
		bs[1] = *cp++;
		bs[2] = 0;
		byte = 0;
		if (sscanf(bs, "%x", &byte) != 1){
			MM("## ERR: format error in hash fingerprint hex byte: %s ##\n", str);
		}
		ret[i] = (uint8_t)byte;
		term = *cp++;
		if (term != ':' && term != 0){
			MM("## ERR: format error in hash fingerprint delimiter: %s ##\n", str);
		}
		if (term == 0){
			break;
		}
	}
	if (term != 0 || i != nbytes-1){
		MM("## ERR: hash fingerprint is different length than expected (%d bytes): %s ##\n", nbytes, str);
	}
	return ret;
}


void show_p2mp_parms (const struct options *o)
{
	char str0[64]={0,};
	print_in_addr_t (o->server_network, 0,str0);
	MM("  server_network = %s \n", str0);
	print_in_addr_t (o->server_netmask, 0,str0);
	MM("  server_netmask = %s \n", str0);
#if 0
	print_in6_addr (o->server_network_ipv6, 0,str0);
	MM("  server_network_ipv6 = %s \n",str0);
	SHOW_INT (server_netbits_ipv6);
#endif
	print_in_addr_t (o->server_bridge_ip, 0,str0);
	MM("  server_bridge_ip = %s \n", str0);
	print_in_addr_t (o->server_bridge_netmask, 0,str0);
	MM("  server_bridge_netmask = %s \n", str0);
	print_in_addr_t (o->server_bridge_pool_start, 0,str0);
	MM("  server_bridge_pool_start = %s \n",str0);
	print_in_addr_t (o->server_bridge_pool_end, 0,str0);
	MM("  server_bridge_pool_end = %s \n", str0);
#if 0
	if (o->push_list.head)
	{
		const struct push_entry *e = o->push_list.head;
		while (e)
		{
			if (e->enable){
				MM("  push_entry = '%s' \n", e->option);
			}
			e = e->next;
		}
	}
#endif
	SHOW_BOOL (ifconfig_pool_defined);
	print_in_addr_t (o->ifconfig_pool_start, 0,str0);
	MM("  ifconfig_pool_start = %s \n",str0);
	print_in_addr_t (o->ifconfig_pool_end, 0,str0);
	MM("  ifconfig_pool_end = %s \n", str0);
	print_in_addr_t (o->ifconfig_pool_netmask, 0,str0);
	MM("  ifconfig_pool_netmask = %s \n", str0);
	SHOW_STR (ifconfig_pool_persist_filename);
	SHOW_INT (ifconfig_pool_persist_refresh_freq);
	SHOW_BOOL (ifconfig_ipv6_pool_defined);
	MM("  ifconfig_ipv6_pool_base = %s \n", print_in6_addr (o->ifconfig_ipv6_pool_base, 0));
	SHOW_INT (ifconfig_ipv6_pool_netbits);
	SHOW_INT (n_bcast_buf);
	SHOW_INT (tcp_queue_limit);
	SHOW_INT (real_hash_size);
	SHOW_INT (virtual_hash_size);
	SHOW_STR (client_connect_script);
	SHOW_STR (learn_address_script);
	SHOW_STR (client_disconnect_script);
	SHOW_STR (client_config_dir);
	SHOW_BOOL (ccd_exclusive);
	SHOW_STR (tmp_dir);
	SHOW_BOOL (push_ifconfig_defined);
	print_in_addr_t (o->push_ifconfig_local, 0,str0);
	MM("  push_ifconfig_local = %s \n", str0);
	print_in_addr_t (o->push_ifconfig_remote_netmask, 0,str0);
	MM("  push_ifconfig_remote_netmask = %s \n", str0);
	SHOW_BOOL (push_ifconfig_ipv6_defined);
	MM("  push_ifconfig_ipv6_local = %s/%d \n", print_in6_addr (o->push_ifconfig_ipv6_local, 0), o->push_ifconfig_ipv6_netbits );
	MM("  push_ifconfig_ipv6_remote = %s \n", print_in6_addr (o->push_ifconfig_ipv6_remote, 0));
	SHOW_BOOL (enable_c2c);
	SHOW_BOOL (duplicate_cn);
	SHOW_INT (cf_max);
	SHOW_INT (cf_per);
	SHOW_INT (max_clients);
	SHOW_INT (max_routes_per_client);
	SHOW_STR (auth_user_pass_verify_script);
	SHOW_BOOL (auth_user_pass_verify_script_via_file);
#if 0
	SHOW_STR (port_share_host);
	SHOW_INT (port_share_port);
#endif
	SHOW_BOOL (client);
	SHOW_BOOL (pull);
	SHOW_STR (auth_user_pass_file);
}

void option_iroute (struct options *o, const char *network_str,const char *netmask_str,struct epoll_ptr_data *epd)
{


#if 1 // 20170105 rainroot remake....
	bool run = true;
	struct user_data ud;
	struct user_data *ret_ud;
	struct user_data *pud;

	in_addr_t network;
	in_addr_t netmask;


	network = getaddr (GETADDR_HOST_ORDER, network_str, 0, NULL, NULL);
	netmask = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, netmask_str, 0, NULL, NULL);

	//network = network & netmask;

	memcpy((char *)&ud.key,&network,4);
	//ud.key = network;
	pthread_mutex_lock(&o->user_tree_mutex);
	ret_ud = (struct user_data *)rb_find(o->user_tree,(void *)&ud);
	pthread_mutex_unlock(&o->user_tree_mutex);

	if(ret_ud != NULL){
		if(((ret_ud->epd != epd) && (ret_ud->thd_mode == THREAD_MODE_NET))){
			pthread_mutex_lock(&o->user_tree_mutex);
			rb_delete(o->user_tree,ret_ud,true,sizeof(struct user_data));
			pthread_mutex_unlock(&o->user_tree_mutex);
			//printf("################ %s %d %s ####\n",__func__,__LINE__,epd->name);
			run = true;
		}else{
			run = false;
		}
	}

	if(run == true){
		pud = malloc(sizeof(struct user_data));
		memset(pud,0x00,sizeof(struct user_data));
		
		memcpy((char*)&pud->key,&network,4);
		memcpy((char*)&pud->netmask,&netmask,4);


		pud->thd_mode = THREAD_MODE_NET;
		pud->epd = epd;
		pthread_mutex_lock(&o->user_tree_mutex);
		rb_insert(o->user_tree,pud);
		pthread_mutex_unlock(&o->user_tree_mutex);

	}
#endif
}

void option_iroute_ipv6 (struct options *o, const char *prefix_str)
{
	struct iroute_ipv6 *ir;

	printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
	ir = malloc(sizeof(struct iroute_ipv6));
	memset(ir,0x00,sizeof(struct iroute_ipv6));

	if ( get_ipv6_addr (prefix_str, &ir->network, &ir->netbits, NULL) < 0 )
	{
		MM("in --iroute-ipv6 %s: Bad IPv6 prefix specification \n",prefix_str);
		free(ir);
		return;
	}else{

		//ir->next = o->iroutes_ipv6;
		o->iroutes_ipv6 = ir;
	}
}

#if 0
void show_http_proxy_options (const struct http_proxy_options *o)
{
	MM("BEGIN http_proxy \n");
	SHOW_STR (server);
	SHOW_INT (port);
	SHOW_STR (auth_method_string);
	SHOW_STR (auth_file);
	SHOW_BOOL (retry);
	SHOW_INT (timeout);
	SHOW_STR (http_version);
	SHOW_STR (user_agent);
	MM("END http_proxy\n");
}
#endif

void options_detach (struct options *o)
{
	o->routes = NULL;
#if 0
	o->client_nat = NULL;
#endif
	clone_push_list(o);
}

void rol_check_alloc (struct options *opt)
{
	if (!opt->routes){
		opt->routes = new_route_option_list (opt->max_routes);
	}
}

void rol6_check_alloc (struct options *opt)
{
	if (!opt->routes_ipv6){
#if 0
		opt->routes_ipv6 = new_route_ipv6_option_list (opt->max_routes);
#endif
	}
}

void cnol_check_alloc (struct options *opt)
{
	if(opt){}
#if 0
	if (!opt->client_nat){
		opt->client_nat = new_client_nat_list ();
	}
#endif
}

void show_connection_entry (const struct connection_entry *o)
{
#if 0
	MM("  proto = %s \n", proto2ascii (o->proto, false));
#endif
	SHOW_STR (local);
	SHOW_INT (local_port);
	SHOW_STR (remote);
	SHOW_INT (remote_port);
	SHOW_BOOL (remote_float);
	SHOW_BOOL (bind_defined);
	SHOW_BOOL (bind_local);
	SHOW_INT (connect_retry_seconds);
	SHOW_INT (connect_timeout);
	SHOW_INT (connect_retry_max);

#if 0
	if (o->http_proxy_options){
		show_http_proxy_options (o->http_proxy_options);
	}
#endif

#if 0
	SHOW_STR (socks_proxy_server);
	SHOW_INT (socks_proxy_port);
	SHOW_BOOL (socks_proxy_retry);
#endif

	SHOW_INT (tun_mtu);
	SHOW_BOOL (tun_mtu_defined);
	SHOW_INT (link_mtu);
	SHOW_BOOL (link_mtu_defined);
	SHOW_INT (tun_mtu_extra);
	SHOW_BOOL (tun_mtu_extra_defined);

	SHOW_INT (mtu_discover_type);

#if 0
	SHOW_INT (fragment);
#endif
	SHOW_INT (mssfix);

#if 0
	SHOW_INT (explicit_exit_notification);
#endif
}


void show_connection_entries (const struct options *o)
{
	if(o){}
#if 0
	printf("Connection profiles [default]:\n");
	show_connection_entry (&o->ce);
	if (o->connection_list)
	{
		const struct connection_list *l = o->connection_list;
		int i;
		for (i = 0; i < l->len; ++i)
		{
			printf( "Connection profiles [%d]: \n", i);
			show_connection_entry (l->array[i]);
		}
	}
	printf("Connection profiles END");
#endif
}


void show_settings (const struct options *o)
{
	printf("Current Parameter Settings: \n");

	SHOW_STR (config);

	SHOW_INT (mode);

	SHOW_BOOL (persist_config);
	SHOW_INT (persist_mode);

	SHOW_BOOL (show_ciphers);
	SHOW_BOOL (show_digests);
	SHOW_BOOL (show_engines);
	SHOW_BOOL (genkey);
	SHOW_STR (key_pass_file);
	SHOW_BOOL (show_tls_ciphers);

	show_connection_entries (o);

	SHOW_BOOL (remote_random);

	SHOW_STR (ipchange);
	SHOW_STR (dev);
	SHOW_STR (dev_type);
	SHOW_STR (dev_node);
	SHOW_STR (lladdr);
	SHOW_INT (topology);
	SHOW_BOOL (tun_ipv6);
	SHOW_STR (ifconfig_local);
	SHOW_STR (ifconfig_remote_netmask);
	SHOW_BOOL (ifconfig_noexec);
	SHOW_BOOL (ifconfig_nowarn);
	SHOW_STR (ifconfig_ipv6_local);
	SHOW_INT (ifconfig_ipv6_netbits);
	SHOW_STR (ifconfig_ipv6_remote);

#if 0
	SHOW_INT (shaper);
	SHOW_INT (mtu_test);
#endif

	SHOW_BOOL (mlock);

	SHOW_INT (keepalive_ping);
	SHOW_INT (keepalive_timeout);
	SHOW_INT (inactivity_timeout);
	SHOW_INT (ping_send_timeout);
	SHOW_INT (ping_rec_timeout);
	SHOW_INT (ping_rec_timeout_action);
	SHOW_BOOL (ping_timer_remote);
	SHOW_INT (remap_sigusr1);
	SHOW_BOOL (persist_tun);
	SHOW_BOOL (persist_local_ip);
	SHOW_BOOL (persist_remote_ip);
	SHOW_BOOL (persist_key);

#if 0
	SHOW_BOOL (passtos);
#endif

	SHOW_INT (resolve_retry_seconds);

	SHOW_STR (username);
	SHOW_STR (groupname);
	SHOW_STR (chroot_dir);
	SHOW_STR (cd_dir);
#if 0
	SHOW_STR (selinux_context);
#endif
	SHOW_STR (writepid);
	SHOW_STR (up_script);
	SHOW_STR (down_script);
	SHOW_BOOL (down_pre);
	SHOW_BOOL (up_restart);
	SHOW_BOOL (up_delay);
	SHOW_BOOL (daemon);
	SHOW_INT (inetd);
	SHOW_BOOL (log);
	SHOW_BOOL (suppress_timestamps);
	SHOW_INT (nice);
	SHOW_INT (verbosity);
	SHOW_INT (mute);

	SHOW_STR (status_file);
	SHOW_INT (status_file_version);
	SHOW_INT (status_file_update_freq);

#if 0
	SHOW_BOOL (occ);
#endif
	SHOW_INT (rcvbuf);
	SHOW_INT (sndbuf);
#if 0
	SHOW_INT (mark);
#endif
	SHOW_INT (sockflags);

	SHOW_BOOL (fast_io);
#if 0
	SHOW_INT (lzo);
#endif
	SHOW_STR (route_script);
	SHOW_STR (route_default_gateway);
	SHOW_INT (route_default_metric);
	SHOW_BOOL (route_noexec);
	SHOW_INT (route_delay);
	SHOW_INT (route_delay_window);
	SHOW_BOOL (route_delay_defined);
	SHOW_BOOL (route_nopull);
	SHOW_BOOL (route_gateway_via_dhcp);
	SHOW_INT (max_routes);
	SHOW_BOOL (allow_pull_fqdn);
#if 0
	if (o->routes){
		print_route_options (o->routes);
	}
#endif
#if 0 
	if (o->client_nat){
		print_client_nat_list(o->client_nat, D_SHOW_PARMS);
	}
#endif
#if 0
	SHOW_STR (management_addr);
	SHOW_INT (management_port);
	SHOW_STR (management_user_pass);
	SHOW_INT (management_log_history_cache);
	SHOW_INT (management_echo_buffer_size);
	SHOW_STR (management_write_peer_info_file);
	SHOW_STR (management_client_user);
	SHOW_STR (management_client_group);
	SHOW_INT (management_flags);
#endif
#if 0
	if (o->plugin_list){
		plugin_option_list_print (o->plugin_list, D_SHOW_PARMS);
	}
#endif

	SHOW_STR (shared_secret_file);
	SHOW_INT (key_direction);
	SHOW_BOOL (ciphername_defined);
	SHOW_STR (ciphername);
	SHOW_BOOL (authname_defined);
	SHOW_STR (authname);
	SHOW_STR (prng_hash);
	SHOW_INT (prng_nonce_secret_len);
	SHOW_INT (keysize);
	SHOW_BOOL (engine);
	SHOW_BOOL (replay);
	SHOW_BOOL (mute_replay_warnings);
	SHOW_INT (replay_window);
	SHOW_INT (replay_time);
	SHOW_STR (packet_id_file);
	SHOW_BOOL (use_iv);
	SHOW_BOOL (test_crypto);
	SHOW_BOOL (use_prediction_resistance);

	SHOW_BOOL (tls_server);
	SHOW_BOOL (tls_client);
	SHOW_INT (key_method);
	SHOW_STR (ca_file);
	SHOW_STR (ca_path);
	SHOW_STR (dh_file);
	SHOW_STR (cert_file);
#if 0
#ifdef MANAGMENT_EXTERNAL_KEY
	if((o->management_flags & MF_EXTERNAL_KEY))
		SHOW_PARM ("priv_key_file","EXTERNAL_PRIVATE_KEY","%s");
	else
#endif
#endif
	SHOW_STR (priv_key_file);
	SHOW_STR (pkcs12_file);
	SHOW_STR (cryptoapi_cert);
	SHOW_STR (cipher_list);
	SHOW_STR (tls_verify);
	SHOW_STR (tls_export_cert);
	SHOW_INT (verify_x509_type);
	SHOW_STR (verify_x509_name);
	SHOW_STR (crl_file);
	SHOW_INT (ns_cert_type);
	{
		int i;
		for (i=0;i<MAX_PARMS;i++){
			SHOW_INT (remote_cert_ku[i]);
		}
	}
	SHOW_STR (remote_cert_eku);
	SHOW_INT (ssl_flags);

	SHOW_INT (tls_timeout);

	SHOW_INT (renegotiate_bytes);
	SHOW_INT (renegotiate_packets);
	SHOW_INT (renegotiate_seconds);

	SHOW_INT (handshake_window);
	SHOW_INT (transition_window);

	SHOW_BOOL (single_session);
	SHOW_BOOL (push_peer_info);
	SHOW_BOOL (tls_exit);

	SHOW_STR (tls_auth_file);

	{
		int i;
		for (i=0;i<MAX_PARMS && o->pkcs11_providers[i] != NULL;i++){
			SHOW_PARM (pkcs11_providers, o->pkcs11_providers[i], "%s\n");
		}
	}
	{
		int i;
		for (i=0;i<MAX_PARMS;i++){
			SHOW_PARM (pkcs11_protected_authentication, o->pkcs11_protected_authentication[i] ? "ENABLED" : "DISABLED", "%s\n");
		}
	}
	{
		int i;
		for (i=0;i<MAX_PARMS;i++){
			SHOW_PARM (pkcs11_private_mode, o->pkcs11_private_mode[i], "%08x\n");
		}
	}
	{
		int i;
		for (i=0;i<MAX_PARMS;i++){
			SHOW_PARM (pkcs11_cert_private, o->pkcs11_cert_private[i] ? "ENABLED" : "DISABLED", "%s\n");
		}
	}
	SHOW_INT (pkcs11_pin_cache_period);
	SHOW_STR (pkcs11_id);
	SHOW_BOOL (pkcs11_id_management);

	show_p2mp_parms (o);

}


#if 0
//#if HTTP_PROXY_OVERRIDE
static struct http_proxy_options * parse_http_proxy_override (const char *server, const char *port,const char *flags)
{
	if (server && port)
	{
		struct http_proxy_options *ho;
		const int int_port = atoi(port);

		if (!legal_ipv4_port (int_port))
		{
			printf(" ## ERR: Bad http-proxy port number: %s \n", port);
			return NULL;
		}

		ho = malloc(sizeof(struct http_proxy_options));
		memset(ho,0x00,sizeof(struct http_proxy_options));

		ho->server = malloc(strlen(server)+1);
		ho->port = int_port;
		ho->retry = true;
		ho->timeout = 5;
		if (flags && !strcmp(flags, "nct")){
			ho->auth_retry = PAR_NCT;
		}else{
			ho->auth_retry = PAR_ALL;
		}
		ho->http_version = "1.0";
		ho->user_agent = "OpenVPN-Autoproxy/1.0";
		return ho;
	}
	else{
		return NULL;
	}
}

void options_postprocess_http_proxy_override (struct options *o)
{
	const struct connection_list *l = o->connection_list;
	if (l)
	{
		int i;
		bool succeed = false;
		for (i = 0; i < l->len; ++i)
		{
			struct connection_entry *ce = l->array[i];
			if (ce->proto == PROTO_TCPv4_CLIENT || ce->proto == PROTO_TCPv4)
			{
				ce->http_proxy_options = o->http_proxy_override;
				succeed = true;
			}
		}
		if (succeed)
		{
			for (i = 0; i < l->len; ++i)
			{
				struct connection_entry *ce = l->array[i];
				if (ce->proto == PROTO_UDPv4)
				{
					ce->flags |= CE_DISABLED;
				}
			}
		}
		else{
			printf("Note: option http-proxy-override ignored because no TCP-based connection profiles are defined");
		}
	}
}

#endif

#if 1
struct connection_list * alloc_connection_list_if_undef (struct options *opt)
{
	if (!opt->connection_list){
	printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
		opt->connection_list = malloc(sizeof(struct connection_list));
		memset(opt->connection_list,0x00,sizeof(struct connection_list));
	}
	return opt->connection_list;
}
#endif

#if 1
struct connection_entry * alloc_connection_entry (struct options *opt)
{
	struct connection_list *l = alloc_connection_list_if_undef (opt);
	struct connection_entry *e = NULL;

	if (l->len >= CONNECTION_LIST_SIZE)
	{
		MM("## ERR: Maximum number of 'connection' options (%d) exceeded ##\n", CONNECTION_LIST_SIZE);
		return NULL;
	}
	e = malloc(sizeof(struct connection_entry));
	memset(e,0x00,sizeof(struct connection_entry));
	l->array[l->len++] = e;
	return e;
}
#endif

#if 0
struct remote_list * alloc_remote_list_if_undef (struct options *opt)
{
	if (!opt->remote_list){
		opt->remote_list = malloc(sizeof(struct remote_list));
		memset(opt->remote_list,0x00,sizeof(struct remote_list));
	}
	return opt->remote_list;
}
#endif

#if 0
struct remote_entry * alloc_remote_entry (struct options *options)
{
	struct remote_list *l = alloc_remote_list_if_undef (options);
	struct remote_entry *e;

	if (l->len >= CONNECTION_LIST_SIZE)
	{
		MM("## ERR: Maximum number of 'remote' options (%d) exceeded ##\n", CONNECTION_LIST_SIZE);
		return NULL;
	}

	e = malloc(sizeof(struct remote_entry));
	memset(e,0x00,sizeof(struct remote_entry));
	l->array[l->len++] = e;
	return e;
}
#endif

#if 1
void connection_entry_load_re (struct connection_entry *ce, const struct remote_entry *re)
{
	if (re->remote){
		ce->remote = re->remote;
	}
	if (re->remote_port >= 0){
		ce->remote_port = re->remote_port;
	}
	if (re->proto >= 0){
		ce->proto = re->proto;
	}
}
#endif

void options_postprocess_verify_ce (const struct options *options, const struct connection_entry *ce)
{
	struct options defaults;
	int dev = DEV_TYPE_UNDEF;
	bool pull = false;

	printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
	init_options (&defaults, true);

	if(options->dev == NULL){
		MM("TUN/TAP device (--dev) \n");
	}

	dev = dev_type_enum (options->dev, options->dev_type);

	if (ce->proto == PROTO_TCPv4){
		MM("--proto tcp is ambiguous in this context.  Please specify --proto tcp-server or --proto tcp-client\n");
	}
	if (ce->proto == PROTO_TCPv6){
		MM("--proto tcp6 is ambiguous in this context.  Please specify --proto tcp6-server or --proto tcp6-client\n");
	}


	if (options->daemon && options->inetd){
		MM("only one of --daemon or --inetd may be specified\n");
	}

	if (options->inetd && (ce->local || ce->remote)){
		MM( "--local or --remote cannot be used with --inetd\n");
	}

	if (options->inetd && ce->proto == PROTO_TCPv4_CLIENT){
		MM("--proto tcp-client cannot be used with --inetd\n");
	}
#if 0
	if (options->inetd == INETD_NOWAIT && ce->proto != PROTO_TCPv4_SERVER){
		MM("--inetd nowait can only be used with --proto tcp-server\n");
	}

	if (options->inetd == INETD_NOWAIT && !(options->tls_server || options->tls_client) ){
		MM("--inetd nowait can only be used in TLS mode\n");
	}

	if (options->inetd == INETD_NOWAIT && dev != DEV_TYPE_TAP){
		MM("--inetd nowait only makes sense in --dev tap mode\n");
	}
#endif

	if (options->lladdr && dev != DEV_TYPE_TAP){
		MM("--lladdr can only be used in --dev tap mode\n");
	}

	if (ce->connect_retry_defined && ce->proto != PROTO_TCPv4_CLIENT  && ce->proto != PROTO_TCPv6_CLIENT){
		MM("--connect-retry doesn't make sense unless also used with --proto tcp-client or tcp6-client \n");
	}

	if (ce->connect_timeout_defined && ce->proto != PROTO_TCPv4_CLIENT && ce->proto != PROTO_TCPv6_CLIENT){
		MM("--connect-timeout doesn't make sense unless also used with --proto tcp-client or tcp6-client\n");
	}

	if (options->ce.tun_mtu_defined && options->ce.link_mtu_defined){
		MM("only one of --tun-mtu or --link-mtu may be defined (note that --ifconfig implies --link-mtu %d)\n", LINK_MTU_DEFAULT);
	}

#if 0
	if (!proto_is_udp(ce->proto) && options->mtu_test){
		MM("--mtu-test only makes sense with --proto udp\n");
	}
#endif

	pull = options->pull;


	if (proto_is_net(ce->proto) && string_defined_equal (ce->local, ce->remote) && ce->local_port == ce->remote_port){
		MM( "--remote and --local addresses are the same \n");
	}

	if (string_defined_equal (ce->remote, options->ifconfig_local) || string_defined_equal (ce->remote, options->ifconfig_remote_netmask)){
		MM("--local and --remote addresses must be distinct from --ifconfig addresses \n");
	}

	if (string_defined_equal (ce->local, options->ifconfig_local) || string_defined_equal (ce->local, options->ifconfig_remote_netmask)){
		MM( "--local addresses must be distinct from --ifconfig addresses \n");
	}

	if (string_defined_equal (options->ifconfig_local, options->ifconfig_remote_netmask)){
		MM("local and remote/netmask --ifconfig addresses must be different\n");
	}

	if (ce->bind_defined && !ce->bind_local){
		MM("--bind and --nobind can't be used together\n");
	}

	if (ce->local && !ce->bind_local){
		MM("--local and --nobind don't make sense when used together\n");
	}

	if (ce->local_port_defined && !ce->bind_local){
		MM("--lport and --nobind don't make sense when used together \n");
	}

	if (!ce->remote && !ce->bind_local){
		MM("--nobind doesn't make sense unless used with --remote \n");
	}

#ifdef ENABLE_MANAGEMENT
	if (!options->management_addr && (options->management_flags|| options->management_write_peer_info_file || options->management_log_history_cache != defaults.management_log_history_cache)){
		MM("--management is not specified, however one or more options which modify the behavior of --management were specified \n");
	}

	if ((options->management_client_user || options->management_client_group) && !(options->management_flags & MF_UNIX_SOCK)){
		MM("--management-client-(user|group) can only be used on unix domain sockets\n");
	}
#endif


#if 0
#ifdef ENABLE_FRAGMENT
	if (!proto_is_udp(ce->proto) && ce->fragment){
		MM("--fragment can only be used with --proto udp \n");
	}
#endif
#endif

#if 1
//#ifdef ENABLE_OCC
	if (!proto_is_udp(ce->proto) && ce->explicit_exit_notification){
		MM( "--explicit-exit-notify can only be used with --proto udp");
	}
//#endif
#endif

	if (!ce->remote && (ce->proto == PROTO_TCPv4_CLIENT  || ce->proto == PROTO_TCPv6_CLIENT)){
		MM("--remote MUST be used in TCP Client mode");
	}

#if 0
#ifdef ENABLE_HTTP_PROXY
	if ((ce->http_proxy_options) && ce->proto != PROTO_TCPv4_CLIENT){
		MM("--http-proxy MUST be used in TCP Client mode (i.e. --proto tcp-client)");
	}
	if ((ce->http_proxy_options) && !ce->http_proxy_options->server){
		MM( "--http-proxy not specified but other http proxy options present");
	}
#endif
#endif

#if 0
#if defined(ENABLE_HTTP_PROXY) && defined(ENABLE_SOCKS)
	if (ce->http_proxy_options && ce->socks_proxy_server){
		MM("--http-proxy can not be used together with --socks-proxy\n");
	}
#endif
#endif

#if 0
#ifdef ENABLE_SOCKS
	if (ce->socks_proxy_server && ce->proto == PROTO_TCPv4_SERVER){
		MM( "--socks-proxy can not be used in TCP Server mode\n");
	}
#endif
#endif

	if ((ce->proto == PROTO_TCPv4_SERVER || ce->proto == PROTO_TCPv6_SERVER) && connection_list_defined (options)){
		MM( "TCP server mode allows at most one --remote address\n");
	}


	if (options->mode == SERVER)
	{
		if (!(dev == DEV_TYPE_TUN || dev == DEV_TYPE_TAP)){
			MM("--mode server only works with --dev tun or --dev tap \n");
		}
		if (options->pull){
			MM("--pull cannot be used with --mode server \n");
		}
		if (!(proto_is_udp(ce->proto) || ce->proto == PROTO_TCPv4_SERVER || ce->proto == PROTO_TCPv6_SERVER)){
			MM("--mode server currently only supports --proto udp or --proto tcp-server or proto tcp6-server\n");
		}
#if 0
		if ((options->port_share_host || options->port_share_port) && (ce->proto != PROTO_TCPv4_SERVER && ce->proto != PROTO_TCPv6_SERVER)){
			MM("--port-share only works in TCP server mode (--proto tcp-server or tcp6-server) \n");
		}
#endif
		if (!options->tls_server){
			MM("--mode server requires --tls-server \n");
		}
		if (ce->remote){
			MM( "--remote cannot be used with --mode server \n");
		}
		if (!ce->bind_local){
			MM("--nobind cannot be used with --mode server \n");
		}
#if 0
#ifdef ENABLE_HTTP_PROXY
		if (ce->http_proxy_options){
			MM( "--http-proxy cannot be used with --mode server");
		}
#endif
#endif
#if 0
#ifdef ENABLE_SOCKS
		if (ce->socks_proxy_server){
			MM("--socks-proxy cannot be used with --mode server");
		}
#endif
#endif

#if 0
		if (options->connection_list){
			MM( "<connection> cannot be used with --mode server \n");
		}
#endif

#if 0
		if (options->tun_ipv6)
			MM("--tun-ipv6 cannot be used with --mode server");
#endif
#if 0
		if (options->shaper){
			MM("--shaper cannot be used with --mode server \n");
		}
		if (options->inetd){
			MM("--inetd cannot be used with --mode server \n");
		}
		if (options->ipchange){
			MM("--ipchange cannot be used with --mode server (use --client-connect instead) \n");
		}
#endif
		if (!(proto_is_dgram(ce->proto) || ce->proto == PROTO_TCPv4_SERVER || ce->proto == PROTO_TCPv6_SERVER)){
			MM("--mode server currently only supports --proto udp or --proto tcp-server or --proto tcp6-server\n");
		}
#if 0
		if (!proto_is_udp(ce->proto) && (options->cf_max || options->cf_per)){
			MM("--connect-freq only works with --mode server --proto udp.  Try --max-clients instead.\n");
		}
#endif
		if (!(dev == DEV_TYPE_TAP || (dev == DEV_TYPE_TUN && options->topology == TOP_SUBNET)) && options->ifconfig_pool_netmask){
			MM("The third parameter to --ifconfig-pool (netmask) is only valid in --dev tap mode. \n");
		}
#if 1
//#ifdef ENABLE_OCC
		if (ce->explicit_exit_notification){
			MM("--explicit-exit-notify cannot be used with --mode server\n");
		}
//#endif
#endif
#if 0
		if (options->routes && (options->routes->flags & RG_ENABLE)){
			MM("--redirect-gateway cannot be used with --mode server (however --push \"redirect-gateway\" is fine) \n");
		}
#endif
		if (options->route_delay_defined){
			MM( "--route-delay cannot be used with --mode server \n");
		}
		if (options->up_delay){
			MM("--up-delay cannot be used with --mode server \n");
		}
		if (!options->ifconfig_pool_defined && options->ifconfig_pool_persist_filename){
			MM("--ifconfig-pool-persist must be used with --ifconfig-pool\n");
		}
		if (options->ifconfig_ipv6_pool_defined && !options->ifconfig_ipv6_local ){
			MM("--ifconfig-ipv6-pool needs --ifconfig-ipv6\n");
		}
		if (options->ifconfig_ipv6_local && !options->tun_ipv6 ){
			MM("Warning: --ifconfig-ipv6 without --tun-ipv6 will not do IPv6\n");
		}

		if (options->auth_user_pass_file){
			MM("--auth-user-pass cannot be used with --mode server (it should be used on the client side only) \n");
		}
		if (options->ccd_exclusive && !options->client_config_dir){
			MM("--ccd-exclusive must be used with --client-config-dir \n");
		}
		if (options->key_method != 2){
			MM("--mode server requires --key-method 2 \n");
		}
		{
			const bool ccnr = (options->auth_user_pass_verify_script || PLUGIN_OPTION_LIST (options)|| MAN_CLIENT_AUTH_ENABLED (options));
			const char *postfix = "must be used with --management-client-auth, an --auth-user-pass-verify script, or plugin \n";
			if ((options->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED) && !ccnr){
				MM("--client-cert-not-required %s \n", postfix);
			}
			if ((options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME) && !ccnr){
				MM("--username-as-common-name %s \n", postfix);
			}
			if ((options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL) && !ccnr){
				MM("--auth-user-pass-optional %s \n", postfix);
			}
		}
	}
	else
	{
		if (options->ifconfig_pool_defined || options->ifconfig_pool_persist_filename){
			MM( "--ifconfig-pool/--ifconfig-pool-persist requires --mode server \n");
		}
		if (options->ifconfig_ipv6_pool_defined){
			MM("--ifconfig-ipv6-pool requires --mode server \n");
		}
		if (options->real_hash_size != defaults.real_hash_size || options->virtual_hash_size != defaults.virtual_hash_size){
			MM("--hash-size requires --mode server \n");
		}
		if (options->learn_address_script){
			MM("--learn-address requires --mode server \n");
		}
		if (options->client_connect_script){
			MM( "--client-connect requires --mode server \n");
		}
		if (options->client_disconnect_script){
			MM("--client-disconnect requires --mode server \n");
		}
		if (options->client_config_dir || options->ccd_exclusive){
			MM("--client-config-dir/--ccd-exclusive requires --mode server \n");
		}
		if (options->enable_c2c){
			MM("--client-to-client requires --mode server \n");
		}
		if (options->duplicate_cn){
			MM("--duplicate-cn requires --mode server \n");
		}
		if (options->cf_max || options->cf_per){
			MM("--connect-freq requires --mode server \n");
		}
		if (options->ssl_flags & SSLF_CLIENT_CERT_NOT_REQUIRED){
			MM("--client-cert-not-required requires --mode server \n");
		}
		if (options->ssl_flags & SSLF_USERNAME_AS_COMMON_NAME){
			MM("--username-as-common-name requires --mode server \n");
		}
		if (options->ssl_flags & SSLF_AUTH_USER_PASS_OPTIONAL){
			MM("--auth-user-pass-optional requires --mode server \n");
		}
		if (options->ssl_flags & SSLF_OPT_VERIFY){
			MM("--opt-verify requires --mode server \n");
		}
		if (options->server_flags & SF_TCP_NODELAY_HELPER){
			MM("--tcp-nodelay requires --mode server \n");
		}
		if (options->auth_user_pass_verify_script){
			MM("--auth-user-pass-verify requires --mode server \n");
		}
#if 0
#if PORT_SHARE
		if (options->port_share_host || options->port_share_port){
			MM("--port-share requires TCP server mode (--mode server --proto tcp-server)\n");
		}
#endif
#endif

		if (options->stale_routes_check_interval){
			MM("--stale-routes-check requires --mode server \n");
		}
#if 0
		if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NO_NAME_REMAPPING)){
			MM("--compat-x509-names no-remapping requires --mode server");
		}
#endif
	}

#if 0
	if ((!proto_is_udp(ce->proto)) && (options->replay_window != defaults.replay_window || options->replay_time != defaults.replay_time)){
		MM("--replay-window only makes sense with --proto udp \n");
	}
#endif

	if ((options->replay != true) && (options->replay_window != defaults.replay_window || options->replay_time != defaults.replay_time)){
		MM("--replay-window doesn't make sense when replay protection is disabled with --no-replay \n");
	}


	if (options->tls_server + options->tls_client +  (options->shared_secret_file != NULL) > 1){
		MM( "specify only one of --tls-server, --tls-client, or --secret\n");
	}

	if (options->tls_server)
	{
		if(options->dh_file == NULL){
			MM("DH file (--dh)");
		}
	}
	if (options->tls_server || options->tls_client)
	{
		if (options->pkcs11_providers[0])
		{
			if(options->ca_file == NULL){
				MM("A file (--ca)");
			}
			if (options->pkcs11_id_management && options->pkcs11_id != NULL){
				MM("Parameter --pkcs11-id cannot be used when --pkcs11-id-management is also specified. \n");
			}
			if (!options->pkcs11_id_management && options->pkcs11_id == NULL){
				MM("Parameter --pkcs11-id or --pkcs11-id-management should be specified.\n");
			}
			if (options->cert_file){
				MM("Parameter --cert cannot be used when --pkcs11-provider is also specified.\n");
			}
			if (options->priv_key_file){
				MM( "Parameter --key cannot be used when --pkcs11-provider is also specified.\n");
			}
#ifdef MANAGMENT_EXTERNAL_KEY
			if (options->management_flags & MF_EXTERNAL_KEY){
				MM( "Parameter --management-external-key cannot be used when --pkcs11-provider is also specified.\n");
			}
#endif
			if (options->pkcs12_file){
				MM("Parameter --pkcs12 cannot be used when --pkcs11-provider is also specified.\n");
			}
			if (options->cryptoapi_cert){
				MM( "Parameter --cryptoapicert cannot be used when --pkcs11-provider is also specified.\n");
			}
		}
		else
#ifdef MANAGMENT_EXTERNAL_KEY
		if((options->management_flags & MF_EXTERNAL_KEY) && options->priv_key_file)
		{
			MM("--key and --management-external-key are mutually exclusive"\n);
		}
		else
#endif
		if (options->cryptoapi_cert)
		{
			if ((!(options->ca_file)) && (!(options->ca_path))){
				MM("You must define CA file (--ca) or CA path (--capath)\n");
			}
			if (options->cert_file){
				MM("Parameter --cert cannot be used when --cryptoapicert is also specified.\n");
			}
			if (options->priv_key_file){
				MM("Parameter --key cannot be used when --cryptoapicert is also specified.\n");
			}
			if (options->pkcs12_file){
				MM( "Parameter --pkcs12 cannot be used when --cryptoapicert is also specified.\n");
			}
#ifdef MANAGMENT_EXTERNAL_KEY
			if (options->management_flags & MF_EXTERNAL_KEY){
				MM("Parameter --management-external-key cannot be used when --cryptoapicert is also specified.\n");
			}
#endif
		}
		else
		if (options->pkcs12_file)
		{
#if 0
#ifdef ENABLE_CRYPTO_POLARSSL
			MM("Parameter --pkcs12 cannot be used with the PolarSSL version version of OpenVPN.\n");
#endif
#endif
			if (options->ca_path){
				MM("Parameter --capath cannot be used when --pkcs12 is also specified.\n");
			}
			if (options->cert_file){
				MM( "Parameter --cert cannot be used when --pkcs12 is also specified.\n");
			}
			if (options->priv_key_file){
				MM("Parameter --key cannot be used when --pkcs12 is also specified.\n");
			}
#ifdef MANAGMENT_EXTERNAL_KEY
			if (options->management_flags & MF_EXTERNAL_KEY){
				MM("Parameter --external-management-key cannot be used when --pkcs12 is also specified.\n");
			}
#endif
		}
		else
		{
#if 0
			if (!(options->ca_file)){
				MM("You must define CA file (--ca)\n");
			}
			if (options->ca_path){
				MM("Parameter --capath cannot be used with the PolarSSL version version of OpenVPN.\n");
			}
#endif
			if ((!(options->ca_file)) && (!(options->ca_path))){
				MM("You must define CA file (--ca) or CA path (--capath)\n");
			}
			if (pull)
			{

				const int sum = (options->cert_file != NULL) +
#if 1
						(options->priv_key_file != NULL);
#else
#ifdef MANAGMENT_EXTERNAL_KEY
				((options->priv_key_file != NULL) || (options->management_flags & MF_EXTERNAL_KEY));
#else
				(options->priv_key_file != NULL);
#endif
#endif


				if (sum == 0)
				{
					if (!options->auth_user_pass_file){
						MM("No client-side authentication method is specified.  You must use either --cert/--key, --pkcs12, or --auth-user-pass\n");
					}
					}
					else if (sum == 2)
						;
					else
					{
						MM("If you use one of --cert or --key, you must use them both\n");
					}
				}
				else
				{
					if(options->cert_file == NULL){
						MM("certificate file (--cert) or PKCS#12 file (--pkcs12)\n");
					}
#ifdef MANAGMENT_EXTERNAL_KEY
					if (!(options->management_flags & MF_EXTERNAL_KEY))
#endif
						if(options->priv_key_file == NULL){
							MM("private key file (--key) or PKCS#12 file (--pkcs12)\n");
						}
				}
			}
	}
	else
	{
#if 0

#define MUST_BE_UNDEF(parm) if (options->parm != defaults.parm) MM(err, #parm);
		const char err[] = "Parameter %s can only be specified in TLS-mode, i.e. where --tls-server or --tls-client is also specified.\n";
		MUST_BE_UNDEF (ca_file);
		MUST_BE_UNDEF (ca_path);
		MUST_BE_UNDEF (dh_file);
		MUST_BE_UNDEF (cert_file);
		MUST_BE_UNDEF (priv_key_file);
		MUST_BE_UNDEF (pkcs12_file);
		MUST_BE_UNDEF (cipher_list);
		MUST_BE_UNDEF (tls_verify);
		MUST_BE_UNDEF (tls_export_cert);
		MUST_BE_UNDEF (verify_x509_name);
		MUST_BE_UNDEF (tls_timeout);
		MUST_BE_UNDEF (renegotiate_bytes);
		MUST_BE_UNDEF (renegotiate_packets);
		MUST_BE_UNDEF (renegotiate_seconds);
		MUST_BE_UNDEF (handshake_window);
		MUST_BE_UNDEF (transition_window);
		MUST_BE_UNDEF (tls_auth_file);
		MUST_BE_UNDEF (single_session);
		MUST_BE_UNDEF (push_peer_info);
		MUST_BE_UNDEF (tls_exit);
		MUST_BE_UNDEF (crl_file);
		MUST_BE_UNDEF (key_method);
		MUST_BE_UNDEF (ns_cert_type);
		MUST_BE_UNDEF (remote_cert_ku[0]);
		MUST_BE_UNDEF (remote_cert_eku);
		MUST_BE_UNDEF (pkcs11_providers[0]);
		MUST_BE_UNDEF (pkcs11_private_mode[0]);
		MUST_BE_UNDEF (pkcs11_id);
		MUST_BE_UNDEF (pkcs11_id_management);

		if (pull){
			MM(err, "--pull");
		}
#endif
	}

	if (options->auth_user_pass_file && !options->pull){
		MM("--auth-user-pass requires --pull\n");
	}
	uninit_options (&defaults);
}

void options_postprocess_mutate_ce (struct options *o, struct connection_entry *ce)
{
	const int dev = dev_type_enum (o->dev, o->dev_type);

	if (o->server_defined || o->server_bridge_defined || o->server_bridge_proxy_dhcp)
	{
		if (ce->proto == PROTO_TCPv4){
			ce->proto = PROTO_TCPv4_SERVER;
		}else if (ce->proto == PROTO_TCPv6){
			ce->proto = PROTO_TCPv6_SERVER;
		}
	}
	if (o->client)
	{
		if (ce->proto == PROTO_TCPv4){
			ce->proto = PROTO_TCPv4_CLIENT;
		}else if (ce->proto == PROTO_TCPv6){
			ce->proto = PROTO_TCPv6_CLIENT;
		}
	}

	if (ce->proto == PROTO_TCPv4_CLIENT && !ce->local && !ce->local_port_defined && !ce->bind_defined){
		ce->bind_local = false;
	}
#if 0
#ifdef ENABLE_SOCKS
	if (ce->proto == PROTO_UDPv4 && ce->socks_proxy_server && !ce->local && !ce->local_port_defined && !ce->bind_defined){
		ce->bind_local = false;
	}
#endif
#endif

	if (!ce->bind_local){
		ce->local_port = 0;
	}

	if (o->proto_force >= 0 && proto_is_tcp(o->proto_force) != proto_is_tcp(ce->proto)){
		ce->flags |= CE_DISABLED;
	}

	if (o->ce.mssfix_default)
	{
#if 1
		MM("--mssfix must specify a parameter\n");
#else
#ifdef ENABLE_FRAGMENT
		if (ce->fragment)
			o->ce.mssfix = ce->fragment;
#else
		MM("--mssfix must specify a parameter");
#endif      
#endif      
	}

	{
		if (!ce->tun_mtu_defined && !ce->link_mtu_defined)
		{
			ce->tun_mtu_defined = true;
		}
		if ((dev == DEV_TYPE_TAP) && !ce->tun_mtu_extra_defined)
		{
			ce->tun_mtu_extra_defined = true;
			ce->tun_mtu_extra = TAP_MTU_EXTRA_DEFAULT;
		}
	}
}

void options_postprocess_mutate_invariant (struct options *options)
{
	if(options){}
#if 0
	const int dev = dev_type_enum (options->dev, options->dev_type);
	if (options->inetd == INETD_NOWAIT){
		options->ifconfig_noexec = true;
	}
#endif
}

void options_postprocess_verify (const struct options *o)
{
	if (o->connection_list)
	{
		int i;
		for (i = 0; i < o->connection_list->len; ++i){
			options_postprocess_verify_ce (o, o->connection_list->array[i]);
		}
	}
	else{
		options_postprocess_verify_ce (o, &o->ce);
	}
}

void options_postprocess_mutate (struct options *o)
{
	printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
	helper_client_server (o);
	helper_keepalive (o);
	helper_tcp_nodelay (o);

	//options_postprocess_mutate_invariant (o);

	if (o->remote_list && !o->connection_list)
	{
		if (o->remote_list->len > 1 || o->force_connection_list)
		{
			const struct remote_list *rl = o->remote_list;
			int i;
			for (i = 0; i < rl->len; ++i)
			{
				const struct remote_entry *re = rl->array[i];
				struct connection_entry ce = o->ce;
				struct connection_entry *ace;

				connection_entry_load_re (&ce, re);
				ace = alloc_connection_entry (o);
				*ace = ce;
			}
		}
		else if (o->remote_list->len == 1) 
		{
			connection_entry_load_re (&o->ce, o->remote_list->array[0]);
		}
		else
		{
			//ASSERT (0);
		}
	}
	if (o->connection_list)
	{
		int i;
		for (i = 0; i < o->connection_list->len; ++i){
			options_postprocess_mutate_ce (o, o->connection_list->array[i]);
		}
#if 0
#if HTTP_PROXY_OVERRIDE
		if (o->http_proxy_override){
			options_postprocess_http_proxy_override(o);
		}
#endif
#endif
	}
	else{
		options_postprocess_mutate_ce (o, &o->ce);  
	}

	pre_pull_save (o);
}

#define CHKACC_FILE (1<<0)
#define CHKACC_DIRPATH (1<<1)
#define CHKACC_FILEXSTWR (1<<2)
#define CHKACC_INLINE (1<<3)
#define CHKACC_ACPTSTDIN (1<<4)

bool check_file_access(const int type, const char *file, const int mode, const char *opt)
{
	int errcode = 0;

	if (!file){
		return false;
	}

	if ((type & CHKACC_INLINE) && streq(file, INLINE_FILE_TAG) ){
		return false;
	}

	if( (type & CHKACC_ACPTSTDIN) && streq(file, "stdin") ){
		return false;
	}

	if (type & CHKACC_DIRPATH)
	{
		char *fullpath = strdup(file);
		char *dirpath = dirname(fullpath);

		if (access (dirpath, mode|X_OK) != 0){
			errcode = errno;
		}
		free(fullpath);
	}

	if (!errcode && (type & CHKACC_FILE) && (access (file, mode) != 0) ){
		errcode = errno;
	}

	if (!errcode && (type & CHKACC_FILEXSTWR) && (access (file, F_OK) == 0) ){
		if (access (file, W_OK) != 0){
			errcode = errno;
		}
	}

	if( errcode > 0 ){
		MM("%s fails with '%s': %s", opt, file, strerror(errno));
	}
	return (errcode != 0 ? true : false);
}

bool check_file_access_chroot(const char *chroot, const int type, const char *file, const int mode, const char *opt)
{
	bool ret = false;

	if (!file){
		return false;
	}

	if(chroot){}
	if(type){}
	if(mode){}
	if(opt){}

#if 0
	if( chroot )
	{
		struct buffer chroot_file;
		int len = 0;

		len = strlen(chroot) + strlen(PATH_SEPARATOR_STR) + strlen(file) + 1;
		chroot_file = alloc_buf_gc(len, &gc);
		buf_printf(&chroot_file, "%s%s%s", chroot, PATH_SEPARATOR_STR, file);
		ASSERT (chroot_file.len > 0);

		ret = check_file_access(type, BSTR(&chroot_file), mode, opt);
	}
	else
#endif
	{
		ret = check_file_access(type, file, mode, opt);
	}
	return ret;
}


bool check_cmd_access(const char *command, const char *opt, const char *chroot)
{
	bool return_code=false;

	if(command){}
	if(opt){}
	if(chroot){}
#if 0
	struct argv argv;

	if (!command){
		return false;
	}

	argv = argv_new ();
	argv_printf (&argv, "%sc", command);

	if (argv.argv[0]){
		return_code = check_file_access_chroot(chroot, CHKACC_FILE, argv.argv[0], X_OK, opt);
	}else{
		printf("%s fails with '%s': No path to executable.", opt, command);
		return_code = true;
	}

	argv_reset (&argv);
#endif
	return return_code;
}

void options_postprocess_filechecks (struct options *options)
{
	bool errs = false;

	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->dh_file, R_OK, "--dh");
	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->ca_file, R_OK, "--ca");
	errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->ca_path, R_OK, "--capath");
	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->cert_file, R_OK, "--cert");
	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->extra_certs_file, R_OK, "--extra-certs");

#ifdef ENABLE_MANAGEMENT
	if(!(options->management_flags & MF_EXTERNAL_KEY)){
		errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->priv_key_file, R_OK, "--key");
	}
#endif

	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->pkcs12_file, R_OK,  "--pkcs12");

	if (options->ssl_flags & SSLF_CRL_VERIFY_DIR){
		errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->crl_file, R_OK|X_OK, "--crl-verify directory");
	}else{
		errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->crl_file, R_OK, "--crl-verify");
	}

	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->tls_auth_file, R_OK,  "--tls-auth");
	errs |= check_file_access (CHKACC_FILE|CHKACC_INLINE, options->shared_secret_file, R_OK, "--secret");
	errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->packet_id_file, R_OK|W_OK, "--replay-persist");


	errs |= check_file_access (CHKACC_FILE, options->key_pass_file, R_OK, "--askpass");

#ifdef ENABLE_MANAGEMENT
	errs |= check_file_access (CHKACC_FILE|CHKACC_ACPTSTDIN, options->management_user_pass, R_OK,"--management user/password file");
#endif /* ENABLE_MANAGEMENT */
	errs |= check_file_access (CHKACC_FILE|CHKACC_ACPTSTDIN, options->auth_user_pass_file, R_OK, "--auth-user-pass");

	errs |= check_file_access (CHKACC_FILE, options->chroot_dir, R_OK|X_OK, "--chroot directory");
	errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->writepid, R_OK|W_OK, "--writepid");

	errs |= check_file_access (CHKACC_DIRPATH|CHKACC_FILEXSTWR, options->status_file,  R_OK|W_OK, "--status");

	errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->tls_export_cert, R_OK|W_OK|X_OK, "--tls-export-cert");

	errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->client_config_dir, R_OK|X_OK, "--client-config-dir");

	errs |= check_file_access_chroot (options->chroot_dir, CHKACC_FILE, options->tmp_dir, R_OK|W_OK|X_OK, "Temporary directory (--tmp-dir)");

	if (errs){
		MM("Please correct these errors.\n");
	}
}

void options_postprocess (struct options *options)
{
	options_postprocess_mutate (options);
	options_postprocess_verify (options);
	options_postprocess_filechecks (options);
}

void pre_pull_save (struct options *o)
{
	if (o->pull == false)
	{
	printf("-------------------------------------------------------------------------- %s %d -----------------------\n",__func__,__LINE__);
		o->pre_pull = malloc(sizeof(struct options_pre_pull));
		memset(o->pre_pull,0x00,sizeof(struct options_pre_pull));
		o->pre_pull->tuntap_options = o->tuntap_options;
		o->pre_pull->tuntap_options_defined = true;
		o->pre_pull->foreign_option_index = o->foreign_option_index;
		if (o->routes)
		{
			o->pre_pull->routes = clone_route_option_list(o->routes);
			o->pre_pull->routes_defined = true;
		}
		if (o->routes_ipv6)
		{
			o->pre_pull->routes_ipv6 = clone_route_ipv6_option_list(o->routes_ipv6);
			o->pre_pull->routes_ipv6_defined = true;
		}
#if 0
#ifdef ENABLE_CLIENT_NAT
		if (o->client_nat)
		{
			o->pre_pull->client_nat = clone_client_nat_option_list(o->client_nat);
			o->pre_pull->client_nat_defined = true;
		}
#endif
#endif
	}
}

void pre_pull_restore (struct options *o)
{
	if(o){}
#if 0
	const struct options_pre_pull *pp = o->pre_pull;
	if (pp)
	{
		if (pp->tuntap_options_defined){
			o->tuntap_options = pp->tuntap_options;
		}

		if (pp->routes_defined)
		{
			rol_check_alloc (o);
			copy_route_option_list (o->routes, pp->routes);
		}
		else{
			o->routes = NULL;
		}

		if (pp->routes_ipv6_defined)
		{
			rol6_check_alloc (o);
			copy_route_ipv6_option_list (o->routes_ipv6, pp->routes_ipv6);
		}
		else{
			o->routes_ipv6 = NULL;
		}
#if 0
#ifdef ENABLE_CLIENT_NAT
		if (pp->client_nat_defined)
		{
			cnol_check_alloc (o);
			copy_client_nat_option_list (o->client_nat, pp->client_nat);
		}
		else{
			o->client_nat = NULL;
		}
#endif
#endif

		o->foreign_option_index = pp->foreign_option_index;
	}

	o->push_continuation = 0;
	o->push_option_types_found = 0;
#endif
}


//#ifdef ENABLE_OCC
//char * options_string (const struct options *o, const struct frame *frame,struct tuntap *tt,bool remote)
char * options_string (struct epoll_ptr_data *epd,bool remote,char *out)
{

	struct main_data *md=NULL;
	md = (struct main_data *)epd->gl_var;

	struct options *o = NULL;
	o = (struct options *)md->opt;

	sprintf(out, "V4");

	sprintf(out, "%s,dev-type %s",out,dev_type_string (o->dev, o->dev_type));
	//sprintf(out, ",link-mtu %d", EXPANDED_SIZE (frame));
	//sprintf(out, ",tun-mtu %d", PAYLOAD_SIZE (frame));
	sprintf(out, "%s,link-mtu 1539",out);
	sprintf(out, "%s,tun-mtu 1532",out);
	sprintf(out, "%s,proto %s",out,proto2ascii (proto_remote (o->ce.proto, remote), true));

	/* send tun_ipv6 only in peer2peer mode - in client/server mode, it
	 * is usually pushed by the server, triggering a non-helpful warning
	 */
	if (o->tun_ipv6 && o->mode == CLIENT && !PULL_DEFINED(o)){
		sprintf (out, "%s,tun-ipv6",out);
	}
#if 0
	/*
	 * Try to get ifconfig parameters into the options string.
	 * If tt is undefined, make a temporary instantiation.
	 */
	if (!tt)
	{
		tt = init_tun (o->dev,
				o->dev_type,
				o->topology,
				o->ifconfig_local,
				o->ifconfig_remote_netmask,
				o->ifconfig_ipv6_local,
				o->ifconfig_ipv6_netbits,
				o->ifconfig_ipv6_remote,
				(in_addr_t)0,
				(in_addr_t)0,
				false,
				NULL);
		if (tt){
			tt_local = true;
		}
	}
#endif

	if (o->mode == CLIENT && !PULL_DEFINED(o))
	{
		const char *ios = ifconfig_options_string (epd,remote);
		if (ios && strlen (ios)){
			sprintf(out,"%s,ifconfig %s",out,ios);
		}
	}
#if 0
	if (tt_local)
	{
		free (tt);
		tt = NULL;
	}
#endif

#if 0
	if (o->lzo & LZO_SELECTED){
		sprintf (out,"%s,comp-lzo",out);
	}
#endif

	if (o->ce.fragment){
		sprintf (out,"%s,mtu-dynamic",out);
	}

	/*
	 * Key direction
	 */
	{
		char *kd = keydirection2ascii (o->key_direction, remote);
		if (kd){
			sprintf (out, "%s,keydir %s",out,kd);
		}
	}

	/*
	 * Crypto Options
	 */
	if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
	{
		struct key_type kt;

		if(!((o->shared_secret_file != NULL) + (TLS_CLIENT == true) + (TLS_SERVER == true) <= 1)){
			MM("## %s %d ##\n",__func__,__LINE__);
		}

		init_key_type (&kt, o->ciphername, o->authname,o->keysize, true);

		if(o->ciphername_defined == false){
			sprintf (out, "%s,cipher %s",out,cipher_kt_name (NULL));
		}else{
			sprintf (out, "%s,cipher %s",out,cipher_kt_name (kt.cipher));
		}
		if(o->authname_defined == false){
			sprintf (out, "%s,auth %s",out,(char *)md_kt_name (NULL));
		}else{
			sprintf (out, "%s,auth %s",out,(char *)md_kt_name (kt.digest));
		}
		sprintf (out, "%s,keysize %d",out,kt.cipher_length * 8);
		if (o->shared_secret_file){
			sprintf (out, "%s,secret",out);
		}
		if (!o->replay){
			sprintf (out,"%s,no-replay",out);
		}
		if (!o->use_iv){
			sprintf (out,"%s,no-iv",out);
		}

		//#ifdef ENABLE_PREDICTION_RESISTANCE
		if (o->use_prediction_resistance){
			sprintf (out,"%s,use-prediction-resistance",out);
		}
		//#endif
	}

	{
		if (TLS_CLIENT || TLS_SERVER)
		{
			if (o->tls_auth_file){
				sprintf (out,"%s,tls-auth",out);
			}

			if (o->key_method > 1){
				sprintf (out,"%s,key-method %d",out,o->key_method);
			}
		}

		if (remote)
		{
			if (TLS_CLIENT){
				sprintf (out,"%s,tls-server",out);
			}else if (TLS_SERVER){
				sprintf (out,"%s,tls-client",out);
			}
		}
		else
		{
			if (TLS_CLIENT){
				sprintf (out,"%s,tls-client",out);
			}else if (TLS_SERVER){
				sprintf (out,"%s,tls-server",out);
			}
		}
	}
	return out;
}

#if 0
bool options_cmp_equal (char *actual, const char *expected)
{
	return options_cmp_equal_safe (actual, expected, strlen (actual) + 1);
}

void options_warning (char *actual, const char *expected)
{
	options_warning_safe (actual, expected, strlen (actual) + 1);
}

char * options_warning_extract_parm1 (const char *option_string)
{
	char *ret;
#if 0
	struct gc_arena gc = gc_new ();
	struct buffer b = string_alloc_buf (option_string, &gc);
	char *p = gc_malloc (OPTION_PARM_SIZE, false, &gc);

	buf_parse (&b, ' ', p, OPTION_PARM_SIZE);
	ret = string_alloc (p, gc_ret);
	gc_free (&gc);
#endif
	return ret;
}

static void
options_warning_safe_scan2 (const int delim,
			    const bool report_inconsistent,
			    const char *p1,
			    const struct buffer *b2_src,
			    const char *b1_name,
			    const char *b2_name)
{
  /* we will stop sending 'proto xxx' in OCC in a future version
   * (because it's not useful), and to reduce questions when
   * interoperating, we start not-printing a warning about it today
   */
  if (strncmp(p1, "proto ", 6) == 0 )
    {
      return;
    }

  if (strlen (p1) > 0)
    {
      struct gc_arena gc = gc_new ();
      struct buffer b2 = *b2_src;
      const char *p1_prefix = options_warning_extract_parm1 (p1, &gc);
      char *p2 = gc_malloc (OPTION_PARM_SIZE, false, &gc);

      while (buf_parse (&b2, delim, p2, OPTION_PARM_SIZE))
	{
	  if (strlen (p2))
	    {
	      const char *p2_prefix = options_warning_extract_parm1 (p2, &gc);
	    
	      if (!strcmp (p1, p2))
		goto done;
	      if (!strcmp (p1_prefix, p2_prefix))
		{
		  if (report_inconsistent){
		    MM("WARNING: '%s' is used inconsistently, %s='%s', %s='%s'",
			 safe_print (p1_prefix, &gc),
			 b1_name,
			 safe_print (p1, &gc),
			 b2_name,
			 safe_print (p2, &gc)); 
		  goto done;
			}
		}
	    }
	}
      
      MM("WARNING: '%s' is present in %s config but missing in %s config, %s='%s'",
	   safe_print (p1_prefix),
	   b1_name,
	   b2_name,
	   b1_name,	   
	   safe_print (p1));

    done:
      gc_free (&gc);
    }
}

void options_warning_safe_scan1 ( const int delim, const bool report_inconsistent,const struct buffer *b1_src,const struct buffer *b2_src,const char *b1_name, const char *b2_name)
{
#if 0
	while (buf_parse (&b, delim, p, OPTION_PARM_SIZE)){
		options_warning_safe_scan2 (delim, report_inconsistent, p, b2_src, b1_name, b2_name);
	}
#endif

}

void options_warning_safe_ml (char *actual, const char *expected, size_t actual_n)
{
#if 0
  if (actual_n > 0)
    {
      struct buffer local = alloc_buf_gc (OPTION_PARM_SIZE + 16, &gc);
      struct buffer remote = alloc_buf_gc (OPTION_PARM_SIZE + 16, &gc);
      actual[actual_n - 1] = 0;

      buf_printf (&local, "version %s", expected);
      buf_printf (&remote, "version %s", actual);

      options_warning_safe_scan1 (',', true,
				  &local, &remote,
				  "local", "remote");

      options_warning_safe_scan1 (',', false,
				  &remote, &local,
				  "remote", "local");
    }
#endif
}

bool options_cmp_equal_safe (char *actual, const char *expected, size_t actual_n)
{
  bool ret = true;

#if 0
  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
#ifndef ENABLE_STRICT_OPTIONS_CHECK
      if (strncmp (actual, expected, 2))
	{
	  MM("NOTE: Options consistency check may be skewed by version differences");
	  options_warning_safe_ml (D_SHOW_OCC, actual, expected, actual_n);
	}
      else
#endif
	ret = !strcmp (actual, expected);
    }
#endif
  return ret;
}

void options_warning_safe (char *actual, const char *expected, size_t actual_n)
{
	options_warning_safe_ml (M_WARN, actual, expected, actual_n);
}

char * options_string_version (const char* s)
{
#if 0
	struct buffer out = alloc_buf_gc (4, gc);
	strncpynt ((char *) BPTR (&out), s, 3);
	return BSTR (&out);
#endif
	return NULL;
}

//#endif /* ENABLE_OCC */
#endif

void foreign_option (struct options *o, char *argv[], int len)
{
	if(o){}
	if(argv){}
	if(len){}
#if 0
	if (len > 0)
	{
		struct buffer name = alloc_buf_gc (OPTION_PARM_SIZE, &gc);
		struct buffer value = alloc_buf_gc (OPTION_PARM_SIZE, &gc);
		int i;
		bool first = true;
		bool good = true;

		good &= buf_printf (&name, "foreign_option_%d", o->foreign_option_index + 1);
		++o->foreign_option_index;
		for (i = 0; i < len; ++i)
		{
			if (argv[i])
			{
				if (!first)
					good &= buf_printf (&value, " ");
				good &= buf_printf (&value, "%s", argv[i]);
				first = false;
			}
		}
		if (good)
			setenv_str (es, BSTR(&name), BSTR(&value));
		else
			MM("foreign_option: name/value overflow");
		gc_free (&gc);
	}
#endif
}


int parse_topology (const char *str)
{
	if (streq (str, "net30")){
		return TOP_NET30;
	}else if (streq (str, "p2p")){
		return TOP_P2P;
	}else if (streq (str, "subnet")){
		return TOP_SUBNET;
	}else{
		MM("ERR: --topology must be net30, p2p, or subnet \n");
		return TOP_UNDEF;
	}
}

char * print_topology (const int topology)
{
	switch (topology)
	{
		case TOP_UNDEF:
			return "undef";
		case TOP_NET30:
			return "net30";
		case TOP_P2P:
			return "p2p";
		case TOP_SUBNET:
			return "subnet";
		default:
			return "unknown";
	}
}

static int global_auth_retry; /* GLOBAL */

int auth_retry_get (void)
{
	return global_auth_retry;
}

bool auth_retry_set (const char *option)
{
	if (streq (option, "interact")){
		global_auth_retry = AR_INTERACT;
	}else if (streq (option, "nointeract")){
		global_auth_retry = AR_NOINTERACT;
	}else if (streq (option, "none")){
		global_auth_retry = AR_NONE;
	}else{
		MM("--auth-retry method must be 'interact', 'nointeract', or 'none'");
		return false;
	}
	return true;
}

char * auth_retry_print (void)
{
	switch (global_auth_retry)
	{
		case AR_NONE:
			return "none";
		case AR_NOINTERACT:
			return "nointeract";
		case AR_INTERACT:
			return "interact";
		default:
			return "???";
	}
}


void usage (void)
{
#if 0
	struct options o;
	init_options (&o, true);

	fprintf (fp, usage_message,
			title_string,
			o.ce.connect_retry_seconds,
			o.ce.local_port, o.ce.remote_port,
			TUN_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT,
			o.verbosity,
			o.authname, o.ciphername,
			o.replay_window, o.replay_time,
			o.tls_timeout, o.renegotiate_seconds,
			o.handshake_window, o.transition_window);
	fflush(fp);
#endif
	exit(0);
}

void usage_small (void)
{
	MM("Use --help for more information.\n");
	exit(0);
}

void show_library_versions()
{
	if(0){
		//MM("library versions: %s%s%s",get_ssl_library_version(),", LZO ", lzo_version_string() );
	}else{
		MM("library versions: %s",get_ssl_library_version());
	}
}

void usage_version (void)
{
	MM("%s", title_string);
	show_library_versions();
#if 0
	MM("Originally developed by James Yonan \n");
	MM("Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net> \n");
	MM("Compile time defines: %s", CONFIGURE_DEFINES);
	MM("special build: %s", CONFIGURE_SPECIAL_BUILD);
	MM("git revision: %s", CONFIGURE_GIT_REVISION);
#endif
}

#if 0
void notnull (const char *arg, const char *description)
{
	if (!arg){
		MM("You must define %s \n", description);
	}
}
#endif

bool string_defined_equal (const char *s1, const char *s2)
{
	if (s1 && s2){
		return !strcmp (s1, s2);
	}else{
		return false;
	}
}

int positive_atoi (const char *str)
{
	const int i = atoi (str);
	return i < 0 ? 0 : i;
}

inline bool space (unsigned char c)
{
	return c == '\0' || isspace (c);
}

//int parse_line (const char *line, char *p[],const int n,const char *file,const int line_num,struct epoll_ptr_data *epd)
int parse_line (const char *line, char *p[],const int n,const char *file,const int line_num)
{
	const int STATE_INITIAL = 0;
	const int STATE_READING_QUOTED_PARM = 1;
	const int STATE_READING_UNQUOTED_PARM = 2;
	const int STATE_DONE = 3;
	const int STATE_READING_SQUOTED_PARM = 4;

	const char *error_prefix = "";

	int ret = 0;
	const char *c = line;
	int state = STATE_INITIAL;
	bool backslash = false;
	char in, out;

	char parm[OPTION_PARM_SIZE];
	unsigned int parm_len = 0;

	error_prefix = "ERROR: ";
	do
	{
		in = *c;
		out = 0;

		if (!backslash && in == '\\' && state != STATE_READING_SQUOTED_PARM)
		{
			backslash = true;
		}
		else
		{
			if (state == STATE_INITIAL)
			{
				if (!space (in))
				{
					if (in == ';' || in == '#'){
						break;
					}
					if (!backslash && in == '\"'){
						state = STATE_READING_QUOTED_PARM;
					}else if (!backslash && in == '\''){
						state = STATE_READING_SQUOTED_PARM;
					}else{
						out = in;
						state = STATE_READING_UNQUOTED_PARM;
					}
				}
			}
			else if (state == STATE_READING_UNQUOTED_PARM)
			{
				if (!backslash && space (in)){
					state = STATE_DONE;
				}else{
					out = in;
				}
			}
			else if (state == STATE_READING_QUOTED_PARM)
			{
				if (!backslash && in == '\"'){
					state = STATE_DONE;
				}else{
					out = in;
				}
			}
			else if (state == STATE_READING_SQUOTED_PARM)
			{
				if (in == '\''){
					state = STATE_DONE;
				}else{
					out = in;
				}
			}
			if (state == STATE_DONE)
			{
				p[ret] = malloc(parm_len+1);

				memset(p[ret],0x00,parm_len+1);
				memcpy (p[ret], parm, parm_len);
				p[ret][parm_len] = '\0';
				state = STATE_INITIAL;
				parm_len = 0;
				++ret;

			}

			if (backslash && out)
			{
				if (!(out == '\\' || out == '\"' || space (out)))
				{
					//MM("## ERR:  %sOptions warning: Bad backslash ('\\') usage in %s:%d: remember that backslashes are treated as shell-escapes and if you need to pass backslash characters as part of a Windows filename, you should use double backslashes such as \"c:\\\\" PACKAGE "\\\\static.key\"", error_prefix, file, line_num);
					return 0;
				}
			}
			backslash = false;
		}

		if (out)
		{
			if (parm_len >= SIZE (parm))
			{
				parm[SIZE (parm) - 1] = 0;
				MM("## ERR: %sOptions error: Parameter at %s:%d is too long (%d chars max): %s ##\n", error_prefix, file, line_num, (int) SIZE (parm), parm);
				return 0;
			}
			parm[parm_len++] = out;
		}

		if (ret >= n){
			break;
		}

	} while (*c++ != '\0');

	if (state == STATE_READING_QUOTED_PARM)
	{
		MM("## ERR: %sOptions error: No closing quotation (\") in %s:%d \n", error_prefix, file, line_num);
		return 0;
	}
	if (state == STATE_READING_SQUOTED_PARM)
	{
		MM("## ERR: %sOptions error: No closing single quotation (\') in %s:%d \n", error_prefix, file, line_num);
		return 0;
	}
	if (state != STATE_INITIAL)
	{
		MM("## ERR: %sOptions error: Residual parse state (%d) in %s:%d \n", error_prefix, state, file, line_num);
		return 0;
	}
#if 0
	int i;
	for (i = 0; i < ret; ++i)
	{
		MM("## %s %d  %s:%d ARG[%d] '%s' \n",__func__,__LINE__, file, line_num, i, p[i]);
	}
#endif
	return ret;
}

void bypass_doubledash (char **p)
{
	if (strlen (*p) >= 3 && !strncmp (*p, "--", 2)){
		*p += 2;
	}
}

struct in_src {
# define IS_TYPE_FP 1
# define IS_TYPE_BUF 2
	int type;
	union {
		FILE *fp;
		char *multiline;
	}u;
};


void rm_trailing_chars (char *str,char *what_to_delete)
{
	bool modified;
	do {
		int len = strlen (str);
		modified = false;
		if (len > 0)
		{
			char *cp = str + (len - 1);
			if (strchr (what_to_delete, *cp) != NULL)
			{
				*cp = '\0';
				modified = true;
			}
		}
	} while (modified);
}
void chomp (char *str)
{
	rm_trailing_chars (str, "\r\n");
}



bool char_parse (char *buf, const int delim, char *line, const int size)
{
	bool eol = false;
	int n = 0;
	int c;

	int x = 0;
	do
	{
		c = buf[x];
		if (c < 0){
			eol = true;
		}
		if (c <= 0 || c == delim){
			c = 0;
		}
		if (n >= size){
			break;
		}
		line[n++] = c;
		x++;
	}
	while (c);

	if(strlen(line) == 0){
		return false;
	}else{
		line[size-1] = '\0';
		return !(eol && !strlen(line));
	}
}


bool in_src_get (const struct in_src *is, char *line, const int size)
{
	if (is->type == IS_TYPE_FP)
	{
		return BOOL_CAST (fgets (line, size, is->u.fp));
	}
	else if (is->type == IS_TYPE_BUF)
	{
		bool status = char_parse (is->u.multiline, '\n', line, size);
		if ((int) strlen (line) + 1 < size){
			strcat (line, "\n");
		}
		return status;
	}
	else
	{
		return false;
	}
}

char * read_inline_file (struct in_src *is, const char *close_tag)
{
	char line[OPTION_LINE_SIZE];
	char *buf = malloc(10000);
	memset(buf,0x00,10000);
	while (in_src_get (is, line, sizeof (line)))
	{
		if (!strncmp (line, close_tag, strlen (close_tag))){
			break;
		}
		sprintf(buf,"%s",line);
	}

	return buf;
}

bool check_inline_file (struct in_src *is, char *p[])
{
	bool ret = false;
	if (p[0] && !p[1])
	{
		char *arg = p[0];
		if (arg[0] == '<' && arg[strlen(arg)-1] == '>')
		{
			char *close_tag = NULL;
			arg[strlen(arg)-1] = '\0';
			p[0] = malloc(strlen(arg)+1);
			memcpy(p[0],arg,strlen(arg)+1);

			p[1] = malloc(strlen(INLINE_FILE_TAG));
			memcpy(p[1],INLINE_FILE_TAG,strlen(INLINE_FILE_TAG));

			close_tag = malloc(strlen(p[0]) + 4);
			sprintf(close_tag,"</%s>",p[0]);

			p[2] = read_inline_file (is, close_tag);
			p[3] = NULL;
			free(close_tag);
			ret = true;
		}
	}
	return ret;
}

bool check_inline_file_via_fp (FILE *fp, char *p[])
{
	struct in_src is;
	is.type = IS_TYPE_FP;
	is.u.fp = fp;
	return check_inline_file (&is, p);
}

bool check_inline_file_via_buf (char *multiline, char *p[])
{
	struct in_src is;
	is.type = IS_TYPE_BUF;
	is.u.multiline = multiline;
	return check_inline_file (&is, p);
}

void read_config_file (struct options *options,char *file,char *top_file,const int top_line,const unsigned int permission_mask,unsigned int *option_types_found,struct epoll_ptr_data *epd)
{
	FILE *fp=NULL;
	int line_num;
	char line[OPTION_LINE_SIZE];
	char *p[MAX_PARMS];

	if (streq (file, "stdin")){
		fp = stdin;
	}else{
		fp = fopen (file, "r");
	}
	if (fp != NULL)
	{
		line_num = 0;
		while (fgets(line, sizeof (line), fp))
		{
			int offset = 0;
			int ret = 0;
			int xx = 0;
			memset(&p,0x00,sizeof(p));
			++line_num;
			if (line_num == 1 && strncmp (line, "\xEF\xBB\xBF", 3) == 0){
				offset = 3;
			}
			ret = parse_line (line + offset, p, SIZE (p), file, line_num);
			if (ret > 0)
			{
				bypass_doubledash (&p[0]);
				check_inline_file_via_fp (fp, p);
				add_option (options, p, file, line_num, permission_mask, option_types_found,epd);
			}
			printf("##################### %s %d #############\n",__func__,__LINE__);
#if 0
			for(xx = 0 ; xx < ret ; xx++){
				sfree(p[xx],0);
			}
#endif
		}
		if (fp != stdin){
			fclose (fp);
		}
	}
	else
	{
		//MM("## ERR: In %s:%d: Error opening configuration file: %s \n", top_file, top_line, file);
	}
}

void read_config_string (const char *prefix, struct options *options,const char *config,const unsigned int permission_mask,unsigned int *option_types_found)
{
	if(prefix){}
	if(options){}
	if(config){}
	if(permission_mask){}
	if(option_types_found){}

#if 0
	char line[OPTION_LINE_SIZE];
	struct buffer multiline;
	int line_num = 0;

	buf_set_read (&multiline, (uint8_t*)config, strlen (config));

	while (buf_parse (&multiline, '\n', line, sizeof (line)))
	{
		char *p[MAX_PARMS];
		memset(&p,0x00,sizeof(p));
		++line_num;
		if (parse_line (line, p, SIZE (p), prefix, line_num ))
		{
			bypass_doubledash (&p[0]);
			check_inline_file_via_buf (&multiline, p);
			add_option (options, p, prefix, line_num, 0, permission_mask, option_types_found, es);
		}
		memset(&p,0x00,sizeof(p));
	}
	memset(&line,0x00,sizeof(line));
#endif
}

void parse_argv (struct options *options, const int argc,char *argv[],const unsigned int permission_mask,unsigned int *option_types_found)
{
	int i, j;

	if (argc <= 1){
		usage ();
	}

	if (argc == 2 && strncmp (argv[1], "--", 2))
	{
		char *p[MAX_PARMS];
		memset(&p,0x00,sizeof(p));
		p[0] = "config";
		p[1] = argv[1];
		add_option (options, p, NULL, 0, permission_mask, option_types_found,NULL);
	}
	else
	{
		for (i = 1; i < argc; ++i)
		{
			char *p[MAX_PARMS];
			memset(&p,0x00,sizeof(p));
			p[0] = argv[i];
			if (strncmp(p[0], "--", 2)){
				MM("## ERR: I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--' ##\n", p[0]);
			}else{
				p[0] += 2;
			}

			for (j = 1; j < MAX_PARMS; ++j)
			{
				if (i + j < argc)
				{
					char *arg = argv[i + j];
					if (strncmp (arg, "--", 2)){
						p[j] = arg;
					}else{
						break;
					}
				}
			}
			add_option (options, p, NULL, 0, permission_mask, option_types_found,NULL);
			i += j - 1;
		}
	}
}

bool apply_push_options (struct options *options,char *buf, int len ,unsigned int permission_mask,unsigned int *option_types_found)
{

	char line[OPTION_PARM_SIZE];
	int line_num = 0;
	char *file = "[PUSH-OPTIONS]";

	int idx = 0;
	memset(line,0x00,OPTION_PARM_SIZE);

	while (char_parse(buf+idx, ',', line, OPTION_PARM_SIZE))
	{
		idx += strlen(line)+1;
		char *p[MAX_PARMS];
		int ret = 0;
		int xx = 0;
		memset(&p,0x00,sizeof(p));
		++line_num;

		ret = parse_line (line, p, SIZE (p), file, line_num);
		if (ret > 0)
		{
			add_option (options, p, file, line_num, permission_mask, option_types_found,NULL);
		}

		for(xx = 0 ; xx < ret ; xx++){
			sfree(p[xx],0);
		}

		if(idx == len){
			break;
		}
	}
	return true;
}

void options_server_import (struct options *o, char *filename,unsigned int permission_mask,unsigned int *option_types_found,struct epoll_ptr_data *epd)
{
					printf("##################### %s %d #############\n",__func__,__LINE__);
	//MM( "## OPTIONS IMPORT: reading client specific options from: %s ##\n", filename);
	read_config_file (o,filename,filename,0,permission_mask,option_types_found,epd);
}

void options_string_import (struct options *options, const char *config,const unsigned int permission_mask,unsigned int *option_types_found)
{
	read_config_string ("[CONFIG-STRING]", options, config, permission_mask, option_types_found);
}

#if 0
#define VERIFY_PERMISSION(mask) { if (!verify_permission(p[0], file, line, (mask), permission_mask, option_types_found,  options)) goto err; }

bool verify_permission (const char *name, const char* file,int line,const unsigned int type,const unsigned int allowed,unsigned int *found,struct options* options)
{
	if (!(type & allowed))
	{
		MM("## ERR: option '%s' cannot be used in this context (%s) \n", name, file);
		return false;
	}

	if (found){
		*found |= type;
	}
	if ((type & OPT_P_CONNECTION) && options->connection_list)
	{
		if (file){
			MM("Option '%s' in %s:%d is ignored by previous <connection> blocks \n", name, file, line);
		}else{
			MM( "Option '%s' is ignored by previous <connection> blocks \n", name);
		}
	}
	return true;
}
#endif

int string_array_len(char **array)
{
	int i = 0;
	if (array)
	{
		while (array[i]){
			++i;
		}
	}
	return i;
}

#define NM_QUOTE_HINT (1<<0)
bool no_more_than_n_args (char *p[],const int max,const unsigned int flags)
{
	const int len = string_array_len ((char **)p);

	if (!len){
		return false;
	}

	if (len > max)
	{
		MM("## ERR: the --%s directive should have at most %d parameter%s.%s",
				p[0],
				max - 1,
				max >= 3 ? "s" : "",
				(flags & NM_QUOTE_HINT) ? "  To pass a list of arguments as one of the parameters, try enclosing them in double quotes (\"\").\n" : "\n");
		return false;
	}
	else{
		return true;
	}
}
void set_user_script (struct options *options, const char **script,const char *new_script,const char *type,bool in_chroot)
{
	if (*script) {
		MM("## ERR: Multiple --%s scripts defined.  The previously configured script is overridden.\n", type);
	}
	*script = new_script;
	options->user_script_used = true;

	{
		char script_name[100];
		snprintf (script_name, sizeof(script_name),  "--%s script", type);

		if (check_cmd_access (*script, script_name, (in_chroot ? options->chroot_dir : NULL))){
			MM("## ERR: %s %d  Please correct this error.%s %s \n",__func__,__LINE__,script_name,*script);
		}
	}
}


void add_option(struct options *options, char *p[],char *file,int line,const unsigned int permission_mask,unsigned int *option_types_found,struct epoll_ptr_data *epd)
{
	const bool pull_mode = BOOL_CAST (permission_mask & OPT_P_PULL_MODE);

	if (streq (p[0], "setenv") && p[1] && streq (p[1], "opt") && !(permission_mask & OPT_P_PULL_MODE))
	{
		p += 2;
	}

	if (!file)
	{
		file = "[CMD-LINE]";
		line = 1;
	}
	if (streq (p[0], "help"))
	{
		usage ();
	}
	if (streq (p[0], "version"))
	{
		usage_version ();
	}
	else if (streq (p[0], "config") && p[1])
	{

		if (!options->config){
			options->config = p[1];
		}

		read_config_file (options, p[1], file, line, permission_mask, option_types_found,NULL);
	}
	else if (streq (p[0], "core-count") && p[1])
	{
		options->core = atoi(p[1]);
	}
	else if (streq (p[0], "mempool-count") && p[1])
	{
		options->mempool_cnt = atoi(p[1]);
		if(options->mempool_cnt < 2048){
			options->mempool_cnt = 2048;
		}
	}


#ifdef ENABLE_MANAGEMENT
	else if (streq (p[0], "management") && p[1] && p[2])
	{
		MM("### %s %d not support option %s ###\n",__func__,__LINE__,p[0]);
		int port = 0;

		if (streq (p[2], "unix"))
		{
#if UNIX_SOCK_SUPPORT
			options->management_flags |= MF_UNIX_SOCK;
#else
			MM("MANAGEMENT: this platform does not support unix domain sockets");
			goto err;
#endif
		}
		else
		{
			port = atoi (p[2]);
			if (!legal_ipv4_port (port))
			{
				MM("port number associated with --management directive is out of range");
				goto err;
			}
		}

		options->management_addr = p[1];
		options->management_port = port;
		if (p[3])
		{
			options->management_user_pass = p[3];
		}
	}
#endif
#ifdef ENABLE_MANAGEMENT
	else if (streq (p[0], "management-client-user") && p[1])
	{
		options->management_client_user = p[1];
	}
	else if (streq (p[0], "management-client-group") && p[1])
	{
		options->management_client_group = p[1];
	}
	else if (streq (p[0], "management-query-passwords"))
	{
		options->management_flags |= MF_QUERY_PASSWORDS;
	}
	else if (streq (p[0], "management-query-remote"))
	{
		options->management_flags |= MF_QUERY_REMOTE;
	}
	else if (streq (p[0], "management-query-proxy"))
	{
		options->management_flags |= MF_QUERY_PROXY;
		options->force_connection_list = true;
	}
	else if (streq (p[0], "management-hold"))
	{
		options->management_flags |= MF_HOLD;
	}
	else if (streq (p[0], "management-signal"))
	{
		options->management_flags |= MF_SIGNAL;
	}
	else if (streq (p[0], "management-forget-disconnect"))
	{
		options->management_flags |= MF_FORGET_DISCONNECT;
	}
	else if (streq (p[0], "management-up-down"))
	{
		options->management_flags |= MF_UP_DOWN;
	}
	else if (streq (p[0], "management-client"))
	{
		options->management_flags |= MF_CONNECT_AS_CLIENT;
		options->management_write_peer_info_file = p[1];
	}
#endif
#ifdef MANAGMENT_EXTERNAL_KEY
	else if (streq (p[0], "management-external-key"))
	{
		options->management_flags |= MF_EXTERNAL_KEY;
	}
#endif
#ifdef MANAGEMENT_DEF_AUTH
	else if (streq (p[0], "management-client-auth"))
	{
		options->management_flags |= MF_CLIENT_AUTH;
	}
#endif
#ifdef ENABLE_X509_TRACK
	else if (streq (p[0], "x509-track") && p[1])
	{
		x509_track_add (&options->x509_track, p[1]);
	}
#endif
#ifdef MANAGEMENT_PF
	else if (streq (p[0], "management-client-pf"))
	{
		options->management_flags |= (MF_CLIENT_PF | MF_CLIENT_AUTH);
	}
#endif
#ifdef ENABLE_MANAGEMENT
	else if (streq (p[0], "management-log-cache") && p[1])
	{
		int cache;

		cache = atoi (p[1]);
		if (cache < 1)
		{
			MM("--management-log-cache parameter is out of range");
			goto err;
		}
		options->management_log_history_cache = cache;
	}
#endif
#if 0
#ifdef ENABLE_PLUGIN
	else if (streq (p[0], "plugin") && p[1])
	{
		if (!options->plugin_list)
			options->plugin_list = plugin_option_list_new ();
		if (!plugin_option_list_add (options->plugin_list, &p[1]))
		{
			MM("plugin add failed: %s", p[1]);
			goto err;
		}
	}
#endif
#endif
	else if (streq (p[0], "mode") && p[1])
	{
		if (streq (p[1], "p2p")){
			options->mode = CLIENT;
		}else if (streq (p[1], "server")){
			options->mode = SERVER;
		}else{
			MM("## ERR: Bad --mode parameter: %s \n", p[1]);
			goto err;
		}
	}
	else if (streq (p[0], "dev") && p[1])
	{
		options->dev = p[1];
	}
	else if (streq (p[0], "dev-type") && p[1])
	{
		options->dev_type = p[1];
	}
	else if (streq (p[0], "dev-node") && p[1])
	{
		options->dev_node = p[1];
	}
	else if (streq (p[0], "lladdr") && p[1])
	{
		if (mac_addr_safe (p[1])){
			options->lladdr = p[1];
		}
		else
		{
			MM("lladdr parm '%s' must be a MAC address\n", p[1]);
			goto err;
		}
	}
	else if (streq (p[0], "topology") && p[1])
	{
		options->topology = parse_topology (p[1]);
	}
	else if (streq (p[0], "tun-ipv6"))
	{
		options->tun_ipv6 = true;
	}
	else if (streq (p[0], "iproute") && p[1])
	{
		MM("### %s %d not support option %s ###\n",__func__,__LINE__,p[0]);
		//iproute_path = p[1]; ??????
	}
	else if (streq (p[0], "ifconfig") && p[1] && p[2])
	{
		if (ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) && ip_or_dns_addr_safe (p[2], options->allow_pull_fqdn))
		{
			//options->ifconfig_local = p[1];
			//options->ifconfig_remote_netmask = p[2];
			sprintf(options->ifconfig_local,"%s",p[1]);
			sprintf(options->ifconfig_remote_netmask,"%s",p[2]);
		
		}
		else
		{
			MM("ifconfig parms '%s' and '%s' must be valid addresses", p[1], p[2]);
			goto err;
		}
	}
	else if (streq (p[0], "ifconfig-ipv6") && p[1] && p[2] )
	{
		unsigned int netbits;
		char * ipv6_local;

		if ( get_ipv6_addr( p[1], NULL, &netbits, &ipv6_local) && ipv6_addr_safe( p[2] ) )
		{
			if ( netbits < 64 || netbits > 124 )
			{
				MM("ifconfig-ipv6: /netbits must be between 64 and 124, not '/%d' \n", netbits );
				goto err;
			}

			if (options->ifconfig_ipv6_local){
				free ((char *) options->ifconfig_ipv6_local);
			}

			options->ifconfig_ipv6_local = ipv6_local;
			options->ifconfig_ipv6_netbits = netbits;
			options->ifconfig_ipv6_remote = p[2];
		}
		else
		{
			MM("ifconfig-ipv6 parms '%s' and '%s' must be valid addresses\n", p[1], p[2]);
			goto err;
		}
	}
	else if (streq (p[0], "ifconfig-noexec"))
	{
		options->ifconfig_noexec = true;
	}
	else if (streq (p[0], "ifconfig-nowarn"))
	{
		options->ifconfig_nowarn = true;
	}
	else if (streq (p[0], "local") && p[1])
	{
		options->ce.local = p[1];
	}
	else if (streq (p[0], "remote-random"))
	{
		options->remote_random = true;
	}
#if 0
	else if (streq (p[0], "connection") && p[1])
	{
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			struct options sub;
			struct connection_entry *e;

			init_options (&sub, true);
			sub.ce = options->ce;
			read_config_string ("[CONNECTION-OPTIONS]", &sub, p[2], OPT_P_CONNECTION, option_types_found);
			if (!sub.ce.remote)
			{
				MM("Each 'connection' block must contain exactly one 'remote' directive");
				goto err;
			}

			e = alloc_connection_entry (options);
			if (!e){
				goto err;
			}
			*e = sub.ce;
			uninit_options (&sub);
		}
	}
#endif
	else if (streq (p[0], "ignore-unknown-option") && p[1])
	{
#if 0 //2017.01.05 rainroot 
		int i;
		int j;
		int numignored=0;
		const char **ignore;

		for (i=1;p[i];i++){
			numignored++;
		}

		for (i=0;options->ignore_unknown_option && options->ignore_unknown_option[i]; i++){
			numignored++;
		}

		ignore = malloc(numignored+1);
		memset(ignore,0x00,numignored+1);


		for (i=0;options->ignore_unknown_option && options->ignore_unknown_option[i]; i++){
			ignore[i]=options->ignore_unknown_option[i];
		}
		options->ignore_unknown_option=ignore;

		for (j=1;p[j];j++)
		{
			if (p[j][0]=='-' && p[j][1]=='-'){
				options->ignore_unknown_option[i] = (p[j]+2);
			}else{
				options->ignore_unknown_option[i] = p[j];
			}
			i++;
		}
		options->ignore_unknown_option[i] = NULL;
#endif
	}
	else if (streq (p[0], "remote-ip-hint") && p[1])
	{
		options->remote_ip_hint = p[1];
	}
#if 0
#if HTTP_PROXY_OVERRIDE
	else if (streq (p[0], "http-proxy-override") && p[1] && p[2])
	{
		options->http_proxy_override = parse_http_proxy_override(p[1], p[2], p[3]);
		if (!options->http_proxy_override)
			goto err;
		options->force_connection_list = true;
	}
#endif
#endif
	else if (streq (p[0], "remote") && p[1])
	{
		struct remote_entry re;
		re.remote = NULL;
		re.remote_port = re.proto = -1;

		re.remote = p[1];
		if (p[2])
		{
			const int port = atoi (p[2]);
			if (!legal_ipv4_port (port))
			{
				MM("remote: port number associated with host %s is out of range \n", p[1]);
				goto err;
			}
			re.remote_port = port;
			if (p[3])
			{
				const int proto = ascii2proto(p[3]);
				if (proto < 0)
				{
					MM("remote: bad protocol associated with host %s: '%s' \n", p[1], p[3]);
					goto err;
				}
				re.proto = proto;
			}
		}
		if (permission_mask & OPT_P_GENERAL)
		{
			struct remote_entry *e = malloc(sizeof(struct remote_entry));
			memset(e,0x00,sizeof(struct remote_entry));
			if (!e){
				goto err;
			}
			e->remote = p[1];
			if(p[2] != NULL){
				e->remote_port = atoi(p[2]);
			}
			//e->proto = ascii2proto(p[3]); 
			options->remote_list->array[options->remote_list->len] = e;
			options->remote_list->len++;

		}
		else if (permission_mask & OPT_P_CONNECTION)
		{
			options->ce.remote = re.remote;
			options->ce.remote_port = re.remote_port;
			options->ce.proto = re.proto;
		}
	}
	else if (streq (p[0], "resolv-retry") && p[1])
	{
		if (streq (p[1], "infinite")){
			options->resolve_retry_seconds = RESOLV_RETRY_INFINITE;
		}else{
			options->resolve_retry_seconds = positive_atoi (p[1]);
		}
	}
	else if (streq (p[0], "connect-retry") && p[1])
	{
		options->ce.connect_retry_seconds = positive_atoi (p[1]);
		options->ce.connect_retry_defined = true;
	}
	else if (streq (p[0], "connect-timeout") && p[1])
	{
		options->ce.connect_timeout = positive_atoi (p[1]);
		options->ce.connect_timeout_defined = true;
	}
	else if (streq (p[0], "connect-retry-max") && p[1])
	{
		options->ce.connect_retry_max = positive_atoi (p[1]);
	}
#if 0
	else if (streq (p[0], "ipchange") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options,
				&options->ipchange,
				string_substitute (p[1], ',', ' '),
				"ipchange", true);
	}
#endif
	else if (streq (p[0], "float"))
	{
		options->ce.remote_float = true;
	}
	else if (streq (p[0], "chroot") && p[1])
	{
		options->chroot_dir = p[1];
	}
	else if (streq (p[0], "cd") && p[1])
	{
		if (chdir (p[1]))
		{
			MM("cd to '%s' failed\n", p[1]);
			goto err;
		}
		options->cd_dir = p[1];
	}
#if 0
#ifdef ENABLE_SELINUX
	else if (streq (p[0], "setcon") && p[1])
	{
		options->selinux_context = p[1];
	}
#endif
#endif
	else if (streq (p[0], "writepid") && p[1])
	{
		options->writepid = p[1];
	}
	else if (streq (p[0], "up") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->up_script, p[1], "up", false);
	}
	else if (streq (p[0], "down") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->down_script, p[1], "down", true);
	}
	else if (streq (p[0], "down-pre"))
	{
		options->down_pre = true;
	}
	else if (streq (p[0], "up-delay"))
	{
		options->up_delay = true;
	}
	else if (streq (p[0], "up-restart"))
	{
		options->up_restart = true;
	}
#if 0
	else if (streq (p[0], "syslog"))
	{
		open_syslog (p[1], false);
	}
#endif
#if 0
	else if (streq (p[0], "daemon"))
	{
		bool didit = false;
		if (!options->daemon)
		{
			options->daemon = didit = true;
			open_syslog (p[1], false);
		}
		if (p[1])
		{
			if (!didit)
			{
				MM("WARNING: Multiple --daemon directives specified, ignoring --daemon %s. (Note that initscripts sometimes add their own --daemon directive.)\n", p[1]);
				goto err;
			}
		}
	}
#endif
#if 0
	else if (streq (p[0], "inetd"))
	{
		if (!options->inetd)
		{
			int z;
			const char *name = NULL;
			const char *opterr = "when --inetd is used with two parameters, one of them must be 'wait' or 'nowait' and the other must be a daemon name to use for system logging";

			options->inetd = -1;

			for (z = 1; z <= 2; ++z)
			{
				if (p[z])
				{
					if (streq (p[z], "wait"))
					{
						if (options->inetd != -1)
						{
							MM("%s\n", opterr);
							goto err;
						}
						else{
							options->inetd = INETD_WAIT;
						}
					}
					else if (streq (p[z], "nowait"))
					{
						if (options->inetd != -1)
						{
							MM( "%s", opterr);
							goto err;
						}
						else{
							options->inetd = INETD_NOWAIT;
						}
					}
					else
					{
						if (name != NULL)
						{
							MM("%s\n", opterr);
							goto err;
						}
						name = p[z];
					}
				}
			}

			if (options->inetd == -1){
				options->inetd = INETD_WAIT;
			}

			save_inetd_socket_descriptor ();
			open_syslog (name, true);
		}
	}
#endif
#if 0
	else if (streq (p[0], "log") && p[1])
	{
		options->log = true;
		redirect_stdout_stderr (p[1], false);
	}
#endif
#if 0
	else if (streq (p[0], "suppress-timestamps"))
	{
		options->suppress_timestamps = true;
		set_suppress_timestamps(true);
	}
#endif
#if 0
	else if (streq (p[0], "log-append") && p[1])
	{
		options->log = true;
		redirect_stdout_stderr (p[1], true);
	}
#endif
	else if (streq (p[0], "mlock"))
	{
		options->mlock = true;
	}
#if 0
	else if (streq (p[0], "multihome"))
	{
		options->sockflags |= SF_USE_IP_PKTINFO;
	}
#endif
	else if (streq (p[0], "verb") && p[1])
	{
		options->verbosity = positive_atoi (p[1]);
	}
	else if (streq (p[0], "mute") && p[1])
	{
		options->mute = positive_atoi (p[1]);
	}
#if 0
	else if (streq (p[0], "errors-to-stderr"))
	{
		errors_to_stderr();
	}
#endif
	else if (streq (p[0], "status") && p[1])
	{
		options->status_file = p[1];
		if (p[2])
		{
			options->status_file_update_freq = positive_atoi (p[2]);
		}
	}
#if 0
	else if (streq (p[0], "status-version") && p[1])
	{
		int version;

		version = atoi (p[1]);
		if (version < 1 || version > 3)
		{
			MM("--status-version must be 1 to 3");
			goto err;
		}
		options->status_file_version = version;
	}
	else if (streq (p[0], "remap-usr1") && p[1])
	{
		if (streq (p[1], "SIGHUP")){
			options->remap_sigusr1 = SIGHUP;
		}else if (streq (p[1], "SIGTERM")){
			options->remap_sigusr1 = SIGTERM;
		}else{
			MM("--remap-usr1 parm must be 'SIGHUP' or 'SIGTERM'");
			goto err;
		}
	}
#endif
	else if ((streq (p[0], "link-mtu") || streq (p[0], "udp-mtu")) && p[1])
	{
		options->ce.link_mtu = positive_atoi (p[1]);
		options->ce.link_mtu_defined = true;
	}
	else if (streq (p[0], "tun-mtu") && p[1])
	{
		options->ce.tun_mtu = positive_atoi (p[1]);
		options->ce.tun_mtu_defined = true;
	}
	else if (streq (p[0], "tun-mtu-extra") && p[1])
	{
		options->ce.tun_mtu_extra = positive_atoi (p[1]);
		options->ce.tun_mtu_extra_defined = true;
	}
#if 0
#ifdef ENABLE_FRAGMENT
	else if (streq (p[0], "mtu-dynamic"))
	{
		MM("--mtu-dynamic has been replaced by --fragment");
		goto err;
	}
	else if (streq (p[0], "fragment") && p[1])
	{
		options->ce.fragment = positive_atoi (p[1]);
	}
#endif
#endif
#if 0
	else if (streq (p[0], "mtu-disc") && p[1])
	{
		options->ce.mtu_discover_type = translate_mtu_discover_type_name (p[1]);
	}
#endif
#if 0
	else if (streq (p[0], "nice") && p[1])
	{
		options->nice = atoi (p[1]);
	}
#endif
	else if (streq (p[0], "rcvbuf") && p[1])
	{
		options->rcvbuf = positive_atoi (p[1]);
	}
	else if (streq (p[0], "sndbuf") && p[1])
	{
		options->sndbuf = positive_atoi (p[1]);
	}
	else if (streq (p[0], "mark") && p[1])
	{
		options->mark = atoi(p[1]);
	}
#if 0
	else if (streq (p[0], "socket-flags"))
	{
		int j;
		for (j = 1; j < MAX_PARMS && p[j]; ++j)
		{
			if (streq (p[j], "TCP_NODELAY")){
				options->sockflags |= SF_TCP_NODELAY;
			}else{
				MM("unknown socket flag: %s \n", p[j]);
			}
		}
	}
#endif
	else if (streq (p[0], "txqueuelen") && p[1])
	{
		options->txqueuelen = positive_atoi (p[1]);
	}
#if 0
	else if (streq (p[0], "shaper") && p[1])
	{
#ifdef ENABLE_FEATURE_SHAPER
		int shaper;

		shaper = atoi (p[1]);
		if (shaper < SHAPER_MIN || shaper > SHAPER_MAX)
		{
			MM("Bad shaper value, must be between %d and %d", SHAPER_MIN, SHAPER_MAX);
			goto err;
		}
		options->shaper = shaper;
#else /* ENABLE_FEATURE_SHAPER */
		MM("--shaper requires the gettimeofday() function which is missing");
		goto err;
#endif /* ENABLE_FEATURE_SHAPER */
	}
#endif
	else if (streq (p[0], "port") && p[1])
	{
		int port;

		port = atoi (p[1]);
		if (!legal_ipv4_port (port))
		{
			MM("Bad port number: %s\n", p[1]);
			goto err;
		}
		options->ce.local_port = options->ce.remote_port = port;
	}
	else if (streq (p[0], "lport") && p[1])
	{
		int port;

		port = atoi (p[1]);
		if ((port != 0) && !legal_ipv4_port (port))
		{
			MM("Bad local port number: %s\n", p[1]);
			goto err;
		}
		options->ce.local_port_defined = true;
		options->ce.local_port = port;
	}
	else if (streq (p[0], "rport") && p[1])
	{
		int port;

		port = atoi (p[1]);
		if (!legal_ipv4_port (port))
		{
			MM("Bad remote port number: %s\n", p[1]);
			goto err;
		}
		options->ce.remote_port = port;
	}
	else if (streq (p[0], "bind"))
	{
		options->ce.bind_defined = true;
	}
	else if (streq (p[0], "nobind"))
	{
		options->ce.bind_local = false;
	}
	else if (streq (p[0], "fast-io"))
	{
		options->fast_io = true;
	}
	else if (streq (p[0], "inactive") && p[1])
	{
		options->inactivity_timeout = positive_atoi (p[1]);
		if (p[2]){
			options->inactivity_minimum_bytes = positive_atoi (p[2]);
		}
	}
	else if (streq (p[0], "proto") && p[1])
	{
		int proto;
		proto = ascii2proto (p[1]);
		if (proto < 0)
		{
			//MM("Bad protocol: '%s'.  Allowed protocols with --proto option: %s", p[1],proto2ascii_all ());
			goto err;
		}
		options->ce.proto = proto;
	}
	else if (streq (p[0], "proto-force") && p[1])
	{
		int proto_force;
		proto_force = ascii2proto (p[1]);
		if (proto_force < 0)
		{
			MM("Bad --proto-force protocol: '%s'\n", p[1]);
			goto err;
		}
		options->proto_force = proto_force;
		options->force_connection_list = true;
	}
#if 0
#ifdef ENABLE_HTTP_PROXY
	else if (streq (p[0], "http-proxy") && p[1])
	{
		struct http_proxy_options *ho;


		{
			int port;
			if (!p[2])
			{
				MM("http-proxy port number not defined\n");
				goto err;
			}
			port = atoi (p[2]);
			if (!legal_ipv4_port (port))
			{
				MM("Bad http-proxy port number: %s\n", p[2]);
				goto err;
			}

			ho = init_http_proxy_options_once (&options->ce.http_proxy_options);

			ho->server = p[1];
			ho->port = port;
		}

		if (p[3])
		{
			/* auto -- try to figure out proxy addr, port, and type automatically */
			/* semiauto -- given proxy addr:port, try to figure out type automatically */
			/* (auto|semiauto)-nct -- disable proxy auth cleartext protocols (i.e. basic auth) */
			if (streq (p[3], "auto"))
				ho->auth_retry = PAR_ALL;
			else if (streq (p[3], "auto-nct"))
				ho->auth_retry = PAR_NCT;
			else
			{
				ho->auth_method_string = "basic";
				ho->auth_file = p[3];

				if (p[4])
				{
					ho->auth_method_string = p[4];
				}
			}
		}
		else
		{
			ho->auth_method_string = "none";
		}
	}
	else if (streq (p[0], "http-proxy-retry"))
	{
		struct http_proxy_options *ho;
		ho = init_http_proxy_options_once (&options->ce.http_proxy_options);
		ho->retry = true;
	}
	else if (streq (p[0], "http-proxy-timeout") && p[1])
	{
		struct http_proxy_options *ho;

		ho = init_http_proxy_options_once (&options->ce.http_proxy_options);
		ho->timeout = positive_atoi (p[1]);
	}
	else if (streq (p[0], "http-proxy-option") && p[1])
	{
		struct http_proxy_options *ho;

		ho = init_http_proxy_options_once (&options->ce.http_proxy_options);

		if (streq (p[1], "VERSION") && p[2])
		{
			ho->http_version = p[2];
		}
		else if (streq (p[1], "AGENT") && p[2])
		{
			ho->user_agent = p[2];
		}
		else
		{
			MM("Bad http-proxy-option or missing parameter: '%s'\n", p[1]);
		}
	}
#endif
#endif
#if 0
#ifdef ENABLE_SOCKS
	else if (streq (p[0], "socks-proxy") && p[1])
	{

		if (p[2])
		{
			int port;
			port = atoi (p[2]);
			if (!legal_ipv4_port (port))
			{
				MM("Bad socks-proxy port number: %s \n", p[2]);
				goto err;
			}
			options->ce.socks_proxy_port = port;
		}
		else
		{
			options->ce.socks_proxy_port = 1080;
		}
		options->ce.socks_proxy_server = p[1];
		options->ce.socks_proxy_authfile = p[3]; /* might be NULL */
	}
	else if (streq (p[0], "socks-proxy-retry"))
	{
		options->ce.socks_proxy_retry = true;
	}
#endif
#endif
	else if (streq (p[0], "keepalive") && p[1] && p[2])
	{
		options->keepalive_ping = atoi (p[1]);
		options->keepalive_timeout = atoi (p[2]);
	}
	else if (streq (p[0], "ping") && p[1])
	{
		options->ping_send_timeout = positive_atoi (p[1]);
	}
	else if (streq (p[0], "ping-exit") && p[1])
	{
		options->ping_rec_timeout = positive_atoi (p[1]);
		options->ping_rec_timeout_action = PING_EXIT;
	}
	else if (streq (p[0], "ping-restart") && p[1])
	{
		options->ping_rec_timeout = positive_atoi (p[1]);
		options->ping_rec_timeout_action = PING_RESTART;
	}
	else if (streq (p[0], "ping-timer-rem"))
	{
		options->ping_timer_remote = true;
	}
#if 0
#ifdef ENABLE_OCC
	else if (streq (p[0], "explicit-exit-notify"))
	{
		if (p[1])
		{
			options->ce.explicit_exit_notification = positive_atoi (p[1]);
		}
		else
		{
			options->ce.explicit_exit_notification = 1;
		}
	}
#endif
#endif
	else if (streq (p[0], "persist-tun"))
	{
		options->persist_tun = true;
	}
	else if (streq (p[0], "persist-key"))
	{
		options->persist_key = true;
	}
	else if (streq (p[0], "persist-local-ip"))
	{
		options->persist_local_ip = true;
	}
	else if (streq (p[0], "persist-remote-ip"))
	{
		options->persist_remote_ip = true;
	}
#if 0
#ifdef ENABLE_CLIENT_NAT
	else if (streq (p[0], "client-nat") && p[1] && p[2] && p[3] && p[4])
	{
		cnol_check_alloc (options);
		add_client_nat_to_option_list(options->client_nat, p[1], p[2], p[3], p[4]);
	}
#endif
#endif
	else if (streq (p[0], "route") && p[1])
	{
		rol_check_alloc (options);
		if (pull_mode)
		{
			if (!ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) && !is_special_addr (p[1]))
			{
				MM("route parameter network/IP '%s' must be a valid address \n", p[1]);
				goto err;
			}
			if (p[2] && !ip_addr_dotted_quad_safe (p[2]))
			{
				MM("route parameter netmask '%s' must be an IP address\n", p[2]);
				goto err;
			}
			if (p[3] && !ip_or_dns_addr_safe (p[3], options->allow_pull_fqdn) && !is_special_addr (p[3]))
			{
				MM("route parameter gateway '%s' must be a valid address\n", p[3]);
				goto err;
			}
		}
		add_route_to_option_list (options->routes, p[1], p[2], p[3], p[4]);
	}
	else if (streq (p[0], "route-ipv6") && p[1])
	{
		rol6_check_alloc (options);
		if (pull_mode)
		{
			if (!ipv6_addr_safe_hexplusbits (p[1]))
			{
				MM("route-ipv6 parameter network/IP '%s' must be a valid address\n", p[1]);
				goto err;
			}
			if (p[2] && !ipv6_addr_safe (p[2]))
			{
				MM("route-ipv6 parameter gateway '%s' must be a valid address\n", p[2]);
				goto err;
			}
		}
		add_route_ipv6_to_option_list (options->routes_ipv6, p[1], p[2], p[3]);
	}
	else if (streq (p[0], "max-routes") && p[1])
	{
		int max_routes;

		max_routes = atoi (p[1]);
		if (max_routes < 0 || max_routes > 100000000)
		{
			MM("--max-routes parameter is out of range\n");
			goto err;
		}
		if (options->routes || options->routes_ipv6)
		{
			MM("--max-routes must to be specifed before any route/route-ipv6/redirect-gateway option\n");
			goto err;
		}
		options->max_routes = max_routes;
	}
	else if (streq (p[0], "route-gateway") && p[1])
	{
		if (streq (p[1], "dhcp"))
		{
			options->route_gateway_via_dhcp = true;
		}
		else
		{
			if (ip_or_dns_addr_safe (p[1], options->allow_pull_fqdn) || is_special_addr (p[1]))
			{
				//options->route_default_gateway = p[1];
				sprintf(options->route_default_gateway,"%s",p[1]);
			}
			else
			{
				MM("route-gateway parm '%s' must be a valid address\n", p[1]);
				goto err;
			}
		}
	}
	else if (streq (p[0], "route-metric") && p[1])
	{
		options->route_default_metric = positive_atoi (p[1]);
	}
	else if (streq (p[0], "route-delay"))
	{
		options->route_delay_defined = true;
		if (p[1])
		{
			options->route_delay = positive_atoi (p[1]);
			if (p[2])
			{
				options->route_delay_window = positive_atoi (p[2]);
			}
		}
		else
		{
			options->route_delay = 0;
		}
	}
	else if (streq (p[0], "route-up") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->route_script, p[1], "route-up", false);
	}
	else if (streq (p[0], "route-pre-down") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->route_predown_script,p[1],"route-pre-down", true);  
	}
	else if (streq (p[0], "route-noexec"))
	{
		options->route_noexec = true;
	}
	else if (streq (p[0], "route-nopull"))
	{
		options->route_nopull = true;
	}
	else if (streq (p[0], "allow-pull-fqdn"))
	{
		options->allow_pull_fqdn = true;
	}
	else if (streq (p[0], "redirect-gateway") || streq (p[0], "redirect-private"))
	{
		int j;
		rol_check_alloc (options);
		if (streq (p[0], "redirect-gateway")){
			options->routes->flags |= RG_REROUTE_GW;
		}
		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j)
		{
			if (streq (p[j], "local")){
				options->routes->flags |= RG_LOCAL;
			}else if (streq (p[j], "autolocal")){
				options->routes->flags |= RG_AUTO_LOCAL;
			}else if (streq (p[j], "def1")){
				options->routes->flags |= RG_DEF1;
			}else if (streq (p[j], "bypass-dhcp")){
				options->routes->flags |= RG_BYPASS_DHCP;
			}else if (streq (p[j], "bypass-dns")){
				options->routes->flags |= RG_BYPASS_DNS;
			}else if (streq (p[j], "block-local")){
				options->routes->flags |= RG_BLOCK_LOCAL;
			}else{
				MM("unknown --%s flag: %s \n", p[0], p[j]);
				goto err;
			}
		}
		options->routes->flags |= RG_ENABLE;
	}
#if 0
	else if (streq (p[0], "remote-random-hostname"))
	{
		options->sockflags |= SF_HOST_RANDOMIZE;
	}
#endif
#if 0
	else if (streq (p[0], "setenv") && p[1])
	{
		if (streq (p[1], "REMOTE_RANDOM_HOSTNAME"))
		{
			options->sockflags |= SF_HOST_RANDOMIZE;
		}
		else if (streq (p[1], "GENERIC_CONFIG"))
		{
			MM("this is a generic configuration and cannot directly be used\n");
			goto err;
		}
		else if (streq (p[1], "PUSH_PEER_INFO"))
		{
			options->push_peer_info = true;
		}
		else if (streq (p[1], "SERVER_POLL_TIMEOUT") && p[2])
		{
			options->server_poll_timeout = positive_atoi(p[2]);
		}
		else
		{
			if (streq (p[1], "FORWARD_COMPATIBLE") && p[2] && streq (p[2], "1"))
			{
				options->forward_compatible = true;
			}
			setenv_str (es, p[1], p[2] ? p[2] : "");
		}
	}
	else if (streq (p[0], "setenv-safe") && p[1])
	{
		setenv_str_safe (es, p[1], p[2] ? p[2] : "");
	}
#endif
	else if (streq (p[0], "script-security") && p[1])
	{
		MM("### %s %d not support option %s ###\n",__func__,__LINE__,p[0]);
#if 0
		script_security = atoi (p[1]);
#endif
	}
	else if (streq (p[0], "mssfix"))
	{
		if (p[1])
		{
			options->ce.mssfix = positive_atoi (p[1]);
		}
		else
			options->ce.mssfix_default = true;

	}
#if 0
#ifdef ENABLE_OCC
	else if (streq (p[0], "disable-occ"))
	{
		options->occ = false;
	}
#endif
#endif
	else if (streq (p[0], "server") && p[1] && p[2])
	{
		bool error = false;
		in_addr_t network, netmask;

		network = get_ip_addr (p[1], &error);
		netmask = get_ip_addr (p[2], &error);
		if (error || !network || !netmask)
		{
			MM("error parsing --server parameters\n");
			goto err;
		}
		options->server_defined = true;
		options->server_network = network;
		options->server_netmask = netmask;


		if (p[3])
		{
			if (streq (p[3], "nopool")){
				options->server_flags |= SF_NOPOOL;
			}
			else
			{
				MM("error parsing --server: %s is not a recognized flag\n", p[3]);
				goto err;
			}
		}
	}
	else if (streq (p[0], "server-ipv6") && p[1] )
	{
		struct in6_addr network;
		unsigned int netbits = 0;

		if ( ! get_ipv6_addr (p[1], &network, &netbits, NULL) )
		{
			MM("error parsing --server-ipv6 parameter\n");
			goto err;
		}
		if ( netbits < 64 || netbits > 112 )
		{
			MM("--server-ipv6 settings: only /64../112 supported right now (not /%d)\n", netbits );
			goto err;
		}
		options->server_ipv6_defined = true;
		options->server_network_ipv6 = network;
		options->server_netbits_ipv6 = netbits;

		if (p[2])
		{
			MM("error parsing --server-ipv6: %s is not a recognized flag\n", p[3]);
			goto err;
		}
	}
	else if (streq (p[0], "server-bridge") && p[1] && p[2] && p[3] && p[4])
	{
		bool error = false;
		in_addr_t ip, netmask, pool_start, pool_end;

		ip = get_ip_addr (p[1], &error);
		netmask = get_ip_addr (p[2], &error);
		pool_start = get_ip_addr (p[3], &error);
		pool_end = get_ip_addr (p[4], &error);
		if (error || !ip || !netmask || !pool_start || !pool_end)
		{
			MM("error parsing --server-bridge parameters\n");
			goto err;
		}
		options->server_bridge_defined = true;
		options->server_bridge_ip = ip;
		options->server_bridge_netmask = netmask;
		options->server_bridge_pool_start = pool_start;
		options->server_bridge_pool_end = pool_end;

	}
	else if (streq (p[0], "server-bridge") && p[1] && streq (p[1], "nogw"))
	{
		options->server_bridge_proxy_dhcp = true;
		options->server_flags |= SF_NO_PUSH_ROUTE_GATEWAY;
	}
	else if (streq (p[0], "server-bridge") && !p[1])
	{
		options->server_bridge_proxy_dhcp = true;
	}
	else if (streq (p[0], "push") && p[1])
	{
		push_options (options, &p[1]);
	}
	else if (streq (p[0], "push-reset"))
	{
		push_reset (options);
	}
	else if (streq (p[0], "ifconfig-pool") && p[1] && p[2])
	{
		bool error = false;
		in_addr_t start, end, netmask=0;

		start = get_ip_addr (p[1], &error);
		end = get_ip_addr (p[2], &error);
		if (p[3])
		{
			netmask = get_ip_addr (p[3], &error);
		}
		if (error)
		{
			MM("error parsing --ifconfig-pool parameters\n");
			goto err;
		}
		if (!ifconfig_pool_verify_range (start, end)){
			goto err;
		}

		options->ifconfig_pool_defined = true;
		options->ifconfig_pool_start = start;
		options->ifconfig_pool_end = end;
		if (netmask){
			options->ifconfig_pool_netmask = netmask;
		}
	}
	else if (streq (p[0], "ifconfig-pool-persist") && p[1])
	{
		options->ifconfig_pool_persist_filename = p[1];
		if (p[2])
		{
			MM("## %s %d ifconfig_pool_persist_refresh_freq not support ##\n",__func__,__LINE__);
			options->ifconfig_pool_persist_refresh_freq = positive_atoi (p[2]);
		}
	}
	else if (streq (p[0], "ifconfig-pool-linear"))
	{
		options->topology = TOP_P2P;
	}
	else if (streq (p[0], "ifconfig-ipv6-pool") && p[1] )
	{
		struct in6_addr network;
		unsigned int netbits = 0;

		if ( ! get_ipv6_addr (p[1], &network, &netbits, NULL) )
		{
			MM("error parsing --ifconfig-ipv6-pool parameters\n");
			goto err;
		}
		if ( netbits < 64 || netbits > 112 )
		{
			MM("--ifconfig-ipv6-pool settings: only /64../112 supported right now (not /%d)\n", netbits );
			goto err;
		}

		options->ifconfig_ipv6_pool_defined = true;
		options->ifconfig_ipv6_pool_base = network;
		options->ifconfig_ipv6_pool_netbits = netbits;
	}
	else if (streq (p[0], "hash-size") && p[1] && p[2])
	{
		int real, virtual;

		real = atoi (p[1]);
		virtual = atoi (p[2]);
		if (real < 1 || virtual < 1)
		{
			MM("--hash-size sizes must be >= 1 (preferably a power of 2)\n");
			goto err;
		}
		options->real_hash_size = real;
		options->virtual_hash_size = real;
	}
	else if (streq (p[0], "connect-freq") && p[1] && p[2])
	{
		int cf_max, cf_per;

		cf_max = atoi (p[1]);
		cf_per = atoi (p[2]);
		if (cf_max < 0 || cf_per < 0)
		{
			MM( "--connect-freq parms must be > 0\n");
			goto err;
		}
		options->cf_max = cf_max;
		options->cf_per = cf_per;
	}
	else if (streq (p[0], "max-clients") && p[1])
	{
		int max_clients;

		max_clients = atoi (p[1]);
		if (max_clients < 0)
		{
			MM("--max-clients must be at least 1\n");
			goto err;
		}
		options->max_clients = max_clients;
	}
	else if (streq (p[0], "max-routes-per-client") && p[1])
	{
		if(atoi(p[1]) > 1){
			options->max_routes_per_client = atoi(p[1]);
		}else{
			options->max_routes_per_client = 1;
		}
	}
	else if (streq (p[0], "client-cert-not-required"))
	{
		options->ssl_flags |= SSLF_CLIENT_CERT_NOT_REQUIRED;
	}
	else if (streq (p[0], "username-as-common-name"))
	{
		options->ssl_flags |= SSLF_USERNAME_AS_COMMON_NAME;
	}
	else if (streq (p[0], "auth-user-pass-optional"))
	{
		options->ssl_flags |= SSLF_AUTH_USER_PASS_OPTIONAL;
	}
	else if (streq (p[0], "opt-verify"))
	{
		options->ssl_flags |= SSLF_OPT_VERIFY;
	}
	else if (streq (p[0], "auth-user-pass-verify") && p[1])
	{
		if (!no_more_than_n_args (p, 3, NM_QUOTE_HINT)){
			goto err;
		}
		if (p[2])
		{
			if (streq (p[2], "via-env")){
				options->auth_user_pass_verify_script_via_file = false;
			}else if (streq (p[2], "via-file")){
				options->auth_user_pass_verify_script_via_file = true;
			}else{
				MM("second parm to --auth-user-pass-verify must be 'via-env' or 'via-file'\n");
				goto err;
			}
		}
		else
		{
			MM("--auth-user-pass-verify requires a second parameter ('via-env' or 'via-file')\n");
			goto err;
		}
		set_user_script (options, &options->auth_user_pass_verify_script,p[1], "auth-user-pass-verify", true);
	}
	else if (streq (p[0], "client-connect") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->client_connect_script, p[1], "client-connect", true);
	}
	else if (streq (p[0], "client-disconnect") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->client_disconnect_script, p[1], "client-disconnect", true);
	}
	else if (streq (p[0], "learn-address") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->learn_address_script, p[1], "learn-address", true);
	}
	else if (streq (p[0], "tmp-dir") && p[1])
	{
		options->tmp_dir = p[1];
	}
	else if (streq (p[0], "client-config-dir") && p[1])
	{
		options->client_config_dir = p[1];
	}
	else if (streq (p[0], "ccd-exclusive"))
	{
		options->ccd_exclusive = true;
	}
	else if (streq (p[0], "bcast-buffers") && p[1])
	{
		int n_bcast_buf;

		n_bcast_buf = atoi (p[1]);
		if (n_bcast_buf < 1){
			MM("--bcast-buffers parameter must be > 0 \n");
		}
		options->n_bcast_buf = n_bcast_buf;
	}
	else if (streq (p[0], "tcp-queue-limit") && p[1])
	{
		int tcp_queue_limit;

		tcp_queue_limit = atoi (p[1]);
		if (tcp_queue_limit < 1){
			MM("--tcp-queue-limit parameter must be > 0\n");
		}
		options->tcp_queue_limit = tcp_queue_limit;
	}
#if 0
	else if (streq (p[0], "port-share") && p[1] && p[2])
	{
		int port;

		port = atoi (p[2]);
		if (!legal_ipv4_port (port))
		{
			MM("port number associated with --port-share directive is out of range\n");
			goto err;
		}

		options->port_share_host = p[1];
		options->port_share_port = port;
		options->port_share_journal_dir = p[3];
	}
#endif
	else if (streq (p[0], "client-to-client"))
	{
		options->enable_c2c = true;
	}
	else if (streq (p[0], "duplicate-cn"))
	{
		options->duplicate_cn = true;
	}
	else if (streq (p[0], "iroute") && p[1])
	{
		const char *netmask = NULL;

		if (p[2])
		{
			netmask = p[2];
		}
		if(epd != NULL){
			printf("############## %s %d %s %s ##########\n",__func__,__LINE__,p[0],p[1],p[2]);
			option_iroute (options, p[1], netmask,epd);
		}
	}
	else if (streq (p[0], "iroute-ipv6") && p[1])
	{
		option_iroute_ipv6 (options, p[1]);
	}
	else if (streq (p[0], "ifconfig-push") && p[1] && p[2])
	{
		in_addr_t local, remote_netmask;

		local = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
		remote_netmask = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[2], 0, NULL, NULL);
		if (local && remote_netmask)
		{
			options->push_ifconfig_defined = true;
			options->push_ifconfig_local = local;
			options->push_ifconfig_remote_netmask = remote_netmask;
#if 0
#ifdef ENABLE_CLIENT_NAT
			if (p[3])
				options->push_ifconfig_local_alias = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[3], 0, NULL, NULL);
#endif
#endif
		}
		else
		{
			MM("cannot parse --ifconfig-push addresses\n");
			goto err;
		}
	}
	else if (streq (p[0], "ifconfig-push-constraint") && p[1] && p[2])
	{
		in_addr_t network, netmask;

		network = getaddr (GETADDR_HOST_ORDER|GETADDR_RESOLVE, p[1], 0, NULL, NULL);
		netmask = getaddr (GETADDR_HOST_ORDER, p[2], 0, NULL, NULL);
		if (network && netmask)
		{
			options->push_ifconfig_constraint_defined = true;
			options->push_ifconfig_constraint_network = network;
			options->push_ifconfig_constraint_netmask = netmask;
		}
		else
		{
			MM("cannot parse --ifconfig-push-constraint addresses\n");
			goto err;
		}
	}
	else if (streq (p[0], "ifconfig-ipv6-push") && p[1] )
	{
		struct in6_addr local, remote;
		unsigned int netbits;


		if ( ! get_ipv6_addr( p[1], &local, &netbits, NULL) )
		{
			MM("cannot parse --ifconfig-ipv6-push addresses\n");
			goto err;
		}

		if ( p[2] )
		{
			if ( !get_ipv6_addr( p[2], &remote, NULL, NULL) )
			{
				MM("cannot parse --ifconfig-ipv6-push addresses");
				goto err;
			}
		}
		else
		{
			if ( ! options->ifconfig_ipv6_local ||  ! get_ipv6_addr( options->ifconfig_ipv6_local, &remote,NULL, NULL) )
			{
				MM("second argument to --ifconfig-ipv6-push missing and no global --ifconfig-ipv6 address set\n");
				goto err;
			}
		}

		options->push_ifconfig_ipv6_defined = true;
		options->push_ifconfig_ipv6_local = local;
		options->push_ifconfig_ipv6_netbits = netbits;
		options->push_ifconfig_ipv6_remote = remote;
	}
	else if (streq (p[0], "disable"))
	{
		options->disable = true;
	}
	else if (streq (p[0], "tcp-nodelay"))
	{
		options->server_flags |= SF_TCP_NODELAY_HELPER;
	}
	else if (streq (p[0], "stale-routes-check") && p[1])
	{
		int ageing_time, check_interval;

		ageing_time = atoi (p[1]);
		if (p[2]){
			check_interval = atoi (p[2]);
		}else{
			check_interval = ageing_time;
		}

		if (ageing_time < 1 || check_interval < 1)
		{
			MM("--stale-routes-check aging time and check interval must be >= 1\n");
			goto err;
		}
		options->stale_routes_ageing_time  = ageing_time;
		options->stale_routes_check_interval = check_interval;
	}
	else if (streq (p[0], "client"))
	{
		options->client = true;
	}
	else if (streq (p[0], "pull"))
	{
		options->pull = true;
	}
	else if (streq (p[0], "push-continuation") && p[1])
	{
		options->push_continuation = atoi(p[1]);
	}
	else if (streq (p[0], "server-poll-timeout") && p[1])
	{
		options->server_poll_timeout = positive_atoi(p[1]);
	}
	else if (streq (p[0], "auth-user-pass"))
	{
		if (p[1])
		{
			options->auth_user_pass_file = p[1];
		}
		else{
			options->auth_user_pass_file = "stdin";
		}
	}
	else if (streq (p[0], "auth-retry") && p[1])
	{
		auth_retry_set (p[1]);
	}
#if 0
	else if (streq (p[0], "static-challenge") && p[1] && p[2])
	{
		options->sc_info.challenge_text = p[1];
		if (atoi(p[2])){
			options->sc_info.flags |= SC_ECHO;
		}
	}
#endif
	else if (streq (p[0], "user") && p[1])
	{
		options->username = p[1];
	}
	else if (streq (p[0], "group") && p[1])
	{
		options->groupname = p[1];
	}
	else if (streq (p[0], "dhcp-option") && p[1])
	{
		foreign_option (options, p, 3);
	}
	else if (streq (p[0], "route-method") && p[1]) /* ignore when pushed to non-Windows OS */
	{
	}
#if 0
#if PASSTOS_CAPABILITY
	else if (streq (p[0], "passtos"))
	{
		options->passtos = true;
	}
#endif
#endif
#if 0
#ifdef ENABLE_LZO
	else if (streq (p[0], "comp-lzo"))
	{
		if (p[1])
		{
			if (streq (p[1], "yes"))
				options->lzo = LZO_SELECTED|LZO_ON;
			else if (streq (p[1], "no"))
				options->lzo = LZO_SELECTED;
			else if (streq (p[1], "adaptive"))
				options->lzo = LZO_SELECTED|LZO_ON|LZO_ADAPTIVE;
			else
			{
				MM("bad comp-lzo option: %s -- must be 'yes', 'no', or 'adaptive' \n", p[1]);
				goto err;
			}
		}
		else
			options->lzo = LZO_SELECTED|LZO_ON|LZO_ADAPTIVE;
	}
	else if (streq (p[0], "comp-noadapt"))
	{
		options->lzo &= ~LZO_ADAPTIVE;
	}
#endif /* ENABLE_LZO */
#endif
	else if (streq (p[0], "show-ciphers"))
	{
		options->show_ciphers = true;
	}
	else if (streq (p[0], "show-digests"))
	{
		options->show_digests = true;
	}
	else if (streq (p[0], "show-engines"))
	{
		options->show_engines = true;
	}
#if 0
	else if (streq (p[0], "key-direction") && p[1])
	{
		int key_direction;

		key_direction = ascii2keydirection (p[1]);
		if (key_direction >= 0){
			options->key_direction = key_direction;
		}else{
			goto err;
		}
	}
#endif
#if 0
	else if (streq (p[0], "secret") && p[1])
	{
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->shared_secret_file_inline = p[2];
		}
		else{
			if (p[2])
			{
				int key_direction;

				key_direction = ascii2keydirection (p[2]);
				if (key_direction >= 0){
					options->key_direction = key_direction;
				}else{
					goto err;
				}
			}
		}
		options->shared_secret_file = p[1];
	}
#endif
	else if (streq (p[0], "genkey"))
	{
		options->genkey = true;
	}
	else if (streq (p[0], "auth") && p[1])
	{
		options->authname_defined = true;
		options->authname = p[1];
		if (streq (options->authname, "none"))
		{
			options->authname_defined = false;
			options->authname = NULL;
		}
	}
	else if (streq (p[0], "auth"))
	{
		options->authname_defined = true;
	}
	else if (streq (p[0], "cipher") && p[1])
	{
		options->ciphername_defined = true;
		options->ciphername = p[1];
		if (streq (options->ciphername, "none"))
		{
			options->ciphername_defined = false;
			options->ciphername = NULL;
		}
	}
	else if (streq (p[0], "cipher"))
	{
		options->ciphername_defined = true;
	}
#if 0
	else if (streq (p[0], "prng") && p[1])
	{
		if (streq (p[1], "none")){
			options->prng_hash = NULL;
		}else{
			options->prng_hash = p[1];
		}
		if (p[2])
		{
			const int sl = atoi (p[2]);
			if (sl >= NONCE_SECRET_LEN_MIN && sl <= NONCE_SECRET_LEN_MAX)
			{
				options->prng_nonce_secret_len = sl;
			}
			else
			{
				MM("prng parameter nonce_secret_len must be between %d and %d \n", NONCE_SECRET_LEN_MIN, NONCE_SECRET_LEN_MAX);
				goto err;
			}
		}
	}
#endif
	else if (streq (p[0], "no-replay"))
	{
		options->replay = false;
	}
#if 0
	else if (streq (p[0], "replay-window"))
	{
		if (p[1])
		{
			int replay_window;

			replay_window = atoi (p[1]);
			if (!(MIN_SEQ_BACKTRACK <= replay_window && replay_window <= MAX_SEQ_BACKTRACK))
			{
				MM("replay-window window size parameter (%d) must be between %d and %d \n", replay_window,MIN_SEQ_BACKTRACK,MAX_SEQ_BACKTRACK);
				goto err;
			}
			options->replay_window = replay_window;

			if (p[2])
			{
				int replay_time;

				replay_time = atoi (p[2]);
				if (!(MIN_TIME_BACKTRACK <= replay_time && replay_time <= MAX_TIME_BACKTRACK))
				{
					MM("replay-window time window parameter (%d) must be between %d and %d\n",  replay_time,MIN_TIME_BACKTRACK,MAX_TIME_BACKTRACK);
					goto err;
				}
				options->replay_time = replay_time;
			}
		}
		else
		{
			MM("replay-window option is missing window size parameter\n");
			goto err;
		}
	}
#endif
	else if (streq (p[0], "mute-replay-warnings"))
	{
		options->mute_replay_warnings = true;
	}
	else if (streq (p[0], "no-iv"))
	{
		options->use_iv = false;
	}
	else if (streq (p[0], "replay-persist") && p[1])
	{
		options->packet_id_file = p[1];
	}
	else if (streq (p[0], "test-crypto"))
	{
		options->test_crypto = true;
	}
	else if (streq (p[0], "engine"))
	{
		if (p[1])
		{
			options->engine = p[1];
		}
		else{
			options->engine = "auto";
		}
	}  
	else if (streq (p[0], "keysize") && p[1])
	{
		int keysize;

		keysize = atoi (p[1]) / 8;
		if (keysize < 0 || keysize > MAX_CIPHER_KEY_LENGTH)
		{
			MM("Bad keysize: %s\n", p[1]);
			goto err;
		}
		options->keysize = keysize;
	}
	else if (streq (p[0], "use-prediction-resistance"))
	{
		options->use_prediction_resistance = true;
	}
	else if (streq (p[0], "show-tls"))
	{
		options->show_tls_ciphers = true;
	}
	else if (streq (p[0], "tls-server"))
	{
		options->tls_server = true;
		//options->mode = SERVER;
	}
	else if (streq (p[0], "tls-client"))
	{
		options->tls_client = true;
		//options->mode = CLIENT;
	}
	else if (streq (p[0], "ca") && p[1])
	{
		options->ca_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->ca_file_inline = p[2];
		}
	}
	else if (streq (p[0], "capath") && p[1])
	{
		options->ca_path = p[1];
	}
	else if (streq (p[0], "dh") && p[1])
	{
		options->dh_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->dh_file_inline = p[2];
		}
	}
	else if (streq (p[0], "cert") && p[1])
	{
		options->cert_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->cert_file_inline = p[2];
		}
	}
	else if (streq (p[0], "extra-certs") && p[1])
	{
		options->extra_certs_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->extra_certs_file_inline = p[2];
		}
	}
	else if (streq (p[0], "verify-hash") && p[1])
	{
		options->verify_hash = parse_hash_fingerprint(p[1], SHA_DIGEST_LENGTH);
	}
	else if (streq (p[0], "cryptoapicert") && p[1])
	{
		options->cryptoapi_cert = p[1];
	}
	else if (streq (p[0], "key") && p[1])
	{
		options->priv_key_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->priv_key_file_inline = p[2];
		}
	}
	else if (streq (p[0], "tls-version-min") && p[1])
	{
		int ver;
		ver = tls_version_min_parse(p[1], p[2]);
		if (ver == TLS_VER_BAD)
		{
			MM("unknown tls-version-min parameter: %s\n", p[1]);
			goto err;
		}
		options->ssl_flags &= ~(SSLF_TLS_VERSION_MASK << SSLF_TLS_VERSION_SHIFT);
		options->ssl_flags |= (ver << SSLF_TLS_VERSION_SHIFT);
	}
	else if (streq (p[0], "pkcs12") && p[1])
	{
		options->pkcs12_file = p[1];
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->pkcs12_file_inline = p[2];
		}
	}
	else if (streq (p[0], "askpass"))
	{
		if (p[1])
		{
			options->key_pass_file = p[1];
		}
		else{
			options->key_pass_file = "stdin";
		}
	}
	else if (streq (p[0], "auth-nocache"))
	{
		ssl_set_auth_nocache ();
	}
	else if (streq (p[0], "auth-token") && p[1])
	{
		ssl_set_auth_token(p[1]);
#ifdef ENABLE_MANAGEMENT
#if 0
		if (management)
			management_auth_token (management, p[1]);
#endif
#endif
	}
	else if (streq (p[0], "single-session"))
	{
		options->single_session = true;
	}
	else if (streq (p[0], "push-peer-info"))
	{
		options->push_peer_info = true;
	}
	else if (streq (p[0], "tls-exit"))
	{
		options->tls_exit = true;
	}
	else if (streq (p[0], "tls-cipher") && p[1])
	{
		options->cipher_list = p[1];
	}
	else if (streq (p[0], "crl-verify") && p[1])
	{
		if (p[2] && streq(p[2], "dir"))
			options->ssl_flags |= SSLF_CRL_VERIFY_DIR;
		options->crl_file = p[1];
	}
	else if (streq (p[0], "tls-verify") && p[1])
	{
		if (!no_more_than_n_args (p, 2, NM_QUOTE_HINT)){
			goto err;
		}
		set_user_script (options, &options->tls_verify, string_substitute (p[1], ',', ' '),"tls-verify", true);
	}
	else if (streq (p[0], "tls-export-cert") && p[1])
	{
		options->tls_export_cert = p[1];
	}
#if 0
	else if (streq (p[0], "compat-names"))
	{
		if (options->verify_x509_type != VERIFY_X509_NONE && options->verify_x509_type != TLS_REMOTE_SUBJECT_DN && options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
		{
			MM( "you cannot use --compat-names with --verify-x509-name\n");
			goto err;
		}
		MM("DEPRECATED OPTION: --compat-names, please update your configuration\n");
		compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);
		if (p[1] && streq (p[1], "no-remapping")){
			compat_flag (COMPAT_FLAG_SET | COMPAT_NO_NAME_REMAPPING);
		}
	}
#endif
#if 0
	else if (streq (p[0], "no-name-remapping"))
	{
		if (options->verify_x509_type != VERIFY_X509_NONE && options->verify_x509_type != TLS_REMOTE_SUBJECT_DN && options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
		{
			MM("you cannot use --no-name-remapping with --verify-x509-name\n");
			goto err;
		}
		MM("DEPRECATED OPTION: --no-name-remapping, please update your configuration\n");
		compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);
		compat_flag (COMPAT_FLAG_SET | COMPAT_NO_NAME_REMAPPING);
	}
#endif
#if 0
	else if (streq (p[0], "tls-remote") && p[1])
	{

		if (options->verify_x509_type != VERIFY_X509_NONE && options->verify_x509_type != TLS_REMOTE_SUBJECT_DN && options->verify_x509_type != TLS_REMOTE_SUBJECT_RDN_PREFIX)
		{
			MM("you cannot use --tls-remote with --verify-x509-name\n");
			goto err;
		}
		MM("DEPRECATED OPTION: --tls-remote, please update your configuration\n");

		if (strlen (p[1]))
		{
			int is_username = (!strchr (p[1], '=') || !strstr (p[1], ", "));
			int type = TLS_REMOTE_SUBJECT_DN;
			if (p[1][0] != '/' && is_username){
				type = TLS_REMOTE_SUBJECT_RDN_PREFIX;
			}

			if (p[1][0] == '/' || is_username){
				compat_flag (COMPAT_FLAG_SET | COMPAT_NAMES);
			}

			options->verify_x509_type = type;
			options->verify_x509_name = p[1];
		}
	}
#endif
#if 0
	else if (streq (p[0], "verify-x509-name") && p[1] && strlen (p[1]))
	{
		int type = VERIFY_X509_SUBJECT_DN;
		if (options->verify_x509_type == TLS_REMOTE_SUBJECT_DN || options->verify_x509_type == TLS_REMOTE_SUBJECT_RDN_PREFIX)
		{
			MM("you cannot use --verify-x509-name with --tls-remote\n");
			goto err;
		}
		if (compat_flag (COMPAT_FLAG_QUERY | COMPAT_NAMES))
		{
			MM("you cannot use --verify-x509-name with --compat-names or --no-name-remapping\n");
			goto err;
		}
		if (p[2])
		{
			if (streq (p[2], "subject")){
				type = VERIFY_X509_SUBJECT_DN;
			}else if (streq (p[2], "name")){
				type = VERIFY_X509_SUBJECT_RDN;
			}else if (streq (p[2], "name-prefix")){
				type = VERIFY_X509_SUBJECT_RDN_PREFIX;
			}else{
				MM("unknown X.509 name type: %s\n", p[2]);
				goto err;
			}
		}
		options->verify_x509_type = type;
		options->verify_x509_name = p[1];
	}
#endif
	else if (streq (p[0], "ns-cert-type") && p[1])
	{
		if (streq (p[1], "server")){
			options->ns_cert_type = NS_CERT_CHECK_SERVER;
		}else if (streq (p[1], "client")){
			options->ns_cert_type = NS_CERT_CHECK_CLIENT;
		}else{
			MM("--ns-cert-type must be 'client' or 'server'");
			goto err;
		}
	}
	else if (streq (p[0], "remote-cert-ku"))
	{
		int j;

		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j){
			sscanf (p[j], "%x", &(options->remote_cert_ku[j-1]));
		}
	}
	else if (streq (p[0], "remote-cert-eku") && p[1])
	{
		options->remote_cert_eku = p[1];
	}
	else if (streq (p[0], "remote-cert-tls") && p[1])
	{

		if (streq (p[1], "server"))
		{
			options->remote_cert_ku[0] = 0xa0;
			options->remote_cert_ku[1] = 0x88;
			options->remote_cert_eku = "TLS Web Server Authentication";
		}
		else if (streq (p[1], "client"))
		{
			options->remote_cert_ku[0] = 0x80;
			options->remote_cert_ku[1] = 0x08;
			options->remote_cert_ku[2] = 0x88;
			options->remote_cert_eku = "TLS Web Client Authentication";
		}
		else
		{
			MM("--remote-cert-tls must be 'client' or 'server'\n");
			goto err;
		}
	}
	else if (streq (p[0], "tls-timeout") && p[1])
	{
		options->tls_timeout = positive_atoi (p[1]);
	}
	else if (streq (p[0], "reneg-bytes") && p[1])
	{
		options->renegotiate_bytes = positive_atoi (p[1]);
	}
	else if (streq (p[0], "reneg-pkts") && p[1])
	{
		options->renegotiate_packets = positive_atoi (p[1]);
	}
	else if (streq (p[0], "reneg-sec") && p[1])
	{
		options->renegotiate_seconds = positive_atoi (p[1]);
	}
	else if (streq (p[0], "hand-window") && p[1])
	{
		options->handshake_window = positive_atoi (p[1]);
	}
	else if (streq (p[0], "tran-window") && p[1])
	{
		options->transition_window = positive_atoi (p[1]);
	}
#if 0
	else if (streq (p[0], "tls-auth") && p[1])
	{
		if (streq (p[1], INLINE_FILE_TAG) && p[2])
		{
			options->tls_auth_file_inline = p[2];
		}
		else{
			if (p[2])
			{
				int key_direction;

				key_direction = ascii2keydirection (p[2]);
				if (key_direction >= 0){
					options->key_direction = key_direction;
				}else{
					goto err;
				}
			}
		}
		options->tls_auth_file = p[1];
	}
#endif
	else if (streq (p[0], "key-method") && p[1])
	{
		int key_method;

		key_method = atoi (p[1]);
		if (key_method < KEY_METHOD_MIN || key_method > KEY_METHOD_MAX)
		{
			MM("## ERR: key_method parameter (%d) must be >= %d and <= %d",
					key_method,
					KEY_METHOD_MIN,
					KEY_METHOD_MAX);
			goto err;
		}
		options->key_method = key_method;
	}
	else if (streq (p[0], "x509-username-field") && p[1])
	{
		char *s = p[1];
		if( strncmp ("ext:",s,4) != 0 ){
			while ((*s = toupper(*s)) != '\0'){
				 s++;
			}
		}
		options->x509_username_field = p[1];
	}
#if 0
	else if (streq (p[0], "show-pkcs11-ids") && p[1])
	{
		char *provider =  p[1];
		bool cert_private = (p[2] == NULL ? false : ( atoi (p[2]) != 0 ));

		show_pkcs11_ids (provider, cert_private);
		//openvpn_exit (OPENVPN_EXIT_STATUS_GOOD);
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-providers") && p[1])
	{
		int j;

		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j){
			options->pkcs11_providers[j-1] = p[j];
		}
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-protected-authentication"))
	{
		int j;


		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j){
			options->pkcs11_protected_authentication[j-1] = atoi (p[j]) != 0 ? 1 : 0;
		}
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-private-mode") && p[1])
	{
		int j;


		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j){
			sscanf (p[j], "%x", &(options->pkcs11_private_mode[j-1]));
		}
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-cert-private"))
	{
		int j;


		for (j = 1; j < MAX_PARMS && p[j] != NULL; ++j){
			options->pkcs11_cert_private[j-1] = atoi (p[j]) != 0 ? 1 : 0;
		}
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-pin-cache") && p[1])
	{
		options->pkcs11_pin_cache_period = atoi (p[1]);
	}
#endif
#if 0
	else if (streq (p[0], "pkcs11-id") && p[1])
	{
		options->pkcs11_id = p[1];
	}
#endif
	else if (streq (p[0], "pkcs11-id-management"))
	{
		options->pkcs11_id_management = true;
	}
	else if (streq (p[0], "rmtun"))
	{
		options->persist_config = true;
		options->persist_mode = 0;
	}
	else if (streq (p[0], "mktun"))
	{
		options->persist_config = true;
		options->persist_mode = 1;
	}
	else
	{
		int i;
		for(i=0; options->ignore_unknown_option && options->ignore_unknown_option[i]; i++)
		{
			if (streq(p[0], options->ignore_unknown_option[i]))
			{
				break;
			}
		}
		if (file){
			MM("ERR: Unrecognized option or missing parameter(s) in %s:%d: %s (%s)\n", file, line, p[0], PACKAGE_VERSION);
		}else{
			MM("ERR: Unrecognized option or missing parameter(s): --%s (%s)\n", p[0], PACKAGE_VERSION);
		}
	}
err:
	return;
}

