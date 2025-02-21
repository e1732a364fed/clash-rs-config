#[cfg(test)]
mod tests;

use educe::Educe;
use std::{collections::HashMap, fmt::Display, path::PathBuf, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};
pub use serde_yml as serde_yaml;
use serde_yml::Value;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum Error {
    // #[error(transparent)]
    #[error("loading config io err: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid BindAddress: {0}")]
    InvalidBindAddress(String),
}

/// Example
/// ```yaml
/// ---
/// port: 8888
/// socks-port: 8889
/// mixed-port: 8899
///
/// tun:
///   enable: false
///   device-id: "dev://utun1989"
///
/// dns:
///   enable: true
///   listen: 127.0.0.1:53553
///   #   udp: 127.0.0.1:53553
///   #   tcp: 127.0.0.1:53553
///   #   dot: 127.0.0.1:53554
///   #   doh: 127.0.0.1:53555
///
///   # ipv6: false # when the false, response to AAAA questions will be empty
///
///   # These nameservers are used to resolve the DNS nameserver hostnames
/// below.   # Specify IP addresses only
///   default-nameserver:
///     - 114.114.114.114
///     - 8.8.8.8
///   enhanced-mode: fake-ip
///   fake-ip-range: 198.18.0.2/16 # Fake IP addresses pool CIDR
///   # use-hosts: true # lookup hosts and return IP record
///
///   # Hostnames in this list will not be resolved with fake IPs
///   # i.e. questions to these domain names will always be answered with their
///   # real IP addresses
///   # fake-ip-filter:
///   #   - '*.lan'
///   #   - localhost.ptlogin2.qq.com
///
///   # Supports UDP, TCP, DoT, DoH. You can specify the port to connect to.
///   # All DNS questions are sent directly to the nameserver, without proxies
///   # involved. Clash answers the DNS question with the first result gathered.
///   nameserver:
///     - 114.114.114.114 # default value
///     - 1.1.1.1 # default value
///     - tls://1.1.1.1:853 # DNS over TLS
///     - https://1.1.1.1/dns-query # DNS over HTTPS
/// #    - dhcp://en0 # dns from dhcp
///
/// allow-lan: true
/// mode: rule
/// log-level: debug
/// external-controller: 127.0.0.1:9090
/// external-ui: "public"
/// # secret: "clash-rs"
/// experimental:
///   ignore-resolve-fail: true
///
/// profile:
///   store-selected: true
///   store-fake-ip: false
///
/// proxy-groups:
///   - name: "relay" type: relay proxies:
///       - "plain-vmess"
///       - "ws-vmess"
///       - "auto"
///       - "fallback-auto"
///       - "load-balance"
///       - "select"
///       - DIRECT
///
///   - name: "relay-one" type: relay use:
///       - "file-provider"
///
///   - name: "auto" type: url-test use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: "fallback-auto" type: fallback use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: "load-balance" type: load-balance use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///     strategy: round-robin
///     url: "http://www.gstatic.com/generate_204"
///     interval: 300
///
///   - name: select type: select use:
///       - "file-provider"
///
///   - name: test 🌏 type: select use:
///       - "file-provider"
///     proxies:
///       - DIRECT
///
/// proxies:
///   - name: plain-vmess type: vmess server: 10.0.0.13 port: 16823 uuid:
///     b831381d-6324-4d53-ad4f-8cda48b30811 alterId: 0 cipher: auto udp: true
///     skip-cert-verify: true
///   - name: ws-vmess type: vmess server: 10.0.0.13 port: 16824 uuid:
///     b831381d-6324-4d53-ad4f-8cda48b30811 alterId: 0 cipher: auto udp: true
///     skip-cert-verify: true network: ws ws-opts: path:
///     /api/v3/download.getFile headers: Host: www.amazon.com
///
///   - name: tls-vmess type: vmess server: 10.0.0.13 port: 8443 uuid:
///     23ad6b10-8d1a-40f7-8ad0-e3e35cd38297 alterId: 0 cipher: auto udp: true
///     skip-cert-verify: true tls: true
///
///   - name: h2-vmess type: vmess server: 10.0.0.13 port: 8444 uuid:
///     b831381d-6324-4d53-ad4f-8cda48b30811 alterId: 0 cipher: auto udp: true
///     skip-cert-verify: true tls: true network: h2 h2-opts: path: /ray
///
///   - name: vmess-altid type: vmess server: tw-1.ac.laowanxiang.com port: 153
///     uuid: 46dd0dd3-2cc0-3f55-907c-d94e54877687 alterId: 64 cipher: auto udp:
///     true network: ws ws-opts: path: /api/v3/download.getFile headers: Host:
///     5607b9d187e655736f563fee87d7283994721.laowanxiang.com
///   - name: "ss-simple" type: ss server: 10.0.0.13 port: 8388 cipher:
///     aes-256-gcm password: "password" udp: true
///   - name: "trojan" type: trojan server: 10.0.0.13 port: 9443 password:
///     password1 udp: true # sni: example.com # aka server name alpn:
///       - h2
///       - http/1.1
///     skip-cert-verify: true
///
/// proxy-providers:
///   file-provider:
///     type: file
///     path: ./ss.yaml
///     interval: 300
///     health-check:
///       enable: true
///       url: http://www.gstatic.com/generate_204
///       interval: 300
///
/// rule-providers:
///   file-provider:
///     type: file
///     path: ./rule-set.yaml
///     interval: 300
///     behavior: domain
///
/// rules:
///   - DOMAIN,ipinfo.io,relay
///   - RULE-SET,file-provider,trojan
///   - GEOIP,CN,relay
///   - DOMAIN-SUFFIX,facebook.com,REJECT
///   - DOMAIN-KEYWORD,google,select
///   - DOMAIN,google.com,select
///   - SRC-IP-CIDR,192.168.1.1/24,DIRECT
///   - GEOIP,CN,DIRECT
///   - DST-PORT,53,trojan
///   - SRC-PORT,7777,DIRECT
///   - MATCH, DIRECT
/// ...
/// ```
#[derive(Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct Config {
    /// The HTTP proxy port
    #[serde(alias = "http_port")]
    pub port: Option<Port>,
    /// The SOCKS5 proxy port
    pub socks_port: Option<Port>,
    /// The redir port
    #[doc(hidden)]
    pub redir_port: Option<Port>,
    pub tproxy_port: Option<Port>,
    /// The HTTP/SOCKS5 mixed proxy port
    /// # Example
    /// ```yaml
    /// mixed-port: 7892
    /// ```
    pub mixed_port: Option<Port>,

    /// HTTP and SOCKS5 proxy authentication
    pub authentication: Vec<String>,
    /// Allow connections to the local-end server from other LAN IP addresses
    /// Deprecated see `bind_address`
    pub allow_lan: Option<bool>,
    /// The address that the inbound listens on
    /// # Note
    /// - setting this to `*` will listen on all interfaces, which is
    ///   essentially the same as setting it to `0.0.0.0`
    /// - setting this to non local IP will enable `allow_lan` automatically
    /// - and if you don't want `allow_lan` to be enabled, you should set this
    ///   to `localhost` or `127.1`
    pub bind_address: BindAddress,
    /// Clash router working mode
    /// Either `rule`, `global` or `direct`
    pub mode: RunMode,
    /// Log level
    /// Either `debug`, `info`, `warning`, `error` or `off`
    pub log_level: LogLevel,
    /// DNS client/server settings
    pub dns: DNS,
    /// Profile settings
    pub profile: Profile,
    /// Proxy settings
    pub proxies: Option<Vec<HashMap<String, Value>>>,
    /// Proxy group settings
    pub proxy_groups: Option<Vec<HashMap<String, Value>>>,
    /// Rule settings
    pub rules: Option<Vec<String>>,
    /// Hosts
    pub hosts: HashMap<String, String>,
    /// Country database path relative to the $CWD
    #[educe(Default = "Country.mmdb")]
    pub mmdb: String,
    /// Country database download url
    // TODO not compatiable with clash-meta
    #[educe(Default = Some("https://github.com/Loyalsoldier/geoip/releases/download/202307271745/Country.mmdb".into()))]
    pub mmdb_download_url: Option<String>,
    /// Optional ASN database path relative to the working dir
    #[educe(Default = "Country-asn.mmdb")]
    pub asn_mmdb: String,
    /// Optional ASN database download url
    pub asn_mmdb_download_url: Option<String>,
    /// Geosite database path relative to the $CWD
    #[educe(Default = "geosite.dat")]
    pub geosite: String,
    /// Geosite database download url
    #[educe(Default = Some("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202406182210/geosite.dat".into()))]
    pub geosite_download_url: Option<String>,

    // these options has default vals,
    // and needs extra processing
    /// whether your network environment supports IPv6
    /// this will affect the DNS server response to AAAA questions
    /// default is `false`
    pub ipv6: bool,
    /// external controller address
    pub external_controller: Option<String>,
    /// dashboard folder path relative to the $CWD
    pub external_ui: Option<String>,
    /// external controller secret
    pub secret: Option<String>,
    /// outbound interface name
    pub interface_name: Option<String>,
    /// fwmark on Linux only
    pub routing_mask: Option<u32>,
    /// proxy provider settings
    pub proxy_providers: Option<HashMap<String, HashMap<String, Value>>>,
    /// rule provider settings
    pub rule_providers: Option<HashMap<String, HashMap<String, Value>>>,
    /// experimental settings, if any
    pub experimental: Option<Experimental>,

    /// tun settings
    /// # Example
    /// ```yaml
    /// tun:
    ///   enable: true
    ///   device-id: "dev://utun1989"
    /// ```
    pub tun: Option<TunConfig>,

    pub listeners: Option<Vec<HashMap<String, Value>>>,
}

impl TryFrom<PathBuf> for Config {
    type Error = Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        let content = std::fs::read_to_string(value)?;
        let config = content.parse::<Config>()?;
        Ok(config)
    }
}

impl FromStr for Config {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut val: Value = serde_yaml::from_str(s).map_err(|e| {
            Error::InvalidConfig(format!("couldn't not parse config content {s}: {e}"))
        })?;

        val.apply_merge().map_err(|e| {
            Error::InvalidConfig(format!(
                "failed to process anchors in config content {s}: {e}"
            ))
        })?;

        serde_yaml::from_value(val).map_err(|e| {
            Error::InvalidConfig(format!("counldn't not parse config content {s}: {e}"))
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum DNSListen {
    Udp(String),
    Multiple(HashMap<String, Value>),
}

/// DNS client/server settings
/// This section is optional. When not present, the DNS server will be disabled
/// and system DNS config will be used # Example
/// ```yaml
/// dns:
///   enable: true
///   ipv6: false # when the false, response to AAAA questions will be empty
///   listen:
///     udp: 127.0.0.1:53553
///     tcp: 127.0.0.1:53553
///     dot:
///       addr: 127.0.0.1:53554
///       hostname: dns.clash
///       ca-cert: dns.crt
///       ca-key: dns.key
///     doh:
///       addr: 127.0.0.1:53555
///       ca-cert: dns.crt
///       ca-key: dns.key
/// ```

#[derive(Serialize, Deserialize, Educe)]
#[serde(rename_all = "kebab-case", default)]
#[educe(Default)]
pub struct DNS {
    /// When disabled, system DNS config will be used
    /// All other DNS related options will only be used when this is enabled
    pub enable: bool,
    /// When false, response to AAAA questions will be empty
    pub ipv6: bool,
    /// Whether to `Config::hosts` as when resolving hostnames
    #[educe(Default = true)]
    pub user_hosts: bool,
    /// DNS servers
    pub nameserver: Vec<String>,
    /// Fallback DNS servers
    pub fallback: Vec<String>,
    /// Fallback DNS filter
    pub fallback_filter: FallbackFilter,
    /// DNS server listening address. If not present, the DNS server will be
    /// disabled.
    pub listen: Option<DNSListen>,
    /// Whether to use fake IP addresses
    pub enhanced_mode: DNSMode,
    /// Fake IP addresses pool CIDR
    #[educe(Default = "198.18.0.1/16")]
    pub fake_ip_range: String,
    /// Fake IP addresses filter
    pub fake_ip_filter: Vec<String>,
    /// Default nameservers, used to resolve DoH hostnames
    #[educe(Default = vec![
      String::from("114.114.114.114"),
      String::from("8.8.8.8")]
    )]
    pub default_nameserver: Vec<String>,
    /// Lookup domains via specific nameservers
    pub nameserver_policy: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum DNSMode {
    #[default]
    Normal,
    FakeIp,
    RedirHost,
}

#[derive(Serialize, Deserialize, Clone, Educe)]
#[serde(default)]
#[educe(Default)]
pub struct FallbackFilter {
    #[educe(Default = true)]
    pub geoip: bool,

    #[educe(Default = "CN")]
    pub geoip_code: String,

    pub ipcidr: Vec<String>,
    pub domain: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Experimental {
    /// buffer size for tcp stream bidirectional copy
    pub tcp_buffer_size: Option<usize>,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
#[serde(rename_all = "kebab-case")]
pub struct Profile {
    /// Store the `select` results in $CWD/cache.db
    pub store_selected: bool,
    /// persistence fakeip
    pub store_fake_ip: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            store_selected: true,
            store_fake_ip: false,
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Copy)]
pub struct Port(pub u16);

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StrOrNum {
            Str(String),
            Num(u64),
            Other,
        }

        let value = StrOrNum::deserialize(deserializer)?;

        match value {
            StrOrNum::Num(num) => u16::try_from(num)
                .map(Port)
                .map_err(|_| serde::de::Error::custom("Port number out of range")),

            StrOrNum::Str(s) => s.parse::<u16>().map(Port).map_err(serde::de::Error::custom),

            StrOrNum::Other => Err(serde::de::Error::custom("Invalid type for port")),
        }
    }
}

fn default_tun_address() -> String {
    "198.18.0.1/32".to_string()
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsHijack {
    Switch(bool),
    List(Vec<String>),
}

impl Default for DnsHijack {
    fn default() -> Self {
        DnsHijack::Switch(false)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TunConfig {
    pub enable: bool,
    #[serde(alias = "device-url")]
    pub device_id: String,
    /// tun interface address
    #[serde(default = "default_tun_address")]
    pub gateway: String,
    pub routes: Option<Vec<String>>,
    #[serde(default)]
    pub route_all: bool,
    pub mtu: Option<u16>,
    /// fwmark on Linux only
    pub so_mark: Option<u32>,
    /// policy routing table on Linux only
    pub route_table: Option<u32>,
    /// Will hijack UDP:53 DNS queries to the Clash DNS server if set to true
    /// setting to a list has the same effect as setting to true
    #[serde(default)]
    pub dns_hijack: DnsHijack,
}

#[derive(Serialize, Deserialize, Default, Copy, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RunMode {
    #[serde(alias = "Global")]
    Global,
    #[default]
    #[serde(alias = "Rule")]
    Rule,
    #[serde(alias = "Direct")]
    Direct,
}

impl Display for RunMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunMode::Global => write!(f, "global"),
            RunMode::Rule => write!(f, "rule"),
            RunMode::Direct => write!(f, "direct"),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Default, Copy, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    #[serde(alias = "off")]
    Silent,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warning => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Silent => write!(f, "off"),
        }
    }
}

use std::net::{IpAddr, Ipv4Addr};

// use ipnet::IpNet;

#[derive(Serialize, Clone, Debug, Copy, PartialEq)]
#[serde(transparent)]
pub struct BindAddress(pub IpAddr);
impl BindAddress {
    pub fn all() -> Self {
        Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    pub fn local() -> Self {
        Self(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }
}
impl Default for BindAddress {
    fn default() -> Self {
        Self::local()
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        match str.as_str() {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "Invalid BindAddress value {str}"
                    )))
                }
            }
        }
    }
}

impl FromStr for BindAddress {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        match str {
            "*" => Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            "localhost" => Ok(Self(IpAddr::from([127, 0, 0, 1]))),
            _ => {
                if let Ok(ip) = str.parse::<IpAddr>() {
                    Ok(Self(ip))
                } else {
                    Err(Error::InvalidBindAddress(str.to_string()))
                }
            }
        }
    }
}
