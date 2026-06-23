#[derive(Debug, Clone)]
pub struct AssignInterfaceReq {
    pub name: String,
    pub num: u16,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub fd: Option<i32>,
    #[cfg(target_os = "windows")]
    pub path: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ClientStartReq {
    pub client_prikey: String,
    pub node_pubkey: String,
    pub node_addr: String,
    pub node_port: u16,
    pub tls: Option<String>,
    pub transport_protocol: String,
    pub crypto_protocol: String,
    pub iface_ipv4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface_ipv6: Option<String>,
    pub timeout: Option<std::time::Duration>,
    #[serde(skip)]
    #[cfg(target_os = "windows")]
    pub path: Option<String>,
    #[serde(skip)]
    pub fd: Option<i32>,
    #[serde(skip)]
    pub on_connected_callback: Option<fp_node_core::TransportCallback>,
    #[serde(skip)]
    pub on_closed_callback: fp_node_core::TransportCallback,
}

impl ClientStartReq {
    pub(crate) fn split(self) -> Result<(TransportConfig, AssignInterfaceReq), fp_node_core::Error> {
        let Self {
            client_prikey,
            node_pubkey,
            node_addr,
            node_port,
            transport_protocol,
            crypto_protocol,
            iface_ipv4,
            iface_ipv6,
            #[cfg(target_os = "windows")]
            path,
            fd,
            on_connected_callback,
            on_closed_callback,
            timeout,
            tls,
            ..
        } = self;

        let assign_interface_req = AssignInterfaceReq {
            name: "utun".to_string(),
            num: 100,
            ipv4: iface_ipv4,
            ipv6: iface_ipv6,
            #[cfg(target_os = "windows")]
            path,
            fd,
        };

        let port = node_port;
        let timeout = timeout.unwrap_or(tokio::time::Duration::from_secs(5));
        let endpoint = node_addr
            .parse()
            .map_err(|_e| fp_node_core::Error::TransportError("invalid endpoint".to_string()))?;
        let own_prikey = fp_node_core::key::gen_prikey_with_str(client_prikey.as_str())?;

        let bytes = hex::decode(node_pubkey)
            .map_err(|_e| fp_node_core::Error::TransportError("Invalid hex string".to_string()))?;
        let mut node_pubkey_bytes: [u8; 32] = [0; 32];
        node_pubkey_bytes.copy_from_slice(&bytes[..32]);
        let node_pubkey = fp_node_core::x25519::PublicKey::from(node_pubkey_bytes);

        Ok((
            TransportConfig {
                transport_protocol,
                crypto_protocol,
                endpoint,
                port,
                tls,
                timeout,
                own_prikey,
                node_pubkey,
                on_connected_callback,
                on_closed_callback,
            },
            assign_interface_req,
        ))
    }
}

pub(crate) struct TransportConfig {
    pub(crate) transport_protocol: String,
    pub(crate) crypto_protocol: String,
    pub(crate) endpoint: std::net::IpAddr,
    pub(crate) port: u16,
    pub(crate) tls: Option<String>,
    pub(crate) timeout: std::time::Duration,
    pub(crate) own_prikey: fp_node_core::x25519::StaticSecret,
    pub(crate) node_pubkey: fp_node_core::x25519::PublicKey,
    pub(crate) on_connected_callback: Option<fp_node_core::TransportCallback>,
    pub(crate) on_closed_callback: fp_node_core::TransportCallback,
}

impl TransportConfig {
    pub(crate) fn gen_rf_transport_config(&self) -> fp_transport::Config {
        fp_transport::Config {
            endpoint: self.endpoint,
            port: self.port,
            tls: self.tls.clone(),
            timeout: self.timeout,
        }
    }
}
