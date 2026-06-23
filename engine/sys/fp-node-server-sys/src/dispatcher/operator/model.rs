#[derive(Debug, Clone)]
pub struct AssignInterfaceReq {
    pub name: String,
    pub num: u16,
    pub ipv4: String,
    pub ipv6: String,
    pub fd: Option<i32>,
    #[cfg(target_os = "windows")]
    pub path: Option<String>,
}

#[derive(Clone)]
pub struct ServerStartReq {
    pub set_key_req: Option<SetKeyReq>,
    pub assign_interface_req: AssignInterfaceReq,
}

#[derive(Clone)]
pub struct SetKeyReq {
    pub prikey: fp_node_core::x25519::StaticSecret,
}

#[derive(Debug, Clone)]
pub struct AddListenerReq {
    pub transport_protocol: Option<String>,
    pub crypto_protocol: Option<String>,
    pub port: u16,
    pub tls: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddPeerReq {
    pub port: u16,
    pub transport_protocol: Option<String>,
    pub crypto_protocol: Option<String>,
    pub pkey: fp_node_core::x25519::PublicKey,
    pub allowed_ips: Vec<fp_node_core::AllowedIP>,
}
