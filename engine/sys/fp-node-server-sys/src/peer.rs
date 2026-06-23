pub struct Peer {
    pub inner: Option<fp_node_core::PeerInner>,
    allowed_ips: fp_node_core::IpTable<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            tracing::warn!("drop peer sender");
            tokio::task::spawn(async move { inner.close(None).await });
        }
    }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut res = String::new();
        for (_, ip, mask) in self.allowed_ips.iter() {
            res.push_str(format!("ip: {ip:?}, mask: {mask}").as_str());
        }
        f.debug_struct("").field("allowed_ips", &res).finish()
    }
}

impl Peer {
    #[allow(unused)]
    pub fn new(allowed_ips: &[fp_node_core::AllowedIP]) -> Peer {
        Peer {
            inner: None,
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
        }
    }
}
