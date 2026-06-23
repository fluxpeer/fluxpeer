use std::{future::Future, pin::Pin};

type BindResponse = Pin<Box<dyn Future<Output = Result<Box<dyn crate::Listener>, crate::Error>> + Send>>;
type ConnectResponse = Pin<Box<dyn Future<Output = Result<crate::SenderAndReceiver, crate::Error>> + Send>>;

pub struct RawConnector {
    vtable: &'static VTable,
}

unsafe impl Send for RawConnector {}

unsafe impl Sync for RawConnector {}

impl RawConnector {
    pub fn new<C: crate::Connector>() -> Self {
        let vtable = &VTable {
            bind: |config: crate::Config| -> BindResponse { C::bind(config) },
            connect: |config: crate::Config| -> ConnectResponse { C::connect(config) },
        };

        Self { vtable }
    }

    pub fn bind(&self, config: crate::Config) -> BindResponse {
        (self.vtable.bind)(config)
    }

    pub fn connect(&self, config: crate::Config) -> ConnectResponse {
        (self.vtable.connect)(config)
    }
}

impl Clone for RawConnector {
    fn clone(&self) -> Self {
        Self { vtable: self.vtable }
    }
}

struct VTable {
    bind: fn(crate::Config) -> BindResponse,
    connect: fn(crate::Config) -> ConnectResponse,
}

#[cfg(test)]
mod test {
    use crate::*;

    fn gen_cfg() -> Config {
        Config {
            endpoint: std::net::IpAddr::from([0, 0, 0, 0]),
            port: 0,
            tls: None,
            timeout: std::time::Duration::from_secs(1),
        }
    }

    #[derive(Debug)]
    struct Co1 {}

    #[async_trait::async_trait]
    impl Connector for Co1 {
        async fn bind(_config: crate::Config) -> Result<Box<dyn Listener>, crate::Error> {
            println!("Connector Co1 bind");

            Ok(Box::new(L1 {}))
        }

        async fn connect(_config: Config) -> Result<crate::SenderAndReceiver, crate::Error> {
            println!("Connector Co1 connect");

            Ok((Box::new(TS1 {}), Box::new(TR2 {})))
        }
    }

    #[derive(Debug)]
    struct Co2 {}

    #[async_trait::async_trait]
    impl Connector for Co2 {
        async fn bind(_config: crate::Config) -> Result<Box<dyn Listener>, crate::Error> {
            println!("Connector Co2 bind");

            Ok(Box::new(L2 {}))
        }

        async fn connect(_config: Config) -> Result<crate::SenderAndReceiver, crate::Error> {
            println!("Connector Co2 connect");

            Ok((Box::new(TS2 {}), Box::new(TR2 {})))
        }
    }

    #[derive(Debug)]
    struct L1 {}

    #[async_trait::async_trait]
    impl Listener for L1 {
        async fn accept(
            &self,
            _closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
        ) -> Result<crate::AcceptResponse, crate::Error> {
            println!("Listener L1 accept");
            let res = crate::AcceptResponse {
                packet: vec![],
                sender: Box::new(TS1 {}),
                receiver: Box::new(TR1 {}),
                peer_addr: "127.0.0.1".parse().unwrap(),
            };
            Ok(res)
        }
    }

    #[derive(Debug)]
    struct L2 {}

    #[async_trait::async_trait]
    impl Listener for L2 {
        async fn accept(
            &self,
            _closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
        ) -> Result<crate::AcceptResponse, crate::Error> {
            println!("Listener L2 accept");
            let res = crate::AcceptResponse {
                packet: vec![],
                sender: Box::new(TS2 {}),
                receiver: Box::new(TR2 {}),
                peer_addr: "127.0.0.1".parse().unwrap(),
            };
            Ok(res)
        }
    }

    #[derive(Debug)]
    struct TS1 {}

    #[async_trait::async_trait]
    impl TransportSender for TS1 {
        async fn send(&mut self, _pkt: Vec<u8>) -> Result<(), crate::Error> {
            println!("TransportSender TS1 send");

            Ok(())
        }

        async fn close(&mut self) {
            println!("TransportSender TS1 closed");
        }
    }

    #[derive(Debug)]
    struct TS2 {}

    #[async_trait::async_trait]
    impl TransportSender for TS2 {
        async fn send(&mut self, _pkt: Vec<u8>) -> Result<(), crate::Error> {
            println!("TransportSender TS2 send");

            Ok(())
        }

        async fn close(&mut self) {
            println!("TransportSender TS2 closed");
        }
    }

    #[derive(Debug)]
    struct TR1 {}

    #[async_trait::async_trait]
    impl TransportReceiver for TR1 {
        async fn recv(&mut self) -> Result<Vec<u8>, crate::Error> {
            println!("TransportReceiver TR1 recved");

            Ok(vec![])
        }

        async fn close(&mut self) {
            println!("TransportReceiver TR1 closed");
        }
    }

    #[derive(Debug)]
    struct TR2 {}

    #[async_trait::async_trait]
    impl TransportReceiver for TR2 {
        async fn recv(&mut self) -> Result<Vec<u8>, crate::Error> {
            println!("TransportReceiver TR2 recved");

            Ok(vec![])
        }

        async fn close(&mut self) {
            println!("TransportReceiver TR2 closed");
        }
    }

    #[test]
    fn raw_connector() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (_tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                let co1 = RawConnector::new::<Co1>();
                let co2 = RawConnector::new::<Co2>();

                let bind = co1.bind(gen_cfg()).await.unwrap();
                println!("co1 bind");
                let mut accpet_response = bind.accept(&mut rx).await.unwrap();
                println!("l1 accept transport");
                accpet_response.sender.close().await;
                accpet_response.receiver.close().await;

                let bind = co2.bind(gen_cfg()).await.unwrap();
                println!("co2 bind");
                let mut accpet_response = bind.accept(&mut rx).await.unwrap();
                println!("l2 accept transport");
                accpet_response.sender.close().await;
                accpet_response.receiver.close().await;

                let (mut ts, mut tr) = co1.connect(gen_cfg()).await.unwrap();
                println!("co1 connect");
                ts.close().await;
                tr.close().await;

                let (mut ts, mut tr) = co2.connect(gen_cfg()).await.unwrap();
                println!("co2 connect");
                ts.close().await;
                tr.close().await;
            })
    }
}
