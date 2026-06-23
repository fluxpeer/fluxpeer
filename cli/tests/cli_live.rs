//! Integration test: the CLI `Client` against a live in-process control-server.

use std::sync::Arc;

use fluxpeer_cli::Client;
use fluxpeer_control_server::{router, state::Store};

#[tokio::test]
async fn cli_drives_control_server_end_to_end() {
    let app = router(Arc::new(Store::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let c = Client::new(format!("http://{addr}"));

    // create + list network
    let net = c.create_network("home").await.expect("create network");
    let nid = net["id"].as_str().expect("id").to_string();
    let nets = c.list_networks().await.expect("list networks");
    assert_eq!(nets.as_array().expect("arr").len(), 1);

    // invite
    let inv = c.create_invite(&nid, Some(3), None).await.expect("invite");
    assert_eq!(inv["max_uses"], 3);
    assert!(inv["code"].as_str().is_some());

    // no devices yet, then (enrollment is via the join API, not CLI) list is empty
    let devs = c.list_devices(&nid).await.expect("list devices");
    assert_eq!(devs.as_array().expect("arr").len(), 0);

    // batch import a wg.conf's worth of devices (full HTTP path), fixed addresses
    let import = serde_json::json!([
        { "name": "hub", "wg_public_key": "k-hub", "address_v4": "10.0.0.1", "endpoints": [] },
        { "name": "laptop", "wg_public_key": "k-laptop", "address_v4": "10.0.0.5", "endpoints": ["203.0.113.7:51820"] },
    ]);
    let res = c.import_devices(&nid, &import).await.expect("import");
    assert_eq!(res["created"].as_array().expect("created").len(), 2);
    assert!(res["skipped"].as_array().expect("skipped").is_empty());
    let devs = c.list_devices(&nid).await.expect("list after import");
    assert_eq!(devs.as_array().expect("arr").len(), 2);
    // re-import is idempotent: the duplicate key is skipped, no new device
    let res2 = c.import_devices(&nid, &import).await.expect("re-import");
    assert_eq!(res2["created"].as_array().expect("created").len(), 0);
    assert_eq!(res2["skipped"].as_array().expect("skipped").len(), 2);
    assert_eq!(c.list_devices(&nid).await.expect("list").as_array().expect("arr").len(), 2);

    // revoking a non-existent device is a 404 → error
    assert!(c.revoke_device("dev-nope").await.is_err());

    // relay directory: register shared relay, list for network
    c.register_relay("eu", "relay-eu:443", None, true, None)
        .await
        .expect("register relay");
    let relays = c.list_relays(&nid).await.expect("list relays");
    assert_eq!(relays.as_array().expect("arr").len(), 1);
    assert_eq!(relays[0]["region"], "eu");

    // MagicDNS on a missing name → 404 error
    assert!(c.resolve(&nid, "ghost").await.is_err());

    // advertising a route for a missing device → 404 error
    assert!(c.advertise_route("dev-nope", "10.0.0.0/8").await.is_err());
}
