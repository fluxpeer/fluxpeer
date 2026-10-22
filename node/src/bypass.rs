// SPDX-License-Identifier: BSD-3-Clause
//! Transactional carrier routes. Only successful exclusive adds create ownership.
use std::collections::{BTreeMap, BTreeSet};
use crate::apply::{self, ApplyError, Result, Runner};
use crate::route::RouteOs;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Via { gateway: String, iface: String }

#[derive(Default)]
pub(crate) struct State {
    owned: BTreeMap<String, Via>,
    v4: Option<Via>,
    v6: Option<Via>,
}

impl State {
    pub(crate) fn sync(&mut self, desired: &[String], retain: bool) -> Result {
        let mut desired: BTreeSet<_> = desired.iter().map(|p| prefix(p)).collect::<Result<_>>()?;
        // Keep old protections until worker endpoint changes and exit retirement finish.
        if retain { desired.extend(self.owned.keys().cloned()); }
        if !desired.is_empty() && self.v4.is_none()
            && let (Some(gateway), Some(iface)) = (crate::route::default_gateway()?, crate::route::physical_iface()?)
        { self.v4 = Some(Via { gateway, iface }); }
        if desired.iter().any(|p| p.contains(':')) && self.v6.is_none() {
            self.v6 = crate::route::physical_v6_route()?.map(|(gateway, iface)| Via { gateway, iface });
        }
        let os = crate::route::current_os();
        let (v4, v6) = (&self.v4, &self.v6);
        reconcile(&mut self.owned, &desired, |prefix| {
            let via = if prefix.contains(':') { v6 } else { v4 };
            let Some(via) = via else {
                if prefix.contains(':') { return Ok(None); } // IPv6 may be disabled on this host.
                return Err(ApplyError::new(&["bypass", prefix], "no physical default route"));
            };
            add(os, prefix, via, &mut apply::System).map(|installed| installed.then(|| via.clone()))
        }, |prefix, via| remove(os, prefix, via, &mut apply::System))
    }
}

// Add all new protections before retiring any old one. Failure restores the old
// set where possible; failed rollback entries remain owned for the next retry.
fn reconcile<T: Clone>(
    owned: &mut BTreeMap<String, T>, desired: &BTreeSet<String>,
    mut add: impl FnMut(&str) -> Result<Option<T>>, mut remove: impl FnMut(&str, &T) -> Result,
) -> Result {
    let before = owned.clone();
    let result = (|| {
        for prefix in desired {
            if !owned.contains_key(prefix) && let Some(via) = add(prefix)? { owned.insert(prefix.clone(), via); }
        }
        for prefix in before.keys().filter(|p| !desired.contains(*p)) {
            if let Some(via) = owned.get(prefix) { remove(prefix, via)?; }
            owned.remove(prefix);
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut errors = vec![Err(error)];
        // Recreate removed old routes before releasing new protections.
        for prefix in before.keys().filter(|p| !owned.contains_key(*p)).cloned().collect::<Vec<_>>() {
            match add(&prefix) {
                Ok(Some(via)) => { owned.insert(prefix, via); },
                Ok(None) => {},
                Err(error) => errors.push(Err(error)),
            }
        }
        for prefix in owned.keys().filter(|p| !before.contains_key(*p)).cloned().collect::<Vec<_>>() {
            if let Some(via) = owned.get(&prefix) {
                match remove(&prefix, via) { Ok(()) => { owned.remove(&prefix); }, Err(error) => errors.push(Err(error)) }
            }
        }
        return apply::all(errors);
    }
    Ok(())
}

fn prefix(value: &str) -> Result<String> {
    value.parse::<fluxpeer_sdk::prefix::IpPrefix>().map(|p| p.to_string())
        .map_err(|_| ApplyError::new(&["bypass", value], "invalid carrier prefix"))
}
fn command(os: RouteOs, destination: &str, via: &Via, add: bool) -> Result<Vec<String>> {
    let prefix = prefix(destination)?;
    let v6 = prefix.contains(':');
    let args: Vec<&str> = match os {
        RouteOs::Linux => vec!["ip", if v6 { "-6" } else { "-4" }, "route", if add { "add" } else { "del" }, &prefix,
            "via", &via.gateway, "dev", &via.iface, "proto", "242"],
        RouteOs::Macos => vec!["route", "-n", if add { "add" } else { "delete" }, if v6 { "-inet6" } else { "-inet" },
            "-net", &prefix, &via.gateway],
        _ => return Err(ApplyError::new(&["bypass"], "unsupported host route platform")),
    };
    Ok(args.into_iter().map(String::from).collect())
}
fn run(runner: &mut impl Runner, args: &[String]) -> Result<String> {
    runner.run(&args.iter().map(String::as_str).collect::<Vec<_>>(), None)
}

fn matches_route(os: RouteOs, destination: &str, via: &Via, owned: bool, runner: &mut impl Runner) -> Result<bool> {
    let prefix = prefix(destination)?;
    let family = if prefix.contains(':') { "-6" } else { "-4" };
    match os {
        RouteOs::Linux => {
            let output = runner.run(&["ip", "-j", "-N", family, "route", "show", "exact", &prefix], None)?;
            let routes: serde_json::Value = serde_json::from_str(&output).map_err(|e| ApplyError::new(&["bypass", "inspect"], e.to_string()))?;
            Ok(routes.as_array().is_some_and(|rows| rows.iter().any(|row| {
                row["gateway"].as_str() == Some(&via.gateway) && row["dev"].as_str() == Some(&via.iface)
                    && (!owned || row["protocol"].as_u64() == Some(242) || row["protocol"].as_str() == Some("242"))
            })))
        }
        RouteOs::Macos => {
            let output = match runner.run(&["route", "-n", "get", if prefix.contains(':') { "-inet6" } else { "-inet" }, "-net", &prefix], None) {
                Err(error) if error.missing() => return Ok(false), result => result?,
            };
            let field = |key: &str| output.lines().find_map(|line| line.trim().strip_prefix(key).map(str::trim));
            Ok(field("gateway:") == Some(via.gateway.as_str()) && field("interface:") == Some(via.iface.as_str()))
        }
        _ => Ok(false),
    }
}
fn add(os: RouteOs, destination: &str, via: &Via, runner: &mut impl Runner) -> Result<bool> {
    // Preserve connected/LAN routes; an exact borrowed route is never replaced.
    if os == RouteOs::Linux {
        let ip = destination.split('/').next().unwrap_or(destination);
        let current = runner.run(&["ip", if ip.contains(':') { "-6" } else { "-4" }, "route", "get", ip], None)?;
        if !current.contains(" via ") && current.split_whitespace().any(|part| part == via.iface) { return Ok(false); }
    }
    match run(runner, &command(os, destination, via, true)?) {
        Ok(_) => Ok(true),
        Err(error) if error.stderr.to_ascii_lowercase().contains("exist") && matches_route(os, destination, via, false, runner)? => Ok(false),
        Err(error) => Err(error),
    }
}
fn remove(os: RouteOs, destination: &str, via: &Via, runner: &mut impl Runner) -> Result {
    if !matches_route(os, destination, via, true, runner)? { return Ok(()); }
    match run(runner, &command(os, destination, via, false)?) {
        Ok(_) => Ok(()), Err(error) if error.missing() => Ok(()), Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_adds_before_deleting_and_rolls_back_failures() {
        use std::cell::RefCell;
        let events = RefCell::new(Vec::new());
        let mut owned = BTreeMap::from([("old".into(), ())]);
        let desired = BTreeSet::from(["new".into()]);
        reconcile(&mut owned, &desired,
            |p| { events.borrow_mut().push(format!("add {p}")); Ok(Some(())) },
            |p, _| { events.borrow_mut().push(format!("del {p}")); Ok(()) }).unwrap();
        assert_eq!(*events.borrow(), ["add new", "del old"]);
        assert!(owned.contains_key("new"));
        let old = owned.clone();
        assert!(reconcile(&mut owned, &BTreeSet::from(["a".into(), "bad".into()]),
            |p| if p == "bad" { Err(ApplyError::new(&[p], "injected add failure")) } else { Ok(Some(())) },
            |_, _| Ok(())).is_err());
        assert_eq!(owned, old);
        assert!(reconcile(&mut owned, &BTreeSet::from(["replacement".into()]), |_| Ok(Some(())),
            |p, _| if p == "new" { Err(ApplyError::new(&[p], "injected delete failure")) } else { Ok(()) }).is_err());
        assert_eq!(owned, old);
    }
    #[test]
    fn borrowed_routes_are_never_owned_or_deleted() {
        let mut owned = BTreeMap::<String, ()>::new();
        reconcile(&mut owned, &BTreeSet::from(["foreign".into()]), |_| Ok(None), |_, _| panic!("foreign delete")).unwrap();
        reconcile(&mut owned, &BTreeSet::new(), |_| panic!("unexpected add"), |_, _| panic!("foreign delete")).unwrap();
        assert!(owned.is_empty());
    }
    #[test]
    fn exclusive_routes_borrow_existing_and_preserve_external_replacements() {
        use crate::apply::test_support::{Scripted, error};
        let via = Via { gateway: "192.0.2.1".into(), iface: "eth0".into() };
        let existing = r#"[{"gateway":"192.0.2.1","dev":"eth0","protocol":"static"}]"#;
        let mut runner = Scripted::new(vec![Ok("192.0.2.9 via 192.0.2.1 dev eth0".into()), Err(error(Some(2), "File exists")), Ok(existing.into())]);
        assert!(!add(RouteOs::Linux, "192.0.2.9", &via, &mut runner).unwrap());
        assert_eq!(runner.commands[1][3], "add"); // never replace another owner's route
        let mut runner = Scripted::new(vec![Ok(existing.into())]);
        remove(RouteOs::Linux, "192.0.2.9", &via, &mut runner).unwrap();
        assert_eq!(runner.commands.len(), 1); // protocol changed after our add: no delete
        let mut runner = Scripted::new(vec![Ok(r#"[{"gateway":"192.0.2.1","dev":"eth0","protocol":242}]"#.into()), Ok(String::new())]);
        remove(RouteOs::Linux, "192.0.2.9", &via, &mut runner).unwrap();
        assert_eq!(runner.commands[1], command(RouteOs::Linux, "192.0.2.9", &via, false).unwrap());
        let v6 = Via { gateway: "2001:db8::1".into(), iface: "en0".into() };
        let mut runner = Scripted::new(vec![Ok("gateway: 2001:db8::99\ninterface: en0".into())]);
        remove(RouteOs::Macos, "2001:db8::9", &v6, &mut runner).unwrap();
        assert_eq!(runner.commands.len(), 1); // changed gateway remains untouched
        assert_eq!(command(RouteOs::Macos, "2001:db8::9", &v6, true).unwrap(),
            ["route", "-n", "add", "-inet6", "-net", "2001:db8::9/128", "2001:db8::1"]);
    }

    #[test]
    fn failed_rollback_retains_cleanup_obligation_for_retry() {
        let mut owned = BTreeMap::from([("old".into(), ())]);
        let desired = BTreeSet::from(["a".into(), "bad".into()]);
        let error = reconcile(&mut owned, &desired,
            |p| if p == "bad" { Err(ApplyError::new(&[p], "add denied")) } else { Ok(Some(())) },
            |_, _| Err(ApplyError::new(&["delete"], "rollback denied"))).unwrap_err();
        assert!(error.stderr.contains("add denied")); assert!(error.stderr.contains("rollback denied"));
        assert!(owned.contains_key("old")); assert!(owned.contains_key("a"));
        let mut deletes = Vec::new();
        reconcile(&mut owned, &BTreeSet::from(["old".into()]), |_| panic!("already installed"),
            |p, _| { deletes.push(p.to_string()); Ok(()) }).unwrap();
        assert_eq!(deletes, ["a"]); assert_eq!(owned.len(), 1);
    }

    #[test]
    fn route_commands_are_exclusive_and_deletes_match_original_gateway() {
        let via = Via { gateway: "192.0.2.1".into(), iface: "eth0".into() };
        assert_eq!(command(RouteOs::Linux, "192.0.2.9", &via, true).unwrap(),
            ["ip", "-4", "route", "add", "192.0.2.9/32", "via", "192.0.2.1", "dev", "eth0", "proto", "242"]);
        assert_eq!(command(RouteOs::Macos, "192.0.2.9", &via, false).unwrap(),
            ["route", "-n", "delete", "-inet", "-net", "192.0.2.9/32", "192.0.2.1"]);
    }
}
