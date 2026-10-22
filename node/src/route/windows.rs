// SPDX-License-Identifier: BSD-3-Clause
//! IP Helper routes with a durable, per-membership ownership journal.
use std::{collections::BTreeMap, fs::{File, OpenOptions}, io::{self, Write}, net::IpAddr, path::{Path, PathBuf}};

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub(crate) use native::{add, begin, cleanup, default_route, needs_bypass, recover, remove, remove_bypass};

const METRIC: u32 = 42760;
const NETMGMT: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Row {
    prefix: String,
    gateway: IpAddr,
    luid: u64,
    metric: u32,
    protocol: u32,
    site_prefix: u8,
    valid: u32,
    preferred: u32,
    loopback: bool,
    autoconfigure: bool,
    publish: bool,
    immortal: bool,
}
impl Row {
    fn new(prefix: &str, gateway: IpAddr, luid: u64) -> io::Result<Self> {
        let prefix: fluxpeer_sdk::prefix::IpPrefix = prefix.parse().map_err(io::Error::other)?;
        if prefix.network().is_ipv4() != gateway.is_ipv4() || luid == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "route family or interface mismatch"));
        }
        Ok(Self { prefix: prefix.to_string(), gateway, luid, metric: METRIC, protocol: NETMGMT,
            site_prefix: 0, valid: u32::MAX, preferred: u32::MAX, loopback: false,
            autoconfigure: false, publish: false, immortal: false })
    }
}
trait Api {
    fn get(&mut self, row: &Row) -> io::Result<Option<Row>>;
    fn create(&mut self, row: &Row) -> io::Result<()>;
    fn delete(&mut self, row: &Row) -> io::Result<()>;
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Journal { rows: BTreeMap<String, Row> }
struct Book { path: PathBuf, _lock: File, journal: Journal }
impl Book {
    fn open(root: &Path, iface: &str) -> io::Result<Self> {
        if !crate::daemon::valid_iface(iface) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid route owner")); }
        std::fs::create_dir_all(root)?;
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(root.join(format!("{iface}.lock")))?;
        lock.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, "membership routes already owned by a live process"),
            std::fs::TryLockError::Error(error) => error,
        })?;
        let path = root.join(format!("{iface}.json"));
        let journal = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Journal::default(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, _lock: lock, journal })
    }
    fn save(&self) -> io::Result<()> {
        let parent = self.path.parent().ok_or_else(|| io::Error::other("missing route journal directory"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(&mut file, &self.journal).map_err(io::Error::other)?;
        file.flush()?; file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
    fn table_lock(&self) -> io::Result<File> {
        let root = self.path.parent().ok_or_else(|| io::Error::other("missing route journal directory"))?;
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(root.join(".table.lock"))?;
        lock.lock()?;
        Ok(lock)
    }
    fn reserved_elsewhere(&self, row: &Row) -> io::Result<bool> {
        let root = self.path.parent().ok_or_else(|| io::Error::other("missing route journal directory"))?;
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path();
            if path == self.path || path.extension().is_none_or(|extension| extension != "json") { continue; }
            let journal: Journal = serde_json::from_slice(&std::fs::read(path)?).map_err(io::Error::other)?;
            if journal.rows.values().any(|other| other.prefix == row.prefix && other.gateway == row.gateway && other.luid == row.luid) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn add(&mut self, key: &str, row: Row, api: &mut impl Api) -> io::Result<()> {
        let _table = self.table_lock()?;
        // A durable pending create also reserves the OS key. Another member must
        // not create that same row in the first member's crash/recovery window.
        if self.reserved_elsewhere(&row)? {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "route reserved by another membership"));
        }
        if let Some(previous) = self.journal.rows.get(key) {
            if previous == &row && api.get(&row)?.as_ref() == Some(&row) { return Ok(()); }
            self.remove_locked(key, api)?;
        }
        if let Some(existing) = api.get(&row)? {
            // On-link routes created by Windows address configuration are usable
            // but never owned. Do not borrow another member's leased route.
            if existing.metric == METRIC && existing.protocol == NETMGMT {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "route is owned by another membership"));
            }
            return Ok(());
        }
        // Persist intent before the API call. A crash after create is recovered
        // by matching the full recorded row; pre-existing rows are never replaced.
        self.journal.rows.insert(key.into(), row.clone());
        self.save()?;
        if let Err(error) = api.create(&row) {
            // IP Helper create failures do not mutate the table. In particular,
            // an AlreadyExists race is foreign and must not be adopted on retry.
            self.journal.rows.remove(key);
            self.save()?;
            return Err(error);
        }
        if api.get(&row)?.as_ref() != Some(&row) { return Err(io::Error::other("route verification failed")); }
        Ok(())
    }
    fn remove(&mut self, key: &str, api: &mut impl Api) -> io::Result<()> {
        let _table = self.table_lock()?;
        self.remove_locked(key, api)
    }
    fn remove_locked(&mut self, key: &str, api: &mut impl Api) -> io::Result<()> {
        let Some(row) = self.journal.rows.get(key).cloned() else { return Ok(()); };
        if let Some(current) = api.get(&row)? {
            if current != row { return Err(io::Error::other("owned route changed externally; refusing deletion")); }
            match api.delete(&row) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {},
            }
            if api.get(&row)?.is_some() { return Err(io::Error::other("route removal verification failed")); }
        }
        self.journal.rows.remove(key);
        if let Err(error) = self.save() {
            self.journal.rows.insert(key.into(), row);
            return Err(error);
        }
        Ok(())
    }
    fn cleanup(&mut self, api: &mut impl Api) -> io::Result<()> {
        let _table = self.table_lock()?;
        let keys: Vec<_> = self.journal.rows.keys().cloned().collect();
        let mut first = None;
        // Keep carrier bypasses while any redirect/guard removal is incomplete.
        for key in keys.iter().filter(|key| !key.starts_with("bypass/")) {
            if let Err(error) = self.remove_locked(key, api) { first.get_or_insert(error); }
        }
        if first.is_none() {
            for key in keys.iter().filter(|key| key.starts_with("bypass/")) {
                if let Err(error) = self.remove_locked(key, api) { first.get_or_insert(error); }
            }
        }
        first.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake { rows: BTreeMap<(String, IpAddr, u64), Row>, fail_delete: bool, fail_create: bool }
    impl Api for Fake {
        fn get(&mut self, row: &Row) -> io::Result<Option<Row>> { Ok(self.rows.get(&identity(row)).cloned()) }
        fn create(&mut self, row: &Row) -> io::Result<()> {
            if self.fail_create { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "create denied")); }
            self.rows.insert(identity(row), row.clone()); Ok(())
        }
        fn delete(&mut self, row: &Row) -> io::Result<()> {
            if self.fail_delete { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "delete denied")); }
            self.rows.remove(&identity(row)); Ok(())
        }
    }
    fn identity(row: &Row) -> (String, IpAddr, u64) { (row.prefix.clone(), row.gateway, row.luid) }
    fn row(prefix: &str) -> Row { Row::new(prefix, "0.0.0.0".parse().unwrap(), 42).unwrap() }
    #[test]
    fn foreign_rows_are_preserved_and_other_member_routes_are_not_borrowed() {
        let dir = tempfile::tempdir().unwrap(); let mut book = Book::open(dir.path(), "fp0").unwrap();
        let wanted = row("100.72.0.0/24"); let mut foreign = wanted.clone(); foreign.metric = 0; foreign.protocol = 2;
        let mut api = Fake::default(); api.rows.insert(identity(&foreign), foreign.clone());
        book.add("tun/overlay", wanted.clone(), &mut api).unwrap(); book.remove("tun/overlay", &mut api).unwrap();
        assert_eq!(api.rows.get(&identity(&foreign)), Some(&foreign)); assert!(book.journal.rows.is_empty());
        api.rows.insert(identity(&wanted), wanted.clone());
        assert_eq!(book.add("tun/overlay", wanted, &mut api).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }
    #[test]
    fn restart_recovers_owned_routes_and_failed_cleanup_retains_bypass_and_journal() {
        let dir = tempfile::tempdir().unwrap(); let mut book = Book::open(dir.path(), "fp0").unwrap(); let mut api = Fake::default();
        book.add("tun/default", row("0.0.0.0/1"), &mut api).unwrap();
        book.add("bypass/control", row("192.0.2.1/32"), &mut api).unwrap();
        assert!(Book::open(dir.path(), "fp0").is_err()); drop(book);
        let mut book = Book::open(dir.path(), "fp0").unwrap(); api.fail_delete = true;
        assert!(book.cleanup(&mut api).is_err()); assert_eq!(book.journal.rows.len(), 2);
        api.fail_delete = false; book.cleanup(&mut api).unwrap(); assert!(api.rows.is_empty());
        drop(book); assert!(Book::open(dir.path(), "fp0").unwrap().journal.rows.is_empty());
    }
    #[test]
    fn foreign_modifications_and_failed_additions_do_not_become_success_or_owned_deletions() {
        let dir = tempfile::tempdir().unwrap(); let mut book = Book::open(dir.path(), "fp0").unwrap(); let mut api = Fake::default();
        let wanted = row("0.0.0.0/1"); api.fail_create = true;
        assert!(book.add("tun/default", wanted.clone(), &mut api).is_err()); assert!(book.journal.rows.is_empty());
        api.fail_create = false; book.add("tun/default", wanted.clone(), &mut api).unwrap();
        api.rows.get_mut(&identity(&wanted)).unwrap().metric += 1;
        assert!(book.cleanup(&mut api).is_err()); assert_eq!(api.rows.len(), 1); assert_eq!(book.journal.rows.len(), 1);
    }
    #[test]
    fn other_members_cannot_create_a_route_reserved_by_an_incomplete_transaction() {
        let dir = tempfile::tempdir().unwrap(); let mut first = Book::open(dir.path(), "fp0").unwrap();
        let mut second = Book::open(dir.path(), "fp1").unwrap(); let wanted = row("192.0.2.1/32");
        first.journal.rows.insert("bypass/control".into(), wanted.clone()); first.save().unwrap();
        let mut api = Fake::default();
        assert_eq!(second.add("bypass/control", wanted.clone(), &mut api).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(api.rows.is_empty()); drop(first);
        Book::open(dir.path(), "fp0").unwrap().cleanup(&mut api).unwrap();
        second.add("bypass/control", wanted, &mut api).unwrap();
        Book::open(dir.path(), "fp0").unwrap().cleanup(&mut api).unwrap();
        assert_eq!(api.rows.len(), 1); second.cleanup(&mut api).unwrap(); assert!(api.rows.is_empty());
    }
    #[test]
    fn same_prefix_on_distinct_interfaces_is_cleaned_only_by_its_owner() {
        let dir = tempfile::tempdir().unwrap(); let mut first = Book::open(dir.path(), "table").unwrap();
        let mut second = Book::open(dir.path(), "fp1").unwrap(); let a = row("100.72.0.0/24");
        let mut b = a.clone(); b.luid += 1; let mut api = Fake::default();
        first.add("tun/overlay", a, &mut api).unwrap();
        second.add("tun/overlay", b.clone(), &mut api).unwrap();
        first.cleanup(&mut api).unwrap();
        assert_eq!(api.rows.len(), 1); assert_eq!(api.get(&b).unwrap(), Some(b));
        second.cleanup(&mut api).unwrap(); assert!(api.rows.is_empty());
    }
    #[test]
    fn failed_journal_commit_after_delete_stays_pending_until_retry() {
        let dir = tempfile::tempdir().unwrap(); let mut book = Book::open(dir.path(), "fp0").unwrap();
        let mut api = Fake::default(); book.add("tun/overlay", row("100.72.0.0/24"), &mut api).unwrap();
        // Deny atomic replacement after the OS removal has succeeded.
        std::fs::remove_file(&book.path).unwrap(); std::fs::create_dir(&book.path).unwrap();
        assert!(book.cleanup(&mut api).is_err()); assert!(api.rows.is_empty());
        assert_eq!(book.journal.rows.len(), 1);
        std::fs::remove_dir(&book.path).unwrap(); book.cleanup(&mut api).unwrap();
        drop(book); assert!(Book::open(dir.path(), "fp0").unwrap().journal.rows.is_empty());
    }
    #[test]
    fn prepared_intent_survives_a_crash_between_create_and_verification() {
        let dir = tempfile::tempdir().unwrap(); let mut book = Book::open(dir.path(), "fp0").unwrap(); let wanted = row("0.0.0.0/1");
        book.journal.rows.insert("tun/default".into(), wanted.clone()); book.save().unwrap(); drop(book);
        let mut api = Fake::default(); api.rows.insert(identity(&wanted), wanted);
        Book::open(dir.path(), "fp0").unwrap().cleanup(&mut api).unwrap(); assert!(api.rows.is_empty());
        assert!(Row::new("2001:db8::/32", "192.0.2.1".parse().unwrap(), 1).is_err());
    }
}
