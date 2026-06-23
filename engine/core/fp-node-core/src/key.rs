pub fn gen_prikey_with_str(key: &str) -> Result<crate::x25519::StaticSecret, crate::Error> {
    let bytes = hex::decode(key).map_err(|e| crate::Error::UnexpectedResult(format!("invalid hex key: {e}")))?;
    let result: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| crate::Error::UnexpectedResult(format!("key length {} != 32", v.len())))?;
    Ok(crate::x25519::StaticSecret::from(result))
}

pub fn gen_pubkey_with_str(key: &str) -> Result<crate::x25519::PublicKey, crate::Error> {
    let bytes = hex::decode(key).map_err(|e| crate::Error::UnexpectedResult(format!("invalid hex key: {e}")))?;
    let result: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| crate::Error::UnexpectedResult(format!("key length {} != 32", v.len())))?;
    Ok(crate::x25519::PublicKey::from(result))
}

pub mod serde {
    pub fn serialize<S>(x: &x25519_dalek::PublicKey, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&hex::encode(x))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<x25519_dalek::PublicKey, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;
        let pkey = String::deserialize(deserializer)?;
        let bytes = hex::decode(&pkey).map_err(serde::de::Error::custom)?;
        let result: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("key length {} != 32", v.len())))?;
        Ok(x25519_dalek::PublicKey::from(result))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        // let pri = "b53e9b4151da4bae982b2c6b74924447355ea946a62c2325dc51e0515dcc658d";
        let public = "2aa9b6540f433b4f4a8b9a3370c9dd27ba8fe9f5ec7843598cba5e4ee5474438";
        let bytes = hex::decode(public).unwrap();

        let mut result: [u8; 32] = [0; 32];
        result.copy_from_slice(&bytes[..32]);

        // let publ = crate::x25519::PublicKey::from(result);
        let public = crate::x25519::PublicKey::from(result);
        // let pri = crate::x25519::StaticSecret::from(result);

        let public = hex::encode(public);
        assert_eq!(
            public,
            "2aa9b6540f433b4f4a8b9a3370c9dd27ba8fe9f5ec7843598cba5e4ee5474438"
        );
    }
}
