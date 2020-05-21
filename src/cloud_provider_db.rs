use cidr::{Cidr, Ipv4Cidr};
use csv::Reader;
use std::collections::HashMap;
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

pub struct Db {
    // Cloud provider name to IPs
    providers: HashMap<String, Vec<Ipv4Cidr>>,
}

impl Db {
    /// Read database from file
    pub fn new(path: PathBuf) -> Result<Self, Box<dyn Error>> {
        let mut providers = HashMap::<String, Vec<Ipv4Cidr>>::new();

        let mut reader = Reader::from_path(path)?;
        for record in reader.records() {
            let record = record?;

            let provider = &record[1];
            let cidr = Ipv4Cidr::from_str(&record[2]).unwrap();

            providers
                .entry(provider.to_string())
                .and_modify(|p| p.push(cidr.clone()))
                .or_insert_with(|| vec![cidr]);
        }

        Ok(Db { providers })
    }

    /// Get cloud provider name that corresponds to `addr`
    pub fn get_provider(&self, addr: Ipv4Addr) -> Option<String> {
        for (provider, cidrs) in self.providers.iter() {
            for cidr in cidrs.iter() {
                if cidr.contains(&addr) {
                    return Some(provider.clone());
                }
            }
        }

        None
    }
}
