use crate::cloud_provider_db;
use client::Client;
use futures::prelude::*;
use futures_timer::Delay;
use libp2p::{
    identify::IdentifyEvent,
    kad::{GetClosestPeersOk, KademliaEvent, QueryResult},
    multiaddr::{Multiaddr, Protocol},
    ping::{PingEvent, PingSuccess},
    PeerId,
};
use log::info;
use maxminddb::{geoip2, Reader};
use node_store::{Node, NodeStore};
use prometheus::{exponential_buckets, CounterVec, HistogramOpts, HistogramVec, Opts, Registry};
use std::{
    collections::HashMap,
    error::Error,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

mod client;
mod node_store;

const TICK_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct Exporter {
    // TODO: Introduce dht id new type.
    clients: HashMap<String, Client>,
    node_stores: HashMap<String, NodeStore>,
    ip_db: Option<Reader<Vec<u8>>>,
    cloud_provider_db: Option<cloud_provider_db::Db>,
    /// Set of in-flight random peer id lookups.
    ///
    /// When a lookup returns the entry is dropped and thus the duratation is
    /// observed through `<HistogramTimer as Drop>::drop`.
    in_flight_lookups: HashMap<PeerId, Instant>,
    tick: Delay,
    metrics: Metrics,
    /// An exporter periodically reconnects to each discovered node to probe
    /// whether it is still online.
    nodes_to_probe_periodically: HashMap<String, Vec<PeerId>>,
}

impl Exporter {
    pub(crate) fn new(
        dhts: Vec<(String, Multiaddr, bool)>,
        ip_db: Option<Reader<Vec<u8>>>,
        cloud_provider_db: Option<cloud_provider_db::Db>,
        registry: &Registry,
    ) -> Result<Self, Box<dyn Error>> {
        let metrics = Metrics::register(registry);

        let clients = dhts
            .clone()
            .into_iter()
            .map(|(name, bootnode, disjoint_paths)| {
                (name, client::Client::new(bootnode, disjoint_paths).unwrap())
            })
            .collect();

        let node_store_metrics = node_store::Metrics::register(registry);
        let node_stores = dhts
            .clone()
            .into_iter()
            .map(|(name, _, _)| {
                (
                    name.clone(),
                    NodeStore::new(name, node_store_metrics.clone()),
                )
            })
            .collect();

        let nodes_to_probe_periodically = dhts
            .into_iter()
            .map(|(name, _, _)| (name, vec![]))
            .collect();

        Ok(Exporter {
            clients,
            metrics,
            ip_db,
            cloud_provider_db,
            node_stores,

            tick: futures_timer::Delay::new(TICK_INTERVAL),

            in_flight_lookups: HashMap::new(),
            nodes_to_probe_periodically,
        })
    }

    fn record_event(&mut self, name: String, event: client::Event) {
        match event {
            // TODO: We could also expose the ping latency.
            client::Event::Ping(PingEvent { peer, result }) => {
                // Update node store.
                match result {
                    Ok(_) => self
                        .node_stores
                        .get_mut(&name)
                        .unwrap()
                        .observed_node(Node::new(peer.clone())),
                    Err(_) => self
                        .node_stores
                        .get_mut(&name)
                        .unwrap()
                        .observed_down(&peer),
                }

                let country = self
                    .node_stores
                    .get_mut(&name)
                    .unwrap()
                    .get_peer(&peer)
                    .map(|p| p.country.clone())
                    .flatten()
                    .unwrap_or_else(|| "unknown".to_string());

                let event = match result {
                    // Sent a ping and received back a pong.
                    Ok(PingSuccess::Ping { rtt }) => {
                        self.metrics
                            .ping_duration
                            .with_label_values(&[&name, &country])
                            .observe(rtt.as_secs_f64());
                        "received_pong"
                    }
                    // Received a ping and sent back a pong.
                    Ok(PingSuccess::Pong) => "received_ping",
                    Err(_) => "error",
                };

                self.metrics
                    .event_counter
                    .with_label_values(&[&name, "ping", event])
                    .inc();
            }
            client::Event::Identify(event) => match *event {
                IdentifyEvent::Error { .. } => {
                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "identify", "error"])
                        .inc();
                }
                IdentifyEvent::Sent { .. } => {
                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "identify", "sent"])
                        .inc();
                }
                IdentifyEvent::Received { peer_id, .. } => {
                    self.node_stores
                        .get_mut(&name)
                        .unwrap()
                        .observed_node(Node::new(peer_id));

                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "identify", "received"])
                        .inc();
                }
            },
            client::Event::Kademlia(event) => match *event {
                KademliaEvent::QueryResult { result, .. } => match result {
                    QueryResult::Bootstrap(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "bootstrap"])
                            .inc();
                    }
                    QueryResult::GetClosestPeers(res) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "get_closest_peers"])
                            .inc();

                        // Record lookup latency.
                        let result_label = if res.is_ok() { "ok" } else { "error" };
                        let peer_id = PeerId::from_bytes(match res {
                            Ok(GetClosestPeersOk { key, .. }) => key,
                            Err(err) => err.into_key(),
                        })
                        .unwrap();
                        let duration =
                            Instant::now() - self.in_flight_lookups.remove(&peer_id).unwrap();
                        self.metrics
                            .random_node_lookup_duration
                            .with_label_values(&[&name, result_label])
                            .observe(duration.as_secs_f64());
                    }
                    QueryResult::GetProviders(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "get_providers"])
                            .inc();
                    }
                    QueryResult::StartProviding(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "start_providing"])
                            .inc();
                    }
                    QueryResult::RepublishProvider(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "republish_provider"])
                            .inc();
                    }
                    QueryResult::GetRecord(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "get_record"])
                            .inc();
                    }
                    QueryResult::PutRecord(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "put_record"])
                            .inc();
                    }
                    QueryResult::RepublishRecord(_) => {
                        self.metrics
                            .event_counter
                            .with_label_values(&[&name, "kad", "republish_record"])
                            .inc();
                    }
                },
                // Note: Do not interpret Discovered event as a proof of a node
                // being online.
                KademliaEvent::Discovered { .. } => {
                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "kad", "discovered"])
                        .inc();
                }
                KademliaEvent::RoutingUpdated {
                    peer, addresses, ..
                } => {
                    let mut node = Node::new(peer);
                    if let Some(country) = self.multiaddresses_to_country_code(addresses.iter()) {
                        node = node.with_country(country);
                    }
                    if let Some(provider) = self.multiaddresses_to_cloud_provider(addresses.iter())
                    {
                        node = node.with_cloud_provider(provider);
                    }
                    self.node_stores.get_mut(&name).unwrap().observed_node(node);

                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "kad", "routing_updated"])
                        .inc();
                }
                KademliaEvent::UnroutablePeer { .. } => {
                    self.metrics
                        .event_counter
                        .with_label_values(&[&name, "kad", "unroutable_peer"])
                        .inc();
                }
            },
        }
    }

    fn multiaddresses_to_cloud_provider<'a>(
        &self,
        addresses: impl Iterator<Item = &'a Multiaddr>,
    ) -> Option<String> {
        for address in addresses {
            let provider = self.multiaddress_to_cloud_provider(address);
            if provider.is_some() {
                return provider;
            }
        }

        None
    }

    fn multiaddress_to_cloud_provider(&self, address: &Multiaddr) -> Option<String> {
        let ip_address = match address.iter().next()? {
            Protocol::Ip4(addr) => Some(addr),
            _ => None,
        }?;

        if let Some(db) = &self.cloud_provider_db {
            return db.get_provider(ip_address);
        }

        None
    }

    fn multiaddresses_to_country_code<'a>(
        &self,
        addresses: impl Iterator<Item = &'a Multiaddr>,
    ) -> Option<String> {
        for address in addresses {
            let country = self.multiaddress_to_country_code(address);
            if country.is_some() {
                return country;
            }
        }

        None
    }

    fn multiaddress_to_country_code(&self, address: &Multiaddr) -> Option<String> {
        let ip_address = match address.iter().next()? {
            Protocol::Ip4(addr) => Some(IpAddr::V4(addr)),
            Protocol::Ip6(addr) => Some(IpAddr::V6(addr)),
            _ => None,
        }?;

        if let Some(ip_db) = &self.ip_db {
            return ip_db
                .lookup::<geoip2::City>(ip_address)
                .ok()?
                .country?
                .iso_code;
        }

        None
    }
}
impl Future for Exporter {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
        let this = &mut *self;

        if let Poll::Ready(()) = this.tick.poll_unpin(ctx) {
            this.tick = Delay::new(TICK_INTERVAL);

            for node_store in &mut this.node_stores.values_mut() {
                node_store.tick();
            }

            // TODO: Introduce meta monitoring to find out how many nodes we actually check.
            for (dht, nodes) in &mut this.nodes_to_probe_periodically {
                match nodes.pop() {
                    Some(peer_id) => {
                        info!("Checking if {:?} is still online.", &peer_id);
                        if this.clients.get_mut(dht).unwrap().dial(&peer_id).is_err() {
                            // Connection limit reached. Retry later.
                            nodes.insert(0, peer_id);
                        }
                    }
                    // List is empty. Reconnected to every peer. Refill the
                    // list.
                    None => {
                        nodes.append(
                            &mut this
                                .node_stores
                                .get(dht)
                                .unwrap()
                                .iter()
                                .map(|n| n.peer_id.clone())
                                .collect(),
                        );
                    }
                }
            }

            // Trigger a random lookup for each client.
            for (name, client) in this.clients.iter_mut() {
                this.metrics
                    .meta_random_node_lookup_triggered
                    .with_label_values(&[name])
                    .inc();
                let random_peer = PeerId::random();
                client.get_closest_peers(random_peer.clone());
                this.in_flight_lookups.insert(random_peer, Instant::now());
            }
        }

        let mut events = vec![];

        for (name, client) in &mut this.clients {
            loop {
                match client.poll_next_unpin(ctx) {
                    Poll::Ready(Some(event)) => events.push((name.clone(), event)),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
        }

        for (name, event) in events {
            this.record_event(name, event);
        }

        Poll::Pending
    }
}

struct Metrics {
    event_counter: CounterVec,

    ping_duration: HistogramVec,
    random_node_lookup_duration: HistogramVec,

    meta_random_node_lookup_triggered: CounterVec,
}

impl Metrics {
    fn register(registry: &Registry) -> Metrics {
        let event_counter = CounterVec::new(
            Opts::new(
                "network_behaviour_event",
                "Libp2p network behaviour events.",
            ),
            &["dht", "behaviour", "event"],
        )
        .unwrap();
        registry.register(Box::new(event_counter.clone())).unwrap();

        let random_node_lookup_duration = HistogramVec::new(
            HistogramOpts::new(
                "random_node_lookup_duration",
                "Duration of random node lookup.",
            )
            .buckets(exponential_buckets(0.1, 2.0, 10).unwrap()),
            &["dht", "result"],
        )
        .unwrap();
        registry
            .register(Box::new(random_node_lookup_duration.clone()))
            .unwrap();

        let ping_duration = HistogramVec::new(
            HistogramOpts::new("ping_duration", "Duration of a ping round trip."),
            &["dht", "country"],
        )
        .unwrap();
        registry.register(Box::new(ping_duration.clone())).unwrap();

        let meta_random_node_lookup_triggered = CounterVec::new(
            Opts::new(
                "meta_random_node_lookup_triggered",
                "Number of times a random Kademlia node lookup was triggered.",
            ),
            &["dht"],
        )
        .unwrap();
        registry
            .register(Box::new(meta_random_node_lookup_triggered.clone()))
            .unwrap();

        Metrics {
            event_counter,

            ping_duration,
            random_node_lookup_duration,

            meta_random_node_lookup_triggered,
        }
    }
}
