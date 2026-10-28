//! One-use Hickory clients: no local cache, search list, hosts file or fallback DNS.
use super::InventoryConfig;
use anyhow::{Context, Result, ensure};
use hickory_net::{
    client::{Client, ClientHandle},
    proto::{
        op::{Message, MessageType, OpCode, ResponseCode},
        rr::{DNSClass, Name, RData, RecordType},
    },
    runtime::TokioRuntimeProvider,
    udp::UdpClientStream,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    time::{Duration, SystemTime},
};

pub(super) struct Observation {
    pub cidrs: BTreeSet<String>,
    pub valid_until: SystemTime,
    pub monotonic_deadline: tokio::time::Instant,
}
struct Part {
    cidrs: BTreeSet<String>,
    terminal: Name,
    ttl: u32,
    follow: bool,
    hops: Vec<Name>,
}
fn decode(message: &Message, query: &Name, kind: RecordType) -> Result<Part> {
    ensure!(
        message.metadata.message_type == MessageType::Response
            && message.metadata.op_code == OpCode::Query
            && message.metadata.response_code == ResponseCode::NoError
            && !message.metadata.truncation,
        "incomplete or failed DNS response"
    );
    ensure!(
        message.queries.len() == 1
            && message.queries[0].name() == query
            && message.queries[0].query_type() == kind
            && message.queries[0].query_class() == DNSClass::IN,
        "DNS response question differs"
    );
    ensure!(
        message.answers.len() + message.authorities.len() + message.additionals.len() <= 1024
            && message.additionals.is_empty(),
        "excessive or mixed DNS additional records"
    );
    let mut records = BTreeMap::<Name, Vec<_>>::new();
    for record in &message.answers {
        ensure!(
            record.dns_class == DNSClass::IN
                && matches!(&record.data, RData::CNAME(_) | RData::A(_) | RData::AAAA(_)),
            "mixed DNS answer type/class"
        );
        records
            .entry(record.name.to_lowercase())
            .or_default()
            .push(record);
    }
    let mut terminal = query.to_lowercase();
    let mut hops = Vec::new();
    let mut ttl = u32::MAX;
    let mut cidrs = BTreeSet::new();
    while let Some(group) = records.remove(&terminal) {
        ensure!(hops.len() <= 8, "DNS CNAME chain exceeds eight links");
        let aliases = group
            .iter()
            .filter(|r| matches!(&r.data, RData::CNAME(_)))
            .collect::<Vec<_>>();
        if !aliases.is_empty() {
            ensure!(
                aliases.len() == 1 && group.len() == 1,
                "mixed or ambiguous DNS CNAME owner"
            );
            let RData::CNAME(target) = &aliases[0].data else {
                unreachable!("filtered CNAME")
            };
            let next = target.0.to_lowercase();
            let canonical = crate::network::normalize_host(&next.to_ascii())?;
            ensure!(
                canonical.parse::<IpAddr>().is_err(),
                "CNAME target must be an exact DNS name"
            );
            ensure!(next != terminal && !hops.contains(&next), "DNS CNAME cycle");
            ttl = ttl.min(aliases[0].ttl);
            hops.push(terminal);
            terminal = next;
            continue;
        }
        for record in group {
            ttl = ttl.min(record.ttl);
            let ip = match &record.data {
                RData::A(a) if kind == RecordType::A => IpAddr::V4(a.0),
                RData::AAAA(a) if kind == RecordType::AAAA => IpAddr::V6(a.0),
                _ => anyhow::bail!("mixed DNS address family"),
            };
            cidrs.insert(match ip {
                IpAddr::V4(_) => format!("{ip}/32"),
                IpAddr::V6(_) => format!("{ip}/128"),
            });
        }
        break;
    }
    ensure!(records.is_empty(), "unrelated DNS answer owner");
    let follow = cidrs.is_empty() && !hops.is_empty();
    if cidrs.is_empty() && !follow {
        let mut negative = false;
        for record in &message.authorities {
            if let RData::SOA(soa) = &record.data {
                ensure!(
                    record.dns_class == DNSClass::IN && record.name.zone_of(query),
                    "negative DNS SOA does not cover query"
                );
                ttl = ttl.min(record.ttl).min(soa.minimum);
                negative = true;
            } else {
                anyhow::bail!("missing complete negative DNS SOA");
            }
        }
        ensure!(negative, "missing DNS address and negative SOA");
    }
    ensure!(ttl > 0 && ttl != u32::MAX, "zero or missing DNS TTL");
    Ok(Part {
        cidrs,
        terminal,
        ttl,
        follow,
        hops,
    })
}
struct Background(tokio::task::JoinHandle<()>);
impl Drop for Background {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn query(
    config: &InventoryConfig,
    name: Name,
    kind: RecordType,
) -> Result<(Part, SystemTime, tokio::time::Instant)> {
    let observed = SystemTime::now();
    let monotonic = tokio::time::Instant::now();
    let connection = UdpClientStream::builder(
        SocketAddr::new(config.resolver_ip, config.resolver_port),
        TokioRuntimeProvider::default(),
    )
    .with_timeout(Some(Duration::from_secs(config.query_timeout_secs)))
    .build();
    let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(connection);
    let _background = Background(tokio::spawn(background));
    let response = tokio::time::timeout(
        Duration::from_secs(config.query_timeout_secs),
        client.query(name.clone(), DNSClass::IN, kind),
    )
    .await
    .context("trusted DNS query timed out")??;
    let part = decode(&response, &name, kind)?;
    let deadline = observed + Duration::from_secs(part.ttl as u64);
    let monotonic_deadline = monotonic + Duration::from_secs(part.ttl as u64);
    Ok((part, deadline, monotonic_deadline))
}
async fn family(
    config: &InventoryConfig,
    host: &str,
    kind: RecordType,
) -> Result<(Observation, Name)> {
    let mut name = Name::from_ascii(format!("{}.", crate::network::normalize_host(host)?))?;
    let mut visited = BTreeSet::new();
    let mut deadline = SystemTime::now() + Duration::from_secs(config.freshness_secs);
    let mut monotonic_deadline =
        tokio::time::Instant::now() + Duration::from_secs(config.freshness_secs);
    loop {
        ensure!(
            visited.len() <= 8 && visited.insert(name.clone()),
            "DNS alias chain exceeds eight or repeats"
        );
        let (part, expires, monotonic_expires) = query(config, name, kind).await?;
        deadline = deadline.min(expires);
        monotonic_deadline = monotonic_deadline.min(monotonic_expires);
        for hop in &part.hops {
            if !visited.contains(hop) {
                ensure!(
                    visited.len() < 9 && visited.insert(hop.clone()),
                    "DNS alias cycle or excessive chain"
                );
            }
        }
        if !part.follow {
            return Ok((
                Observation {
                    cidrs: part.cidrs,
                    valid_until: deadline,
                    monotonic_deadline,
                },
                part.terminal,
            ));
        }
        name = part.terminal;
    }
}
pub(super) async fn observe(config: &InventoryConfig, host: &str) -> Result<Observation> {
    let (a, aaaa) = tokio::try_join!(
        family(config, host, RecordType::A),
        family(config, host, RecordType::AAAA)
    )?;
    ensure!(
        a.1 == aaaa.1,
        "A and AAAA observations disagree on canonical name"
    );
    let mut cidrs = a.0.cidrs;
    cidrs.extend(aaaa.0.cidrs);
    ensure!(
        !cidrs.is_empty() && cidrs.len() <= 1024,
        "missing or excessive DNS addresses"
    );
    Ok(Observation {
        cidrs,
        valid_until: a.0.valid_until.min(aaaa.0.valid_until),
        monotonic_deadline: a.0.monotonic_deadline.min(aaaa.0.monotonic_deadline),
    })
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
