use super::*;
use hickory_proto::{
    op::Query,
    rr::{
        Record,
        rdata::{A, AAAA, CNAME, SOA},
    },
};

fn response(host: &str, kind: RecordType) -> Result<Message> {
    let mut message = Message::query();
    message.metadata.message_type = MessageType::Response;
    message.metadata.recursion_available = true;
    message.add_query(Query::query(Name::from_ascii(host)?, kind));
    Ok(message)
}
#[test]
fn dns_records_bound_chain_ttl_and_reject_truncation_and_mixed_owners() -> Result<()> {
    let name = Name::from_ascii("protected.example.com.")?;
    let target = Name::from_ascii("target.example.com.")?;
    let mut message = response("protected.example.com.", RecordType::A)?;
    message.add_answer(Record::from_rdata(
        name.clone(),
        3,
        RData::CNAME(CNAME(target.clone())),
    ));
    message.add_answer(Record::from_rdata(
        target.clone(),
        60,
        RData::A(A("8.8.4.4".parse()?)),
    ));
    let part = decode(&message, &name, RecordType::A)?;
    assert_eq!(part.ttl, 3);
    assert_eq!(part.terminal, target);
    assert!(part.cidrs.contains("8.8.4.4/32"));
    let mut truncated = message.clone();
    truncated.metadata.truncation = true;
    assert!(decode(&truncated, &name, RecordType::A).is_err());
    let mut mixed = message.clone();
    mixed.add_answer(Record::from_rdata(
        Name::from_ascii("other.example.com.")?,
        60,
        RData::A(A("1.1.1.1".parse()?)),
    ));
    assert!(decode(&mixed, &name, RecordType::A).is_err());
    let mut looped = response("protected.example.com.", RecordType::A)?;
    looped.add_answer(Record::from_rdata(
        name.clone(),
        3,
        RData::CNAME(CNAME(name.clone())),
    ));
    assert!(decode(&looped, &name, RecordType::A).is_err());
    let missing = response("protected.example.com.", RecordType::A)?;
    assert!(decode(&missing, &name, RecordType::A).is_err());
    Ok(())
}
#[test]
fn complete_negative_family_requires_covered_soa_and_uses_negative_ttl() -> Result<()> {
    let name = Name::from_ascii("protected.example.com.")?;
    let mut message = response("protected.example.com.", RecordType::AAAA)?;
    let soa = SOA::new(
        Name::from_ascii("ns.example.com.")?,
        Name::from_ascii("admin.example.com.")?,
        1,
        60,
        60,
        60,
        4,
    );
    message.add_authority(Record::from_rdata(
        Name::from_ascii("example.com.")?,
        30,
        RData::SOA(soa.clone()),
    ));
    let part = decode(&message, &name, RecordType::AAAA)?;
    assert_eq!(part.ttl, 4);
    assert!(part.cidrs.is_empty());
    assert!(!part.follow);
    let mut invalid = response("protected.example.com.", RecordType::AAAA)?;
    invalid.add_authority(Record::from_rdata(
        Name::from_ascii("other.com.")?,
        30,
        RData::SOA(soa),
    ));
    assert!(decode(&invalid, &name, RecordType::AAAA).is_err());
    Ok(())
}

#[tokio::test]
async fn real_udp_client_observes_fresh_ttls_without_a_cache() -> Result<()> {
    let root = tempfile::tempdir()?;
    let config = super::super::tests::fixture_config(root.path())?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let port = socket.local_addr()?.port();
    let server = tokio::spawn(async move {
        let mut count = 0;
        let mut first_received = None;
        loop {
            let mut buffer = [0; 4096];
            let (size, peer) = socket.recv_from(&mut buffer).await?;
            first_received.get_or_insert(SystemTime::now());
            let query = Message::from_vec(&buffer[..size])?;
            let asked = query.queries.first().context("DNS query")?;
            let mut reply = response(&asked.name().to_ascii(), asked.query_type())?;
            reply.metadata.id = query.metadata.id;
            let protected = asked.name() == &Name::from_ascii("protected.example.com.")?;
            let data = if protected {
                RData::CNAME(CNAME(Name::from_ascii("target.example.com.")?))
            } else if asked.query_type() == RecordType::A {
                RData::A(A("8.8.4.4".parse()?))
            } else {
                RData::AAAA(AAAA("2606:4700::1111".parse()?))
            };
            reply.add_answer(Record::from_rdata(
                asked.name().clone(),
                if protected { 2 } else { 60 },
                data,
            ));
            socket.send_to(&reply.to_vec()?, peer).await?;
            count += 1;
            if count == 8 {
                return Ok::<_, anyhow::Error>((
                    count,
                    first_received.context("first DNS request")?,
                ));
            }
        }
    });
    let config = InventoryConfig {
        resolver_ip: "127.0.0.1".parse()?,
        resolver_port: port,
        ..config
    };
    let first = observe(&config, "protected.example.com").await?;
    assert_eq!(first.cidrs.len(), 2);
    let _second = observe(&config, "protected.example.com").await?;
    let (count, received) = server.await??;
    assert_eq!(count, 8);
    assert!(first.valid_until <= received + Duration::from_secs(2));
    Ok(())
}
