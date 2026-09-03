use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsServerCheckResult {
    pub server_name: String,
    pub server_ip: String,
    pub records: Vec<String>,
    pub matched: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsPropagationReport {
    pub txt_host: String,
    pub expected_value: String,
    pub fully_propagated: bool,
    pub results: Vec<DnsServerCheckResult>,
}

fn create_custom_resolver(ip: Ipv4Addr) -> TokioAsyncResolver {
    let mut config = ResolverConfig::new();
    let socket = SocketAddr::new(IpAddr::V4(ip), 53);
    config.add_name_server(NameServerConfig::new(socket, Protocol::Udp));
    config.add_name_server(NameServerConfig::new(socket, Protocol::Tcp));

    let mut opts = ResolverOpts::default();
    opts.attempts = 2;
    opts.timeout = std::time::Duration::from_secs(3);
    opts.try_tcp_on_error = true;
    opts.edns0 = true;

    TokioAsyncResolver::tokio(config, opts)
}


pub async fn check_dns_propagation(
    txt_host: &str,
    expected_value: &str,
) -> DnsPropagationReport {
    let servers = vec![
        ("Cloudflare DNS", Ipv4Addr::new(1, 1, 1, 1)),
        ("Google DNS", Ipv4Addr::new(8, 8, 8, 8)),
        ("Quad9 DNS", Ipv4Addr::new(9, 9, 9, 9)),
    ];

    let query_host = txt_host.trim_end_matches('.').to_string();
    let expected = expected_value.trim().to_string();

    let mut tasks = Vec::new();

    for (name, ip) in servers {
        let q_host = query_host.clone();
        let exp_val = expected.clone();

        tasks.push(tokio::spawn(async move {
            let mut server_res = DnsServerCheckResult {
                server_name: name.to_string(),
                server_ip: ip.to_string(),
                records: Vec::new(),
                matched: false,
                error: None,
            };

            let resolver = create_custom_resolver(ip);

            // Follow CNAME chain if any (e.g. acme-challenge CNAME delegation)
            let mut targets = vec![q_host.clone()];
            let mut current = q_host.clone();
            for _ in 0..3 {
                let query_target = format!("{}.", current.trim_end_matches('.'));
                if let Ok(cname_lookup) = resolver
                    .lookup(&query_target, hickory_resolver::proto::rr::RecordType::CNAME)
                    .await
                {
                    let mut next_cname = None;
                    for r in cname_lookup.iter() {
                        if let Some(cname) = r.as_cname() {
                            let target_str = cname.to_utf8().trim_end_matches('.').to_string();
                            if !target_str.is_empty() && target_str != current {
                                next_cname = Some(target_str);
                                break;
                            }
                        }
                    }
                    if let Some(nxt) = next_cname {
                        targets.push(nxt.clone());
                        current = nxt;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            let mut all_records = Vec::new();
            let mut matched = false;
            let mut last_err = None;

            for target in &targets {
                let target_query = format!("{}.", target.trim_end_matches('.'));
                match resolver.txt_lookup(&target_query).await {
                    Ok(lookup) => {
                        for record in lookup.iter() {
                            for rdata in record.txt_data() {
                                if let Ok(s) = std::str::from_utf8(rdata) {
                                    let s_trim = s.trim().to_string();
                                    if s_trim == exp_val {
                                        matched = true;
                                    }
                                    if !all_records.contains(&s_trim) {
                                        all_records.push(s_trim);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        last_err = Some(format!("{}", e));
                    }
                }
                if matched {
                    break;
                }
            }

            server_res.records = all_records;
            server_res.matched = matched;
            if !matched && server_res.records.is_empty() {
                server_res.error = last_err;
            }

            server_res
        }));
    }

    let mut results = Vec::new();
    let mut all_matched = true;

    for task in tasks {
        if let Ok(res) = task.await {
            if !res.matched {
                all_matched = false;
            }
            results.push(res);
        }
    }

    DnsPropagationReport {
        txt_host: txt_host.to_string(),
        expected_value: expected_value.to_string(),
        fully_propagated: all_matched && !results.is_empty(),
        results,
    }
}


pub async fn resolve_cname_target(host: &str) -> Option<String> {
    let resolver = create_custom_resolver(Ipv4Addr::new(1, 1, 1, 1));
    let clean = host.trim().trim_end_matches('.');
    let query_target = format!("{}.", clean);

    if let Ok(lookup) = resolver.lookup(&query_target, hickory_resolver::proto::rr::RecordType::CNAME).await {
        for record in lookup.iter() {
            if let Some(cname) = record.as_cname() {
                let target_str = cname.to_string();
                let clean_target = target_str.trim().trim_end_matches('.');
                if !clean_target.is_empty() && clean_target != clean {
                    return Some(clean_target.to_string());
                }
            }
        }
    }

    None
}

