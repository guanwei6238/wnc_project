use super::*;

fn chain(ids: &[u32]) -> Result<TcxChain, TcxQueryError> {
    Ok(TcxChain {
        revision: 1,
        prog_ids: ids.to_vec(),
    })
}

#[test]
fn position_follows_the_order_of_the_chain() {
    assert_eq!(position(5, chain(&[5, 9])), Position::First);
    assert_eq!(position(5, chain(&[7, 8, 5])), Position::Behind(vec![7, 8]));
    assert_eq!(position(5, chain(&[7])), Position::Detached);
    assert_eq!(position(5, chain(&[])), Position::Detached);
}

#[test]
fn a_port_that_went_away_counts_as_detached() {
    assert_eq!(position(5, Err(TcxQueryError::NoDevice(3))), Position::Detached);
    assert_eq!(
        position(5, Err(TcxQueryError::NotPermitted)),
        Position::Unknown("listing tcx programs needs CAP_NET_ADMIN".to_owned())
    );
}

#[test]
fn only_changes_are_reported() {
    let ports = vec![
        WatchedPort { name: "eth0".to_owned(), ifindex: 2 },
        WatchedPort { name: "eth1".to_owned(), ifindex: 3 },
    ];
    let mut watch = CoreWatch::new(5, ports);
    assert_eq!(watch.observe(|_| chain(&[5])), vec![]);
    let eth0_behind = |ifindex| if ifindex == 2 { chain(&[9, 5]) } else { chain(&[5]) };
    assert_eq!(watch.observe(eth0_behind), vec![("eth0".to_owned(), Position::Behind(vec![9]))]);
    assert_eq!(watch.observe(eth0_behind), vec![]);
    assert_eq!(
        watch.observe(|_| chain(&[5])),
        vec![("eth0".to_owned(), Position::First)]
    );
    assert_eq!(
        watch.observe(|ifindex| if ifindex == 3 { Err(TcxQueryError::NoDevice(3)) } else { chain(&[5]) }),
        vec![("eth1".to_owned(), Position::Detached)]
    );
}
