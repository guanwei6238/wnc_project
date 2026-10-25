use crate::kernel::nft::{self, BaseChain, Family, Hook, NftError, Policy, Statement, Table};

pub const FAMILY: Family = Family::Inet;
pub const TABLE: &str = "wnc_gw";
const PRIORITY_FILTER: i32 = 0;

pub async fn install() -> Result<(), NftError> {
    nft::replace_table(&table()).await
}

pub async fn remove() -> Result<(), NftError> {
    nft::delete_table(FAMILY, TABLE).await
}

fn table() -> Table {
    Table {
        family: FAMILY,
        name: TABLE.to_owned(),
        chains: vec![BaseChain {
            name: "forward".to_owned(),
            hook: Hook::Forward,
            priority: PRIORITY_FILTER,
            policy: Policy::Accept,
            rules: vec![vec![Statement::Counter]],
        }],
    }
}

#[cfg(test)]
#[path = "../tests/unit/firewall.rs"]
mod tests;
