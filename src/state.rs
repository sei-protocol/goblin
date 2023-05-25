use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Storage, StdResult};
use cw3::{Ballot, Proposal};
use cw_storage_plus::{Map, Item};
use cw_utils::{Duration, Threshold};

#[cw_serde]
pub struct EmptyStruct {}

pub const ADMINS: Map<&Addr, EmptyStruct> = Map::new("admins");
pub fn get_number_of_admins(store: &dyn Storage) -> usize {
    ADMINS
        .keys(
            store,
            Option::None,
            Option::None,
            cosmwasm_std::Order::Ascending,
        )
        .count()
}

// ADMIN STATES
pub const MAX_VOTING_PERIOD: Item<Duration> = Item::new("max_voting_period");
pub const ADMIN_VOTING_THRESHOLD: Item<Threshold> = Item::new("threshold");

pub const PROPOSAL_COUNT: Item<u64> = Item::new("proposal_count");
pub const BALLOTS: Map<(u64, &Addr), Ballot> = Map::new("votes");
pub const PROPOSALS: Map<u64, Proposal> = Map::new("proposals");

pub fn next_proposal_id(store: &mut dyn Storage) -> StdResult<u64> {
    let id: u64 = PROPOSAL_COUNT.may_load(store)?.unwrap_or_default() + 1;
    PROPOSAL_COUNT.save(store, &id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{testing::mock_dependencies, Addr};

    use crate::{
        state::{EmptyStruct, get_number_of_admins, ADMINS},
    };

    #[test]
    fn test_get_number_of_admins() {
        let mut deps = mock_dependencies();
        assert_eq!(0, get_number_of_admins(deps.as_ref().storage));

        ADMINS
            .save(
                deps.as_mut().storage,
                &Addr::unchecked("admin"),
                &EmptyStruct {},
            )
            .unwrap();
        assert_eq!(1, get_number_of_admins(deps.as_ref().storage));
        ADMINS
            .save(
                deps.as_mut().storage,
                &Addr::unchecked("admin2"),
                &EmptyStruct {},
            )
            .unwrap();
        assert_eq!(2, get_number_of_admins(deps.as_ref().storage));
    }
}