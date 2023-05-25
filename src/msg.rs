use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Binary};
use cw_utils::{Duration, Threshold};

#[cw_serde]
pub struct InstantiateMsg {
    pub admins: Vec<Addr>,
    pub max_voting_period: Duration,
    pub admin_voting_threshold_percentage: u8,
}

#[cw_serde]
pub enum ExecuteMsg {
    ProposeMigrate {
        contract_addr: Addr,
        new_code_id: u64,
        /// msg is the json-encoded MigrateMsg struct that will be passed to the new code
        msg: Binary,
    },
    ProposeUpdateAdmin {
        contract_addr: Addr,
        admin: Addr,
    },
    VoteProposal {
        proposal_id: u64,
    },
    ProcessProposal {
        proposal_id: u64,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(cw3::ProposalListResponse)]
    ListProposals {},
    #[returns(cw3::VoteListResponse)]
    ListVotes { proposal_id: u64 },
    #[returns(AdminListResponse)]
    ListAdmins {},
    #[returns(ShowConfigResponse)]
    Config {},
}

#[cw_serde]
pub struct AdminListResponse {
    pub admins: Vec<Addr>,
}

#[cw_serde]
pub struct ShowConfigResponse {
    pub max_voting_period: Duration,
    pub admin_voting_threshold: Threshold,
}
