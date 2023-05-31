#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Addr, Binary, BlockInfo, CosmosMsg, Decimal, Deps, DepsMut, Empty, Env, MessageInfo,
    Order, Response, StdResult, WasmMsg, Storage,
};
use cw2::set_contract_version;
use cw3::{
    Ballot, Proposal, ProposalListResponse, ProposalResponse, Status, Vote, VoteInfo,
    VoteListResponse, Votes,
};
use cw_utils::{Threshold, ThresholdError};

use crate::error::ContractError;
use crate::msg::{
    AdminListResponse, ExecuteMsg, InstantiateMsg, QueryMsg, ShowConfigResponse,
};

use crate::state::{
    get_number_of_admins, next_proposal_id, ADMINS, ADMIN_VOTING_THRESHOLD, BALLOTS,
    MAX_VOTING_PERIOD, PROPOSALS, EmptyStruct,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:sei-gringotts";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    if msg.admins.is_empty() {
        return Err(ContractError::NoAdmins {});
    }
    if msg.admin_voting_threshold_percentage > 100 {
        return Err(ContractError::Threshold(
            ThresholdError::InvalidThreshold {},
        ));
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    for admin in msg.admins.iter() {
        ADMINS.save(deps.storage, admin, &EmptyStruct {})?;
    }
    MAX_VOTING_PERIOD.save(deps.storage, &msg.max_voting_period)?;
    ADMIN_VOTING_THRESHOLD.save(
        deps.storage,
        &Threshold::AbsolutePercentage {
            percentage: Decimal::percent(msg.admin_voting_threshold_percentage as u64),
        },
    )?;
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<Empty>, ContractError> {
    match msg {
        ExecuteMsg::ProposeInstantiate { code_id, msg, label } => {
            execute_propose_instantiate(deps, env, info, code_id, msg, label)
        }
        ExecuteMsg::ProposeMigrate { contract_addr, new_code_id, msg } => {
            execute_propose_migrate(deps, env, info, contract_addr, new_code_id, msg)
        }
        ExecuteMsg::ProposeUpdateAdmin { admin, contract_addr } => {
            execute_propose_update_admin(deps, env, info, admin, contract_addr)
        }
        ExecuteMsg::VoteProposal { proposal_id } => execute_vote(deps, env, info, proposal_id),
        ExecuteMsg::ProcessProposal { proposal_id } => {
            execute_process_proposal(deps, env, info, proposal_id)
        }
    }
}

fn execute_propose_instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    code_id: u64,
    msg: Binary,
    label: String,
) -> Result<Response<Empty>, ContractError> {
    let title = format!("instantiate {}", code_id);
    let wasm_msg = WasmMsg::Instantiate {
        admin: Some(env.contract.address.to_string()),
        code_id,
        msg,
        funds: info.funds.clone(),
        label,
    };
    execute_propose(
        deps,
        env.clone(),
        info.clone(),
        title.clone(),
        vec![CosmosMsg::Wasm(wasm_msg)],
    )
}

fn execute_propose_migrate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    contract_addr: Addr,
    new_code_id: u64,
    msg: Binary,
) -> Result<Response<Empty>, ContractError> {
    let title = format!("migrate {} to {}", contract_addr.to_string(), new_code_id);
    let wasm_msg = WasmMsg::Migrate { contract_addr: contract_addr.to_string(), new_code_id, msg };
    execute_propose(
        deps,
        env.clone(),
        info.clone(),
        title.clone(),
        vec![CosmosMsg::Wasm(wasm_msg)],
    )
}

fn execute_propose_update_admin(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    admin: Addr,
    contract_addr: Addr,
) -> Result<Response<Empty>, ContractError> {
    let title = format!("update admin of {} to {}", contract_addr.to_string(), admin.to_string());
    let msg = WasmMsg::UpdateAdmin { contract_addr: contract_addr.to_string(), admin: admin.to_string() };
    execute_propose(
        deps,
        env.clone(),
        info.clone(),
        title.clone(),
        vec![CosmosMsg::Wasm(msg)],
    )
}

fn execute_propose(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    title: String,
    msgs: Vec<CosmosMsg>,
) -> Result<Response<Empty>, ContractError> {
    authorize_admin(deps.storage, info.sender.clone())?;

    let expires = MAX_VOTING_PERIOD.load(deps.storage)?.after(&env.block);
    let mut prop = Proposal {
        title: title,
        description: "".to_string(),
        start_height: env.block.height,
        expires,
        msgs: msgs,
        status: Status::Open,
        votes: Votes::yes(1), // every admin has equal voting power, and the proposer automatically votes
        threshold: ADMIN_VOTING_THRESHOLD.load(deps.storage)?,
        total_weight: get_number_of_admins(deps.storage) as u64,
        proposer: info.sender.clone(),
        deposit: None,
    };
    prop.update_status(&env.block);
    let id = next_proposal_id(deps.storage)?;
    PROPOSALS.save(deps.storage, id, &prop)?;

    let ballot = Ballot {
        weight: 1,
        vote: Vote::Yes,
    };
    BALLOTS.save(deps.storage, (id, &info.sender), &ballot)?;

    Ok(Response::new()
        .add_attribute("action", "propose")
        .add_attribute("sender", info.sender)
        .add_attribute("proposal_id", id.to_string())
        .add_attribute("status", format!("{:?}", prop.status)))
}

fn execute_vote(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposal_id: u64,
) -> Result<Response<Empty>, ContractError> {
    authorize_admin(deps.storage, info.sender.clone())?;

    let mut prop = PROPOSALS.load(deps.storage, proposal_id)?;
    if prop.status != Status::Open {
        return Err(ContractError::NotOpen {});
    }
    if prop.expires.is_expired(&env.block) {
        return Err(ContractError::Expired {});
    }

    // cast vote if no vote previously cast
    BALLOTS.update(deps.storage, (proposal_id, &info.sender), |bal| match bal {
        Some(_) => Err(ContractError::AlreadyVoted {}),
        None => Ok(Ballot {
            weight: 1,
            vote: Vote::Yes,
        }),
    })?;

    // update vote tally
    prop.votes.add_vote(Vote::Yes, 1);
    prop.update_status(&env.block);
    PROPOSALS.save(deps.storage, proposal_id, &prop)?;

    Ok(Response::new()
        .add_attribute("action", "vote")
        .add_attribute("sender", info.sender)
        .add_attribute("proposal_id", proposal_id.to_string())
        .add_attribute("status", format!("{:?}", prop.status)))
}

fn execute_process_proposal(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proposal_id: u64,
) -> Result<Response<Empty>, ContractError> {
    authorize_admin(deps.storage, info.sender.clone())?;

    let mut prop = PROPOSALS.load(deps.storage, proposal_id)?;
    // we allow execution even after the proposal "expiration" as long as all vote come in before
    // that point. If it was approved on time, it can be executed any time.
    prop.update_status(&env.block);
    if prop.status != Status::Passed {
        return Err(ContractError::WrongExecuteStatus {});
    }

    // set it to executed
    prop.status = Status::Executed;
    PROPOSALS.save(deps.storage, proposal_id, &prop)?;

    // dispatch all proposed messages
    Ok(Response::new()
        .add_messages(prop.msgs)
        .add_attribute("action", "execute")
        .add_attribute("sender", info.sender)
        .add_attribute("proposal_id", proposal_id.to_string()))
}

fn authorize_admin(store: &dyn Storage, caller: Addr) -> Result<(), ContractError> {
    match ADMINS.load(store, &caller) {
        Ok(_) => Ok(()),
        Err(_) => Err(ContractError::Unauthorized {}),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ListProposals {} => to_binary(&query_proposals(deps, env)?),
        QueryMsg::ListVotes { proposal_id } => to_binary(&query_votes(deps, proposal_id)?),
        QueryMsg::ListAdmins {} => to_binary(&query_admins(deps)?),
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
    }
}

fn query_proposals(deps: Deps, env: Env) -> StdResult<ProposalListResponse> {
    let proposals: Vec<ProposalResponse> = PROPOSALS
        .range(deps.storage, None, None, Order::Descending)
        .map(|p| map_proposal(&env.block, p))
        .collect::<StdResult<_>>()?;
    Ok(ProposalListResponse { proposals })
}

fn map_proposal(
    block: &BlockInfo,
    item: StdResult<(u64, Proposal)>,
) -> StdResult<ProposalResponse> {
    item.map(|(id, prop)| {
        let status = prop.current_status(block);
        let threshold = prop.threshold.to_response(prop.total_weight);
        ProposalResponse {
            id,
            title: prop.title,
            description: prop.description,
            msgs: prop.msgs,
            status,
            deposit: prop.deposit,
            proposer: prop.proposer,
            expires: prop.expires,
            threshold,
        }
    })
}

fn query_votes(deps: Deps, proposal_id: u64) -> StdResult<VoteListResponse> {
    let votes = BALLOTS
        .prefix(proposal_id)
        .range(deps.storage, None, None, Order::Ascending)
        .map(|item| {
            item.map(|(addr, ballot)| VoteInfo {
                proposal_id,
                voter: addr.into(),
                vote: ballot.vote,
                weight: ballot.weight,
            })
        })
        .collect::<StdResult<_>>()?;

    Ok(VoteListResponse { votes })
}

fn query_admins(deps: Deps) -> StdResult<AdminListResponse> {
    let admins: Vec<Addr> = ADMINS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|admin| admin.map(|(admin, _)| -> Addr { admin }))
        .collect::<StdResult<_>>()?;
    Ok(AdminListResponse { admins })
}

fn query_config(deps: Deps) -> StdResult<ShowConfigResponse> {
    Ok(ShowConfigResponse {
        max_voting_period: MAX_VOTING_PERIOD.load(deps.storage)?,
        admin_voting_threshold: ADMIN_VOTING_THRESHOLD.load(deps.storage)?,
    })
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{from_binary, Addr, Coin, Decimal,};

    use cw2::{get_contract_version, ContractVersion};
    use cw_utils::{Duration, Expiration, ThresholdResponse};

    use super::*;

    const OWNER: &str = "admin0001";
    const VOTER1: &str = "voter0001";
    const VOTER2: &str = "voter0002";
    const VOTER3: &str = "voter0003";
    const VOTER4: &str = "voter0004";

    // this will set up the instantiation for other tests
    #[track_caller]
    fn setup_test_case(deps: DepsMut, info: MessageInfo) -> Result<Response<Empty>, ContractError> {
        let instantiate_msg = InstantiateMsg {
            admins: vec![
                Addr::unchecked(VOTER1),
                Addr::unchecked(VOTER2),
                Addr::unchecked(VOTER3),
                Addr::unchecked(VOTER4),
            ],
            max_voting_period: Duration::Time(3600),
            admin_voting_threshold_percentage: 75,
        };
        instantiate(deps, mock_env(), info, instantiate_msg)
    }

    #[test]
    fn test_instantiate_works() {
        let mut deps = mock_dependencies();
        let info = mock_info(OWNER, &[]);

        let _max_voting_period = Duration::Time(1234567);

        // No admins fails
        let instantiate_msg = InstantiateMsg {
            admins: vec![],
            max_voting_period: Duration::Time(3600),
            admin_voting_threshold_percentage: 75,
        };
        let err =
            instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap_err();
        assert_eq!(err, ContractError::NoAdmins {});

        // happy path
        let info = mock_info(OWNER, &[Coin::new(48000000, "usei".to_string())]);
        setup_test_case(deps.as_mut(), info).unwrap();

        // Verify
        assert_eq!(
            ContractVersion {
                contract: CONTRACT_NAME.to_string(),
                version: CONTRACT_VERSION.to_string(),
            },
            get_contract_version(&deps.storage).unwrap()
        )
    }

    #[test]
    fn test_propose_migrate_works() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeMigrate {
            new_code_id: 1,
            contract_addr: mock_env().contract.address,
            msg: Binary(vec![]),
        };
        let res = execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        // Verify
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "propose")
                .add_attribute("sender", VOTER1)
                .add_attribute("proposal_id", 1.to_string())
                .add_attribute("status", "Open")
        );
    }

    #[test]
    fn test_propose_migrate_unauthorized() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(OWNER, &[]);
        let proposal = ExecuteMsg::ProposeMigrate {
            new_code_id: 1,
            contract_addr: mock_env().contract.address,
            msg: Binary(vec![]),
        };
        let err = execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});
    }

    #[test]
    fn test_propose_update_admin_works() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        let res = execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        // Verify
        assert_eq!(
            res,
            Response::new()
                .add_attribute("action", "propose")
                .add_attribute("sender", VOTER1)
                .add_attribute("proposal_id", 1.to_string())
                .add_attribute("status", "Open")
        );
    }

    #[test]
    fn test_propose_update_admin_unauthorized() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(OWNER, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        let err = execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});
    }

    #[test]
    fn test_vote_works() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        let info = mock_info(VOTER2, &[]);
        let vote2 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote2.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let vote3 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote3.clone()).unwrap();
    }

    #[test]
    fn test_vote_expired() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        let info = mock_info(VOTER2, &[]);
        let vote2 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote2.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let vote3 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(3601);
        let err = execute(deps.as_mut(), env, info, vote3.clone()).unwrap_err();
        assert_eq!(err, ContractError::Expired {});
    }

    #[test]
    fn test_process_proposal_works() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        let info = mock_info(VOTER2, &[]);
        let vote2 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote2.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let vote3 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote3.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let process = ExecuteMsg::ProcessProposal { proposal_id: 1 };
        let res = execute(deps.as_mut(), mock_env(), info, process.clone()).unwrap();

        assert_eq!(1, res.messages.len());
    }

    #[test]
    fn test_process_proposal_premature() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        let info = mock_info(VOTER2, &[]);
        let vote2 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote2.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let process = ExecuteMsg::ProcessProposal { proposal_id: 1 };
        let err = execute(deps.as_mut(), mock_env(), info, process.clone()).unwrap_err();

        assert_eq!(err, ContractError::WrongExecuteStatus {});
    }

    #[test]
    fn test_process_update_admin_double_process() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();

        let info = mock_info(VOTER1, &[]);
        let proposal = ExecuteMsg::ProposeUpdateAdmin {
            admin: Addr::unchecked("new_admin1"),
            contract_addr: mock_env().contract.address,
        };
        execute(deps.as_mut(), mock_env(), info, proposal.clone()).unwrap();

        let info = mock_info(VOTER2, &[]);
        let vote2 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote2.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let vote3 = ExecuteMsg::VoteProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, vote3.clone()).unwrap();

        let info = mock_info(VOTER3, &[]);
        let process = ExecuteMsg::ProcessProposal { proposal_id: 1 };
        execute(deps.as_mut(), mock_env(), info, process.clone()).unwrap();
        let info = mock_info(VOTER3, &[]);
        let err = execute(deps.as_mut(), mock_env(), info, process.clone()).unwrap_err();

        assert_eq!(err, ContractError::WrongExecuteStatus {});
    }

    #[test]
    fn test_query_proposals() {
        let mut deps = mock_dependencies();
        PROPOSALS
            .save(
                deps.as_mut().storage,
                1,
                &Proposal {
                    title: "title".to_string(),
                    description: "description".to_string(),
                    start_height: 1,
                    expires: Expiration::Never {},
                    msgs: vec![],
                    status: Status::Open,
                    votes: Votes::yes(1),
                    threshold: Threshold::AbsolutePercentage {
                        percentage: Decimal::percent(75),
                    },
                    total_weight: 4,
                    proposer: Addr::unchecked("proposer"),
                    deposit: None,
                },
            )
            .unwrap();
        let msg = QueryMsg::ListProposals {};
        let bin = query(deps.as_ref(), mock_env(), msg).unwrap();
        let res: ProposalListResponse = from_binary(&bin).unwrap();
        assert_eq!(
            res.proposals,
            vec![ProposalResponse {
                id: 1,
                title: "title".to_string(),
                description: "description".to_string(),
                expires: Expiration::Never {},
                msgs: vec![],
                status: Status::Open,
                threshold: ThresholdResponse::AbsolutePercentage {
                    percentage: Decimal::percent(75),
                    total_weight: 4,
                },
                proposer: Addr::unchecked("proposer"),
                deposit: None,
            }]
        );
    }

    #[test]
    fn test_query_votes() {
        let mut deps = mock_dependencies();
        BALLOTS
            .save(
                deps.as_mut().storage,
                (1, &Addr::unchecked("admin")),
                &Ballot {
                    weight: 1,
                    vote: Vote::Yes,
                },
            )
            .unwrap();
        BALLOTS
            .save(
                deps.as_mut().storage,
                (2, &Addr::unchecked("admin")),
                &Ballot {
                    weight: 1,
                    vote: Vote::No,
                },
            )
            .unwrap();
        let msg = QueryMsg::ListVotes { proposal_id: 1 };
        let bin = query(deps.as_ref(), mock_env(), msg).unwrap();
        let res: VoteListResponse = from_binary(&bin).unwrap();
        assert_eq!(
            res.votes,
            vec![VoteInfo {
                proposal_id: 1,
                voter: "admin".to_string(),
                vote: Vote::Yes,
                weight: 1,
            }]
        );
    }

    #[test]
    fn test_query_admins() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[Coin::new(48000000, "usei".to_string())]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();
        let msg = QueryMsg::ListAdmins {};
        let bin = query(deps.as_ref(), mock_env(), msg).unwrap();
        let res: AdminListResponse = from_binary(&bin).unwrap();
        assert_eq!(
            res.admins,
            vec![
                Addr::unchecked(VOTER1),
                Addr::unchecked(VOTER2),
                Addr::unchecked(VOTER3),
                Addr::unchecked(VOTER4),
            ]
        );
    }

    #[test]
    fn test_query_config() {
        let mut deps = mock_dependencies();

        let info = mock_info(OWNER, &[Coin::new(48000000, "usei".to_string())]);
        setup_test_case(deps.as_mut(), info.clone()).unwrap();
        let msg = QueryMsg::Config {};
        let bin = query(deps.as_ref(), mock_env(), msg).unwrap();
        let res: ShowConfigResponse = from_binary(&bin).unwrap();
        assert_eq!(
            res,
            ShowConfigResponse {
                max_voting_period: Duration::Time(3600),
                admin_voting_threshold: Threshold::AbsolutePercentage {
                    percentage: Decimal::percent(75)
                },
            }
        );
    }
}
