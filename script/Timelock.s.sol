// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

import {Test} from "forge-std/Test.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {TimelockController} from "@openzeppelin/governance/TimelockController.sol";

contract TimelockScript is Test {
    // my test gnosis safe deployment on Goerli
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xC3b0ce69F5B891309584cd4F5c6F9d66E6007E48));
    uint256 internal constant DELAY = 2 days;

    bool internal constant SIMULATE = false;

    TimelockController internal timelockController;

    address[] internal proposers;
    address[] internal executors;

    address internal deployer;

    function setUp() public {
        // MULTI_SIG is the only proposer
        proposers.push(address(MULTI_SIG));

        // We set the MULTI_SIG and all it's owners as executors
        executors = MULTI_SIG.getOwners();
        executors.push(address(MULTI_SIG));
    }

    function run() public {
        if (!SIMULATE) {
            vm.startBroadcast();
            deployer = tx.origin;
        } else {
            deployer = address(this);
        }

        timelockController = new TimelockController(DELAY, proposers, executors);

        if (tx.origin != address(MULTI_SIG)) {
            // Since the deployer is not the multisig we set timeLock admin role to MULTI_SIG and revoke the role to deployer
            _transferAdminToMultisig();
        }

        if (!SIMULATE) {
            vm.stopBroadcast();
        }

        _checkRoles();
    }

    function _transferAdminToMultisig() internal {
        timelockController.grantRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG));
        timelockController.revokeRole(timelockController.TIMELOCK_ADMIN_ROLE(), deployer);
    }

    function _checkRoles() internal {
        // Use reverts instead of asserts in order to not deploy in case the checks fail
        if (!timelockController.hasRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG))) {
            revert("MULTI_SIG doesn't have TIMELOCK_ADMIN_ROLE");
        }
        if (timelockController.hasRole(timelockController.TIMELOCK_ADMIN_ROLE(), deployer)) {
            revert("Deployer has TIMELOCK_ADMIN_ROLE");
        }
    }
}
