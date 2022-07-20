// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

import {Script} from "forge-std/Script.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {TimelockController} from "@openzeppelin/governance/TimelockController.sol";


contract TimelockScript is Script {
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xC3b0ce69F5B891309584cd4F5c6F9d66E6007E48));
    uint256 internal constant DELAY = 2 days;

    address[] internal proposers;
    address[] internal executors;

    function setUp() public {
        // MULTI_SIG is the only proposer
        proposers.push(address(MULTI_SIG));

        // We set the MULTI_SIG and all it's owners as executors
        executors = MULTI_SIG.getOwners();
        executors.push(address(MULTI_SIG));
    }

    function run() public {
        vm.startBroadcast();

        TimelockController timelockController = new TimelockController(DELAY, proposers, executors);

        // Set timeLock admin role to MULTI_SIG and revoke the role to deployer
        timelockController.grantRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG));
        timelockController.revokeRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(this));

        vm.stopBroadcast();
    }
}
