// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

import {Test} from "forge-std/Test.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {TimelockController} from "@openzeppelin/governance/TimelockController.sol";

contract DeploymentTest is Test {
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xC3b0ce69F5B891309584cd4F5c6F9d66E6007E48));
    TimelockController internal constant TIMELOCK_CONTROLLER = TimelockController(payable(0x6352f096c25881Fe16E83c5C3CE53E5E6E96EA9e));
    address internal constant DEPLOYER = 0xFf3170A4F117A18740A65C56fCbdd886ADC09a44;

    address[] internal proposers;
    address[] internal executors;

    function setUp() public {
        // MULTI_SIG is the only proposer
        proposers.push(address(MULTI_SIG));

        // We set the MULTI_SIG and all it's owners as executors
        executors = MULTI_SIG.getOwners();
        executors.push(address(MULTI_SIG));

        vm.label(address(MULTI_SIG), "MULTI_SIG");
        vm.label(address(TIMELOCK_CONTROLLER), "timelockController");
    }

    function testDeployment() public {
        assertTrue(
            TIMELOCK_CONTROLLER.hasRole(TIMELOCK_CONTROLLER.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG)),
            "MULTI_SIG doesn't have TIMELOCK_ADMIN_ROLE"
        );
        assertFalse(
            TIMELOCK_CONTROLLER.hasRole(TIMELOCK_CONTROLLER.TIMELOCK_ADMIN_ROLE(), address(this)),
            "Deployer has TIMELOCK_ADMIN_ROLE"
        );
    }
}
