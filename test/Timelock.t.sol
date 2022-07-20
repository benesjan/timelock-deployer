// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

import {Test} from "forge-std/Test.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {Enum} from "safe/common/Enum.sol";
import {TimelockController} from "@openzeppelin/governance/TimelockController.sol";
import {ProxyAdmin} from "@openzeppelin/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/proxy/transparent/TransparentUpgradeableProxy.sol";
import {RollupProcessorV2} from "./processors/RollupProcessorV2.sol";

contract TimelockTest is Test {
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xE298a76986336686CC3566469e3520d23D1a8aaD));
    ProxyAdmin internal constant PROXY_ADMIN = ProxyAdmin(0xC5b735d05c26579B701Be9bED253Bb588503B26B);
    TransparentUpgradeableProxy internal constant PROXY =
    TransparentUpgradeableProxy(payable(0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455));

    // For more details about the params check:
    // https://forum.openzeppelin.com/t/tutorial-on-using-a-gnosis-safe-multisig-with-a-timelock-to-upgrade-contracts-and-use-functions-in-a-proxy-contract/7272
    bytes32 internal constant PREDECESSOR = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant SALT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant DELAY = 2 days;

    bytes upgradeAndCalldata;

    address[] internal proposers;
    address[] internal executors;
    TimelockController internal timelockController;
    RollupProcessorV2 internal newImplementation;

    function setUp() public {
        // MULTI_SIG is the only proposer
        proposers.push(address(MULTI_SIG));

        // We set the MULTI_SIG and all it's owners as executors
        executors = MULTI_SIG.getOwners();
        executors.push(address(MULTI_SIG));

        timelockController = new TimelockController(DELAY, proposers, executors);

        // Set timeLock admin role to MULTI_SIG and revoke the role to deployer
        timelockController.grantRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG));
        timelockController.revokeRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(this));

        newImplementation = new RollupProcessorV2(block.number, block.number);

        upgradeAndCalldata = abi.encodeWithSignature(
            "upgradeAndCall(address,address,bytes)",
            address(PROXY),
            address(newImplementation),
            abi.encodeWithSignature("initialize()")
        );

        vm.label(address(MULTI_SIG), "MULTI_SIG");
        vm.label(address(PROXY), "PROXY");
        vm.label(address(timelockController), "timelockController");
        vm.label(address(newImplementation), "newImplementation");
    }

    function testAddressesAndRoles() public {
        assertEq(PROXY_ADMIN.getProxyAdmin(PROXY), address(PROXY_ADMIN), "Incorrect PROXY_ADMIN");
        assertEq(PROXY_ADMIN.owner(), address(MULTI_SIG), "Incorrect MULTI_SIG");
        assertTrue(
            timelockController.hasRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(MULTI_SIG)),
            "MULTI_SIG doesn't have TIMELOCK_ADMIN_ROLE"
        );
        assertFalse(
            timelockController.hasRole(timelockController.TIMELOCK_ADMIN_ROLE(), address(this)),
            "Deployer has TIMELOCK_ADMIN_ROLE"
        );
        uint256 i;
        for (; i < proposers.length; ++i) {
            assertTrue(
                timelockController.hasRole(timelockController.PROPOSER_ROLE(), proposers[i]),
                "Proposer doesn't have PROPOSER_ROLE"
            );
        }
        for (i = 0; i < executors.length; ++i) {
            assertTrue(
                timelockController.hasRole(timelockController.EXECUTOR_ROLE(), executors[i]),
                "Executor doesn't have EXECUTOR_ROLE"
            );
        }
    }

    function testOwnershipTransfer() public {
        vm.prank(address(MULTI_SIG));
        PROXY_ADMIN.transferOwnership(address(timelockController));

        assertEq(PROXY_ADMIN.owner(), address(timelockController), "timelockController is not the new owner");
    }

    function testImplementationChangeThroughTimelock() public {
        vm.startPrank(address(MULTI_SIG));

        // Set timelock as the new owner of PROXY_ADMIN
        PROXY_ADMIN.transferOwnership(address(timelockController));

        timelockController.schedule(address(PROXY_ADMIN), 0, upgradeAndCalldata, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + DELAY);

        // Try to execute the scheduled call
        timelockController.execute(address(PROXY_ADMIN), 0, upgradeAndCalldata, PREDECESSOR, SALT);

        vm.stopPrank();

        assertEq(PROXY_ADMIN.getProxyImplementation(PROXY), address(newImplementation));
    }

    function testImplementationChangeThroughTimelockAndMultisig() public {
        // Set timelock as the new owner of PROXY_ADMIN
        vm.prank(address(MULTI_SIG));
        PROXY_ADMIN.transferOwnership(address(timelockController));

        // Schedule the upgradeAndCall tx through GnosisSafe
        bytes memory scheduleCalldata = abi.encodeWithSignature(
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
            address(PROXY_ADMIN),
            0,
            upgradeAndCalldata,
            PREDECESSOR,
            SALT,
            DELAY
        );

        bytes32 actionHash = MULTI_SIG.getTransactionHash(
            address(timelockController), // target
            uint256(0), // value
            scheduleCalldata, // data
            Enum.Operation.Call,
            1e6, // safeTxGas
            10000, // baseGas
            0, // gasPrice
            address(0), // gastoken,
            address(0), // refund receiver
            MULTI_SIG.nonce()
        );

        bytes memory sigs = abi.encodePacked(bytes32(uint256(uint160(executors[0]))), bytes32(uint256(0)), uint8(1));

        vm.startPrank(executors[0]);
        MULTI_SIG.approveHash(actionHash);

        MULTI_SIG.execTransaction(
            address(timelockController), // target
            0, // value
            scheduleCalldata, // data
            Enum.Operation.Call,
            1e6, // safeTxGas
            10000, // baseGas
            0, // gasPrice
            address(0), // gastoken,
            payable(address(0)), // refund receiver
            sigs
        );

        vm.stopPrank();

        vm.warp(block.timestamp + DELAY);

        // Try to execute the scheduled call
        vm.prank(executors[0]);
        timelockController.execute(address(PROXY_ADMIN), 0, upgradeAndCalldata, PREDECESSOR, SALT);

        assertEq(PROXY_ADMIN.getProxyImplementation(PROXY), address(newImplementation));
    }

    function testExecutionFailsWhenNotEnoughTimeHavePassed() public {
        vm.startPrank(address(MULTI_SIG));

        // Set timelock as the new owner of PROXY_ADMIN
        PROXY_ADMIN.transferOwnership(address(timelockController));

        timelockController.schedule(address(PROXY_ADMIN), 0, upgradeAndCalldata, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + 1 days);

        vm.expectRevert("TimelockController: operation is not ready");
        // Try to execute the scheduled call
        timelockController.execute(address(PROXY_ADMIN), 0, upgradeAndCalldata, PREDECESSOR, SALT);

        vm.stopPrank();
    }
}
