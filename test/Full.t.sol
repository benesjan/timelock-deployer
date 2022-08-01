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

contract FullTest is Test {
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xE298a76986336686CC3566469e3520d23D1a8aaD));
    ProxyAdmin internal constant PROXY_ADMIN = ProxyAdmin(0xC5b735d05c26579B701Be9bED253Bb588503B26B);
    TransparentUpgradeableProxy internal constant PROXY =
        TransparentUpgradeableProxy(payable(0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455));

    // For more details about the params check:
    // https://forum.openzeppelin.com/t/tutorial-on-using-a-gnosis-safe-multisig-with-a-timelock-to-upgrade-contracts-and-use-functions-in-a-proxy-contract/7272
    bytes32 internal constant PREDECESSOR = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant SALT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant DELAY = 10 days;

    address internal constant MAINTENANCE_MS = address(uint160(uint256(keccak256("MAINTENANCE"))));
    address internal constant EMERGENCY_UPDATE_MS = address(uint160(uint256(keccak256("EMERGENCY_UPDATE"))));
    address internal constant SCHEDULED_UPDATE_MS = address(uint160(uint256(keccak256("SCHEDULED_UPDATE"))));
    address internal constant RESUME_MS = address(uint160(uint256(keccak256("RESUME"))));
    address internal constant EMERGENCY_MS = address(uint160(uint256(keccak256("EMERGENCY"))));

    TimelockController internal controller;
    TimelockController internal timelock;

    RollupProcessorV2 internal newImplementation;

    bytes upgradeCalldata;

    function setupTimelock() public {
        address[] memory proposers = new address[](2);
        proposers[0] = SCHEDULED_UPDATE_MS;
        proposers[1] = EMERGENCY_UPDATE_MS;

        address[] memory executors = new address[](3);
        executors[0] = SCHEDULED_UPDATE_MS;
        executors[1] = EMERGENCY_UPDATE_MS;
        executors[2] = MAINTENANCE_MS;

        timelock = new TimelockController(DELAY, proposers, executors);

        timelock.grantRole(timelock.TIMELOCK_ADMIN_ROLE(), EMERGENCY_UPDATE_MS);
        timelock.revokeRole(timelock.TIMELOCK_ADMIN_ROLE(), address(this));
    }

    function setupController() public {
        require(address(timelock) != address(0), "undefined timelock controller");

        address[] memory proposers = new address[](2);
        proposers[0] = address(timelock);
        proposers[1] = EMERGENCY_UPDATE_MS;

        address[] memory executors = new address[](3);
        executors[0] = address(timelock);
        executors[1] = EMERGENCY_UPDATE_MS;
        executors[2] = MAINTENANCE_MS;

        controller = new TimelockController(0, proposers, executors);

        controller.grantRole(controller.TIMELOCK_ADMIN_ROLE(), address(timelock));
        controller.grantRole(controller.TIMELOCK_ADMIN_ROLE(), EMERGENCY_UPDATE_MS);
        controller.grantRole(controller.CANCELLER_ROLE(), EMERGENCY_UPDATE_MS);

        // ###### Below here needs interaction

        // TODO: The emergency update ms needs to remove the powers of the deployer
        vm.prank(EMERGENCY_UPDATE_MS);
        controller.revokeRole(controller.TIMELOCK_ADMIN_ROLE(), address(this));

        // TODO: current multisig must pass over ownership of contract to controller
        vm.prank(address(MULTI_SIG));
        PROXY_ADMIN.transferOwnership(address(controller));
    }

    function setupLabels() public {
        vm.label(MAINTENANCE_MS, "MAINTENANCE_MS");
        vm.label(EMERGENCY_UPDATE_MS, "EMERGENCY_UPDATE_MS");
        vm.label(SCHEDULED_UPDATE_MS, "SCHEDULED_UPDATE_MS");
        vm.label(RESUME_MS, "RESUME_MS");
        vm.label(EMERGENCY_MS, "EMERGENCY_MS");

        vm.label(address(MULTI_SIG), "MULTI_SIG");
        vm.label(address(PROXY), "PROXY");
        vm.label(address(timelock), "TimelockController");
        vm.label(address(controller), "Controller");
    }

    function setUp() public {
        setupTimelock();
        setupController();
        setupLabels();

        newImplementation = new RollupProcessorV2(block.number, block.number);

        upgradeCalldata = abi.encodeWithSignature(
            "upgradeAndCall(address,address,bytes)",
            address(PROXY),
            address(newImplementation),
            abi.encodeWithSignature("initialize()")
        );
    }

    function testControllerRoles() public {
        // Admin
        assertFalse(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), address(this)));
        assertFalse(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), MAINTENANCE_MS));
        assertFalse(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), SCHEDULED_UPDATE_MS));
        assertFalse(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), RESUME_MS));
        assertFalse(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), EMERGENCY_MS));
        assertTrue(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), EMERGENCY_UPDATE_MS));
        assertTrue(controller.hasRole(controller.TIMELOCK_ADMIN_ROLE(), address(timelock)));

        // Proposers
        assertFalse(controller.hasRole(controller.PROPOSER_ROLE(), MAINTENANCE_MS));
        assertFalse(controller.hasRole(controller.PROPOSER_ROLE(), RESUME_MS));
        assertFalse(controller.hasRole(controller.PROPOSER_ROLE(), SCHEDULED_UPDATE_MS));
        assertFalse(controller.hasRole(controller.PROPOSER_ROLE(), EMERGENCY_MS));
        assertTrue(controller.hasRole(controller.PROPOSER_ROLE(), EMERGENCY_UPDATE_MS));
        assertTrue(controller.hasRole(controller.PROPOSER_ROLE(), address(timelock)));

        // Executors
        assertFalse(controller.hasRole(controller.EXECUTOR_ROLE(), RESUME_MS));
        assertFalse(controller.hasRole(controller.EXECUTOR_ROLE(), EMERGENCY_MS));
        assertFalse(controller.hasRole(controller.EXECUTOR_ROLE(), SCHEDULED_UPDATE_MS));
        assertTrue(controller.hasRole(controller.EXECUTOR_ROLE(), EMERGENCY_UPDATE_MS));
        assertTrue(controller.hasRole(controller.EXECUTOR_ROLE(), MAINTENANCE_MS));
        assertTrue(controller.hasRole(controller.EXECUTOR_ROLE(), address(timelock)));

        // Cancellers
        assertFalse(controller.hasRole(controller.CANCELLER_ROLE(), RESUME_MS));
        assertFalse(controller.hasRole(controller.CANCELLER_ROLE(), EMERGENCY_MS));
        assertFalse(controller.hasRole(controller.CANCELLER_ROLE(), MAINTENANCE_MS));
        assertFalse(controller.hasRole(controller.CANCELLER_ROLE(), SCHEDULED_UPDATE_MS));
        assertTrue(controller.hasRole(controller.CANCELLER_ROLE(), address(timelock)));
        assertTrue(controller.hasRole(controller.CANCELLER_ROLE(), EMERGENCY_UPDATE_MS));
    }

    function testTimelockRoles() public {
        // Admin
        assertFalse(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), address(this)));
        assertFalse(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), MAINTENANCE_MS));
        assertFalse(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), SCHEDULED_UPDATE_MS));
        assertFalse(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), RESUME_MS));
        assertFalse(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), EMERGENCY_MS));
        assertTrue(timelock.hasRole(timelock.TIMELOCK_ADMIN_ROLE(), EMERGENCY_UPDATE_MS));

        // Proposers
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), MAINTENANCE_MS));
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), RESUME_MS));
        assertFalse(timelock.hasRole(timelock.PROPOSER_ROLE(), EMERGENCY_MS));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), EMERGENCY_UPDATE_MS));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), SCHEDULED_UPDATE_MS));

        // Executors
        assertFalse(timelock.hasRole(timelock.EXECUTOR_ROLE(), RESUME_MS));
        assertFalse(timelock.hasRole(timelock.EXECUTOR_ROLE(), EMERGENCY_MS));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), SCHEDULED_UPDATE_MS));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), EMERGENCY_UPDATE_MS));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), MAINTENANCE_MS));

        // Cancellers
        assertFalse(timelock.hasRole(timelock.CANCELLER_ROLE(), RESUME_MS));
        assertFalse(timelock.hasRole(timelock.CANCELLER_ROLE(), EMERGENCY_MS));
        assertFalse(timelock.hasRole(timelock.CANCELLER_ROLE(), MAINTENANCE_MS));
        assertTrue(timelock.hasRole(timelock.CANCELLER_ROLE(), SCHEDULED_UPDATE_MS));
        assertTrue(timelock.hasRole(timelock.CANCELLER_ROLE(), EMERGENCY_UPDATE_MS));
    }

    function testUpdateRoleControllerWithEmergencyUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = controller.TIMELOCK_ADMIN_ROLE();
        assertFalse(controller.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        vm.prank(EMERGENCY_UPDATE_MS);
        controller.grantRole(TIMELOCK_ADMIN_ROLE, address(0xdead));

        assertTrue(controller.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    function testUpdateRoleControllerWithScheduledUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = controller.TIMELOCK_ADMIN_ROLE();
        assertFalse(controller.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        bytes memory grantCallData =
            abi.encodeWithSignature("grantRole(bytes32,address)", TIMELOCK_ADMIN_ROLE, address(0xdead));

        vm.prank(SCHEDULED_UPDATE_MS);
        timelock.schedule(address(controller), 0, grantCallData, SALT, PREDECESSOR, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(MAINTENANCE_MS);
        timelock.execute(address(controller), 0, grantCallData, SALT, PREDECESSOR);

        assertTrue(controller.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    function testUpdateRoleTimelockWithEmergencyUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = timelock.TIMELOCK_ADMIN_ROLE();
        assertFalse(timelock.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        vm.prank(EMERGENCY_UPDATE_MS);
        timelock.grantRole(TIMELOCK_ADMIN_ROLE, address(0xdead));

        assertTrue(timelock.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    function testUpdateRoleTimelockWithScheduledUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = timelock.TIMELOCK_ADMIN_ROLE();
        assertFalse(timelock.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        bytes memory grantCallData =
            abi.encodeWithSignature("grantRole(bytes32,address)", TIMELOCK_ADMIN_ROLE, address(0xdead));

        vm.prank(SCHEDULED_UPDATE_MS);
        timelock.schedule(address(timelock), 0, grantCallData, SALT, PREDECESSOR, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(MAINTENANCE_MS);
        timelock.execute(address(timelock), 0, grantCallData, SALT, PREDECESSOR);

        assertTrue(timelock.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    function testScheduledUpgrade() public {
        bytes memory wrappedUpgradeCallData = abi.encodeWithSignature(
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
            address(PROXY_ADMIN),
            0,
            upgradeCalldata,
            PREDECESSOR,
            SALT,
            0
        );

        vm.prank(SCHEDULED_UPDATE_MS);
        timelock.schedule(address(controller), 0, wrappedUpgradeCallData, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(MAINTENANCE_MS);
        timelock.execute(address(controller), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);

        vm.prank(MAINTENANCE_MS);
        controller.execute(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT);

        address impl = PROXY_ADMIN.getProxyImplementation(PROXY);
        assertEq(impl, address(newImplementation));
    }

    function testScheduledUpgradeCancelled() public {
        bytes memory wrappedUpgradeCallData = abi.encodeWithSignature(
            "schedule(address,uint256,bytes,bytes32,bytes32,uint256)",
            address(PROXY_ADMIN),
            0,
            upgradeCalldata,
            PREDECESSOR,
            SALT,
            0
        );

        vm.prank(SCHEDULED_UPDATE_MS);
        timelock.schedule(address(controller), 0, wrappedUpgradeCallData, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + DELAY / 2);

        bytes32 cancelId = timelock.hashOperation(address(controller), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);
        assertTrue(timelock.isOperationPending(cancelId));

        vm.prank(EMERGENCY_UPDATE_MS);
        timelock.cancel(cancelId);

        assertFalse(timelock.isOperationPending(cancelId));

        vm.warp(block.timestamp + DELAY);

        vm.prank(MAINTENANCE_MS);
        vm.expectRevert("TimelockController: operation is not ready");
        timelock.execute(address(controller), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);
    }

    function testEmergencyUpgrade() public {
        vm.prank(EMERGENCY_UPDATE_MS);
        controller.schedule(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT, 0);

        vm.prank(MAINTENANCE_MS);
        controller.execute(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT);

        address impl = PROXY_ADMIN.getProxyImplementation(PROXY);

        assertEq(impl, address(newImplementation));
    }
}
