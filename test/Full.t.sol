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

import {Full} from "../script/Full.s.sol";

contract FullTest is Full {
    GnosisSafe internal constant MULTI_SIG = GnosisSafe(payable(0xE298a76986336686CC3566469e3520d23D1a8aaD));
    ProxyAdmin internal constant PROXY_ADMIN = ProxyAdmin(0xC5b735d05c26579B701Be9bED253Bb588503B26B);
    TransparentUpgradeableProxy internal constant PROXY =
        TransparentUpgradeableProxy(payable(0xFF1F2B4ADb9dF6FC8eAFecDcbF96A2B351680455));

    // For more details about the params check:
    // https://forum.openzeppelin.com/t/tutorial-on-using-a-gnosis-safe-multisig-with-a-TIME_LOCK-to-upgrade-contracts-and-use-functions-in-a-proxy-contract/7272
    bytes32 internal constant PREDECESSOR = 0x0000000000000000000000000000000000000000000000000000000000000000;
    bytes32 internal constant SALT = 0x0000000000000000000000000000000000000000000000000000000000000000;
    uint256 internal constant DELAY = 10 days;

    RollupProcessorV2 internal newImplementation;

    bytes upgradeCalldata;

    function setUp() public override {
        UPDATE_MULTISIGS = false;
        simulate = true;
        super.setUp();
        fullSetup();

        newImplementation = new RollupProcessorV2(block.number, block.number);

        upgradeCalldata = abi.encodeWithSignature(
            "upgradeAndCall(address,address,bytes)",
            address(PROXY),
            address(newImplementation),
            abi.encodeWithSignature("initialize()")
        );

        // TODO: current multisig must pass over ownership of contract to controller
        vm.prank(address(MULTI_SIG));
        PROXY_ADMIN.transferOwnership(address(CONTROLLER));
    }

    /**
     * @notice Test that emergency update safe has admin of roles on controller
     */
    function testUpdateRoleControllerWithEmergencyUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = CONTROLLER.TIMELOCK_ADMIN_ROLE();
        assertFalse(CONTROLLER.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        vm.prank(address(MS_EMERGENCY_UPDATE));
        CONTROLLER.grantRole(TIMELOCK_ADMIN_ROLE, address(0xdead));

        assertTrue(CONTROLLER.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    /**
     * @notice Test that schedule can update roles on controller after delay
     */
    function testUpdateRoleControllerWithScheduledUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = CONTROLLER.TIMELOCK_ADMIN_ROLE();
        assertFalse(CONTROLLER.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        bytes memory grantCallData =
            abi.encodeWithSignature("grantRole(bytes32,address)", TIMELOCK_ADMIN_ROLE, address(0xdead));

        vm.prank(address(MS_SCHEDULED_UPDATE));
        TIME_LOCK.schedule(address(CONTROLLER), 0, grantCallData, SALT, PREDECESSOR, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(address(MS_MAINTENANCE));
        TIME_LOCK.execute(address(CONTROLLER), 0, grantCallData, SALT, PREDECESSOR);

        assertTrue(CONTROLLER.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    /**
     * @notice Test that emergency update has admin of timelock
     */
    function testUpdateRoleTimelockWithEmergencyUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = TIME_LOCK.TIMELOCK_ADMIN_ROLE();
        assertFalse(TIME_LOCK.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        vm.prank(address(MS_EMERGENCY_UPDATE));
        TIME_LOCK.grantRole(TIMELOCK_ADMIN_ROLE, address(0xdead));

        assertTrue(TIME_LOCK.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    /**
     * @notice Test that timelock has admin of timelock
     */
    function testUpdateRoleTimelockWithScheduledUpdateMs() public {
        bytes32 TIMELOCK_ADMIN_ROLE = TIME_LOCK.TIMELOCK_ADMIN_ROLE();
        assertFalse(TIME_LOCK.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));

        bytes memory grantCallData =
            abi.encodeWithSignature("grantRole(bytes32,address)", TIMELOCK_ADMIN_ROLE, address(0xdead));

        vm.prank(address(MS_SCHEDULED_UPDATE));
        TIME_LOCK.schedule(address(TIME_LOCK), 0, grantCallData, SALT, PREDECESSOR, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(address(MS_MAINTENANCE));
        TIME_LOCK.execute(address(TIME_LOCK), 0, grantCallData, SALT, PREDECESSOR);

        assertTrue(TIME_LOCK.hasRole(TIMELOCK_ADMIN_ROLE, address(0xdead)));
    }

    /**
     * @notice Test that schedules an upgrade and executes it after delay
     */
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

        vm.prank(address(MS_SCHEDULED_UPDATE));
        TIME_LOCK.schedule(address(CONTROLLER), 0, wrappedUpgradeCallData, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + DELAY);

        vm.prank(address(MS_MAINTENANCE));
        TIME_LOCK.execute(address(CONTROLLER), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);

        vm.prank(address(MS_MAINTENANCE));
        CONTROLLER.execute(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT);

        address impl = PROXY_ADMIN.getProxyImplementation(PROXY);
        assertEq(impl, address(newImplementation));
    }

    /**
     * @notice Test that schedule upgrade and uses emergency to cancel it
     */
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

        vm.prank(address(MS_SCHEDULED_UPDATE));
        TIME_LOCK.schedule(address(CONTROLLER), 0, wrappedUpgradeCallData, PREDECESSOR, SALT, DELAY);

        vm.warp(block.timestamp + DELAY / 2);

        bytes32 cancelId = TIME_LOCK.hashOperation(address(CONTROLLER), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);
        assertTrue(TIME_LOCK.isOperationPending(cancelId));

        vm.prank(address(MS_EMERGENCY_UPDATE));
        TIME_LOCK.cancel(cancelId);

        assertFalse(TIME_LOCK.isOperationPending(cancelId));

        vm.warp(block.timestamp + DELAY);

        vm.prank(address(MS_MAINTENANCE));
        vm.expectRevert("TimelockController: operation is not ready");
        TIME_LOCK.execute(address(CONTROLLER), 0, wrappedUpgradeCallData, PREDECESSOR, SALT);
    }

    /**
     * @notice Test that perform an emergency upgrade
     */
    function testEmergencyUpgrade() public {
        vm.prank(address(MS_EMERGENCY_UPDATE));
        CONTROLLER.schedule(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT, 0);

        vm.prank(address(MS_MAINTENANCE));
        CONTROLLER.execute(address(PROXY_ADMIN), 0, upgradeCalldata, PREDECESSOR, SALT);

        address impl = PROXY_ADMIN.getProxyImplementation(PROXY);

        assertEq(impl, address(newImplementation));
    }
}
