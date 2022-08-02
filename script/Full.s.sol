// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

import {Test} from "forge-std/Test.sol";
import {GnosisSafe} from "safe/GnosisSafe.sol";
import {GnosisSafeProxyFactory} from "safe/proxies/GnosisSafeProxyFactory.sol";
import {MultiSend} from "safe/libraries/MultiSend.sol";
import {Enum} from "safe/common/Enum.sol";
import {TimelockController} from "@openzeppelin/governance/TimelockController.sol";

contract Full is Test {
    bool internal UPDATE_MULTISIGS = true;

    address internal constant SINGLETON = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    GnosisSafeProxyFactory internal constant FACTORY =
        GnosisSafeProxyFactory(0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2);

    uint256 internal constant PRIVATE_KEY = 123124123123123;
    address internal DEPLOYER;

    GnosisSafe internal MS_MAINTENANCE;
    GnosisSafe internal MS_EMERGENCY_UPDATE;
    GnosisSafe internal MS_SCHEDULED_UPDATE;
    GnosisSafe internal MS_RESUME;
    GnosisSafe internal MS_EMERGENCY = GnosisSafe(payable(0x23f8008159C0427458b948c3DD7795c6DBE8236F));

    TimelockController internal TIME_LOCK;
    uint256 internal constant TIME_LOCK_DELAY = 10 days;

    TimelockController internal CONTROLLER;
    uint256 internal constant CONTROLLER_DELAY = 0;

    MultiSend internal constant MULTI_SEND = MultiSend(0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761);

    address internal constant FALLBACK_HANDLER = 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;

    function setUp() public virtual {
        DEPLOYER = vm.addr(PRIVATE_KEY);
    }

    function label() public {
        vm.label(address(MS_MAINTENANCE), "MS_MAINTENANCE");
        vm.label(address(MS_EMERGENCY_UPDATE), "MS_EMERGENCY_UPDATE");
        vm.label(address(MS_SCHEDULED_UPDATE), "MS_SCHEDULED_UPDATE");
        vm.label(address(MS_RESUME), "MS_RESUME");
        vm.label(address(MS_EMERGENCY), "MS_EMERGENCY");
        vm.label(address(TIME_LOCK), "TIME_LOCK");
        vm.label(address(CONTROLLER), "CONTROLLER");
        vm.label(address(DEPLOYER), "DEPLOYER");
        vm.label(address(MULTI_SEND), "MULTI_SEND");
        vm.label(address(FALLBACK_HANDLER), "FALLBACK_HANDLER");
        vm.label(address(SINGLETON), "SINGLETON");
    }

    function deployMultisig(address[] memory _signers, uint256 _threshold) public returns (GnosisSafe) {
        bytes memory initializer = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            _signers,
            _threshold,
            address(0),
            bytes(""),
            FALLBACK_HANDLER, // fallback handler
            address(0),
            0,
            address(0)
        );

        return GnosisSafe(payable(address(FACTORY.createProxy(SINGLETON, initializer))));
    }

    function deployTimelock() public {
        emit log("= Timelock");
        address[] memory proposers = new address[](2);
        proposers[0] = address(MS_SCHEDULED_UPDATE);
        proposers[1] = address(MS_EMERGENCY_UPDATE);

        address[] memory executors = new address[](3);
        executors[0] = address(MS_SCHEDULED_UPDATE);
        executors[1] = address(MS_EMERGENCY_UPDATE);
        executors[2] = address(MS_MAINTENANCE);

        TIME_LOCK = new TimelockController(
            TIME_LOCK_DELAY,
            proposers,
            executors
        );
        emit log_named_address("TIME_LOCK          ", address(TIME_LOCK));

        bytes32 adminRole = TIME_LOCK.TIMELOCK_ADMIN_ROLE();

        TIME_LOCK.grantRole(adminRole, address(MS_EMERGENCY_UPDATE));
        emit log_named_address("Granted admin to   ", address(MS_EMERGENCY_UPDATE));

        TIME_LOCK.revokeRole(adminRole, DEPLOYER);
        emit log_named_address("Revoked admin from ", DEPLOYER);
    }

    function deployController() public {
        emit log("= Controller");
        address[] memory proposers = new address[](2);
        proposers[0] = address(TIME_LOCK);
        proposers[1] = address(MS_EMERGENCY_UPDATE);

        address[] memory executors = new address[](3);
        executors[0] = address(TIME_LOCK);
        executors[1] = address(MS_EMERGENCY_UPDATE);
        executors[2] = address(MS_MAINTENANCE);

        CONTROLLER = new TimelockController(
            CONTROLLER_DELAY,
            proposers,
            executors
        );
        emit log_named_address("CONTROLLER         ", address(CONTROLLER));

        bytes32 adminRole = CONTROLLER.TIMELOCK_ADMIN_ROLE();
        bytes32 cancellerRole = CONTROLLER.CANCELLER_ROLE();

        CONTROLLER.grantRole(cancellerRole, address(MS_EMERGENCY_UPDATE));
        emit log_named_address("Granted cancel to  ", address(MS_EMERGENCY_UPDATE));

        CONTROLLER.grantRole(adminRole, address(MS_EMERGENCY_UPDATE));
        emit log_named_address("Granted admin to   ", address(MS_EMERGENCY_UPDATE));

        CONTROLLER.grantRole(adminRole, address(TIME_LOCK));
        emit log_named_address("Granted admin to   ", address(TIME_LOCK));

        CONTROLLER.revokeRole(adminRole, DEPLOYER);
        emit log_named_address("Revoked admin from ", DEPLOYER);
    }

    function deployMultisigs() public {
        address[] memory signers = new address[](1);
        signers[0] = DEPLOYER;

        MS_MAINTENANCE = deployMultisig(signers, 1);
        emit log_named_address("MS_MAINTENANCE     ", address(MS_MAINTENANCE));

        MS_EMERGENCY_UPDATE = deployMultisig(signers, 1);
        emit log_named_address("MS_EMERGENCY_UPDATE", address(MS_EMERGENCY_UPDATE));

        MS_SCHEDULED_UPDATE = deployMultisig(signers, 1);
        emit log_named_address("MS_SCHEDULED_UPDATE", address(MS_SCHEDULED_UPDATE));

        MS_RESUME = deployMultisig(signers, 1);
        emit log_named_address("MS_RESUME          ", address(MS_RESUME));
    }

    function fullSetup() public {
        deployMultisigs();
        deployTimelock();
        deployController();

        label();

        checkControllerRoles();
        checkTimelockRoles();

        if (UPDATE_MULTISIGS) {
            emit log("= Update signers");

            updateSignersMaintenance();
            updateSignersResume();
            updateSignersScheduled();
            updateSignersEmergencyUpdate();
        }
    }

    function updateSigners(address _ms, address[] memory _signers, uint256 _threshold) public returns (bool) {
        GnosisSafe ms = GnosisSafe(payable(_ms));

        bytes memory call;
        {
            uint256 threshold = ms.getThreshold();
            for (uint256 i = 0; i < _signers.length; i++) {
                bytes memory inner =
                    abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", _signers[i], threshold);
                bytes memory oneCall = abi.encodePacked(uint8(0), _ms, uint256(0), inner.length, inner);
                call = bytes.concat(call, oneCall);
            }
            if (_threshold != threshold && _threshold <= _signers.length) {
                call = bytes.concat(
                    call,
                    abi.encodePacked(uint8(0), _ms, uint256(0), abi.encodeWithSignature("changeThreshold(uint256)", _threshold))
                );
            }
            call = abi.encodeWithSignature("multiSend(bytes)", call);
        }

        Enum.Operation op = Enum.Operation.DelegateCall;
        uint256 gas = 100000000;

        // Then we need to send it
        bytes32 transactionHash =
            ms.getTransactionHash(address(MULTI_SEND), 0, call, op, gas, 0, 0, address(0), address(0), ms.nonce());

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PRIVATE_KEY, transactionHash);
        bytes memory sigs = abi.encodePacked(r, s, v);

        vm.prank(DEPLOYER);
        bool success = ms.execTransaction(address(MULTI_SEND), 0, call, op, gas, 0, 0, address(0), payable(0), sigs);

        if (success) {
            emit log("SUCCESS");
        } else {
            emit log("NO SUCCESS");
        }

        /*
        address[] memory owners = ms.getOwners();
        for (uint256 i = 0; i < owners.length; i++) {
            emit log_named_address("owner", owners[i]);
        }
        emit log_named_uint("Threshold", ms.getThreshold());*/

        return success;
    }

    function updateSignersMaintenance() public {
        // Add the signers and the threshold at the last tx.
        uint256 threshold = 3;
        address[] memory signers = new address[](2);
        signers[0] = address(0xdead);
        signers[1] = address(0xbeef);

        updateSigners(address(MS_MAINTENANCE), signers, threshold);
        assertFalse(true, "IMPLEMENT WITH PROPER SIGNERS");
    }

    function updateSignersResume() public {
        assertFalse(true, "IMPLEMENT WITH PROPER SIGNERS");
    }

    function updateSignersScheduled() public {
        assertFalse(true, "IMPLEMENT WITH PROPER SIGNERS");
    }

    function updateSignersEmergencyUpdate() public {
        assertFalse(true, "IMPLEMENT WITH PROPER SIGNERS");
    }

    function checkControllerRoles() public {
        // Admin
        bytes32 adminRole = CONTROLLER.TIMELOCK_ADMIN_ROLE();
        assertFalse(CONTROLLER.hasRole(adminRole, DEPLOYER), "1");
        assertFalse(CONTROLLER.hasRole(adminRole, address(MS_MAINTENANCE)), "2");
        assertFalse(CONTROLLER.hasRole(adminRole, address(MS_SCHEDULED_UPDATE)), "3");
        assertFalse(CONTROLLER.hasRole(adminRole, address(MS_RESUME)), "4");
        assertFalse(CONTROLLER.hasRole(adminRole, address(MS_EMERGENCY)), "5");
        assertTrue(CONTROLLER.hasRole(adminRole, address(MS_EMERGENCY_UPDATE)), "6");
        assertTrue(CONTROLLER.hasRole(adminRole, address(TIME_LOCK)), "7");

        // Proposers
        bytes32 proposerRole = CONTROLLER.PROPOSER_ROLE();
        assertFalse(CONTROLLER.hasRole(proposerRole, address(MS_MAINTENANCE)), "8");
        assertFalse(CONTROLLER.hasRole(proposerRole, address(MS_RESUME)), "9");
        assertFalse(CONTROLLER.hasRole(proposerRole, address(MS_SCHEDULED_UPDATE)), "10");
        assertFalse(CONTROLLER.hasRole(proposerRole, address(MS_EMERGENCY)), "11");
        assertTrue(CONTROLLER.hasRole(proposerRole, address(MS_EMERGENCY_UPDATE)), "12");
        assertTrue(CONTROLLER.hasRole(proposerRole, address(TIME_LOCK)), "13");

        // Executors
        bytes32 executorRole = CONTROLLER.EXECUTOR_ROLE();
        assertFalse(CONTROLLER.hasRole(executorRole, address(MS_RESUME)), "14");
        assertFalse(CONTROLLER.hasRole(executorRole, address(MS_EMERGENCY)), "15");
        assertFalse(CONTROLLER.hasRole(executorRole, address(MS_SCHEDULED_UPDATE)), "16");
        assertTrue(CONTROLLER.hasRole(executorRole, address(MS_EMERGENCY_UPDATE)), "17");
        assertTrue(CONTROLLER.hasRole(executorRole, address(MS_MAINTENANCE)), "18");
        assertTrue(CONTROLLER.hasRole(executorRole, address(TIME_LOCK)), "19");

        // Cancellers
        bytes32 cancellerRole = CONTROLLER.CANCELLER_ROLE();
        assertFalse(CONTROLLER.hasRole(cancellerRole, address(MS_RESUME)), "20");
        assertFalse(CONTROLLER.hasRole(cancellerRole, address(MS_EMERGENCY)), "21");
        assertFalse(CONTROLLER.hasRole(cancellerRole, address(MS_MAINTENANCE)), "22");
        assertFalse(CONTROLLER.hasRole(cancellerRole, address(MS_SCHEDULED_UPDATE)), "23");
        assertTrue(CONTROLLER.hasRole(cancellerRole, address(MS_EMERGENCY_UPDATE)), "24");
        assertTrue(CONTROLLER.hasRole(cancellerRole, address(TIME_LOCK)), "25");

        emit log("Controller roles match expected");
    }

    function checkTimelockRoles() public {
        // Admin
        bytes32 adminRole = TIME_LOCK.TIMELOCK_ADMIN_ROLE();
        assertFalse(TIME_LOCK.hasRole(adminRole, DEPLOYER), "1");
        assertFalse(TIME_LOCK.hasRole(adminRole, address(MS_MAINTENANCE)), "2");
        assertFalse(TIME_LOCK.hasRole(adminRole, address(MS_SCHEDULED_UPDATE)), "3");
        assertFalse(TIME_LOCK.hasRole(adminRole, address(MS_RESUME)), "4");
        assertFalse(TIME_LOCK.hasRole(adminRole, address(MS_EMERGENCY)), "5");
        assertTrue(TIME_LOCK.hasRole(adminRole, address(MS_EMERGENCY_UPDATE)), "6");
        assertTrue(TIME_LOCK.hasRole(adminRole, address(TIME_LOCK)), "7");

        // Proposers
        bytes32 proposerRole = TIME_LOCK.PROPOSER_ROLE();
        assertFalse(TIME_LOCK.hasRole(proposerRole, address(MS_MAINTENANCE)), "8");
        assertFalse(TIME_LOCK.hasRole(proposerRole, address(MS_RESUME)), "9");
        assertFalse(TIME_LOCK.hasRole(proposerRole, address(MS_EMERGENCY)), "10");
        assertFalse(TIME_LOCK.hasRole(proposerRole, address(TIME_LOCK)), "11");
        assertTrue(TIME_LOCK.hasRole(proposerRole, address(MS_SCHEDULED_UPDATE)), "12");
        assertTrue(TIME_LOCK.hasRole(proposerRole, address(MS_EMERGENCY_UPDATE)), "13");

        // Executors
        bytes32 executorRole = TIME_LOCK.EXECUTOR_ROLE();
        assertFalse(TIME_LOCK.hasRole(executorRole, address(MS_RESUME)), "14");
        assertFalse(TIME_LOCK.hasRole(executorRole, address(MS_EMERGENCY)), "15");
        assertFalse(TIME_LOCK.hasRole(executorRole, address(TIME_LOCK)), "16");
        assertTrue(TIME_LOCK.hasRole(executorRole, address(MS_SCHEDULED_UPDATE)), "17");
        assertTrue(TIME_LOCK.hasRole(executorRole, address(MS_EMERGENCY_UPDATE)), "18");
        assertTrue(TIME_LOCK.hasRole(executorRole, address(MS_MAINTENANCE)), "19");

        // Cancellers
        bytes32 cancellerRole = TIME_LOCK.CANCELLER_ROLE();
        assertFalse(TIME_LOCK.hasRole(cancellerRole, address(MS_RESUME)), "20");
        assertFalse(TIME_LOCK.hasRole(cancellerRole, address(MS_EMERGENCY)), "21");
        assertFalse(TIME_LOCK.hasRole(cancellerRole, address(MS_MAINTENANCE)), "22");
        assertFalse(TIME_LOCK.hasRole(cancellerRole, address(TIME_LOCK)), "23");
        assertTrue(TIME_LOCK.hasRole(cancellerRole, address(MS_SCHEDULED_UPDATE)), "24");
        assertTrue(TIME_LOCK.hasRole(cancellerRole, address(MS_EMERGENCY_UPDATE)), "25");

        emit log("Timelock roles match expected");
    }
}
