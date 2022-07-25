// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Aztec.
pragma solidity >=0.8.4;

contract RollupProcessorV2 {
    // bounds used for escapehatch
    uint256 public immutable escapeBlockLowerBound;
    uint256 public immutable escapeBlockUpperBound;

    /**
     * @dev Constructor used to store immutable values for escape hatch window and
     * ensure that the implementation cannot be initialized
     * @param _escapeBlockLowerBound defines start of escape hatch window
     * @param _escapeBlockUpperBound defines end of the escape hatch window
     */
    constructor(uint256 _escapeBlockLowerBound, uint256 _escapeBlockUpperBound) {
        escapeBlockLowerBound = _escapeBlockLowerBound;
        escapeBlockUpperBound = _escapeBlockUpperBound;
    }

    /**
     * @dev Initialiser function. Emulates constructor behaviour for upgradeable contracts
     */
    function initialize() external {}
}
