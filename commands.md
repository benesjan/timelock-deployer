
Deploy to Goerli and verify on etherscan:
> forge script script/Timelock.s.sol:TimelockScript --fork-url https://goerli.infura.io/v3/737bcb5393b146d7870be2f68a7cea9c --private-key 616f013cf8cb4c5e78181cfbd1603c0c4444e011d4a65ae14bb1c2f25dc96e34 --broadcast --verify --etherscan-api-key PZS6C51MXGZ3EKKM9FT86RJVU3UC7Q41HS

Update the addresses in `test/Deployment.t.sol` and check that the deployed contract was deployed correctly and admin role was transferred by calling:
> forge test --fork-url https://goerli.infura.io/v3/737bcb5393b146d7870be2f68a7cea9c --match-contract DeploymentTest