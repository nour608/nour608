# First Flight #17: Dussehra - Findings Report

# Table of contents

- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings

  - ### [H-01. [H-2] Predictable Randomness Logic in `ChoosingRam::increaseValuesOfParticipants()`](#H-01)
  - ### [H-02. [H-3] Lack of Access Control in `RamNFT::mintRamNFT()` Allows Free Minting](#H-02)
  - ### [H-03. [H-4] Inconsistent `block.prevrandao` Values Across Chains Compromise Randomness Logic and `PUSH0` Opcode Compatibility Issues](#H-03)
  - ### [H-04. [H-5] Lack of Access Control in `ChoosingRam::increaseValuesOfParticipants` Allows Free Value Increase](#H-04)

- ## Low Risk Findings
  - ### [L-01. [L-1] Predictable Randomness Logic in `ChoosingRam::selectRamIfNotSelected()`](#L-01)
  - ### [L-02. [L-1] Mark Unused `public` Functions as `external`](#L-02)

# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #17

### Dates: Jun 6th, 2024 - Jun 13th, 2024

[See more contest details here](https://codehawks.cyfrin.io/c/2024-06-Dussehra)

# <a id='results-summary'></a>Results Summary

### Number of findings:

- High: 4
- Medium: 0
- Low: 2

# High Risk Findings

## <a id='H-01'></a>H-01. [H-2] Predictable Randomness Logic in `ChoosingRam::increaseValuesOfParticipants()`

### Relevant GitHub Links

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/ChoosingRam.sol#L52

## Description:

The `increaseValuesOfParticipants()` function in the `ChoosingRam` contract utilizes a logic to generate random numbers. However, this randomness logic can be predicted by users, allowing an attacker to repeatedly call the function until achieving a desired outcome. This predictability undermines the security and fairness of the function.

## Impact:

Predictable randomness enables attackers to manipulate the outcome by repeatedly invoking the function until the desired random number is generated. This compromises the randomness logic, leading to potential exploitation and unfair advantages within the system.

## Proof of Concept:

```solidity
function test_increaseValuesOfParticipantsIsNotRandom() public {
    Dussehra dussehra;
    RamNFT ramNFT;
    ChoosingRam choosingRam;
    address organiser = makeAddr("organiser");
    address player1 = makeAddr("player1");
    address player2 = makeAddr("player2");

    vm.startPrank(organiser);
    ramNFT = new RamNFT();
    choosingRam = new ChoosingRam(address(ramNFT));
    dussehra = new Dussehra(1 ether, address(choosingRam), address(ramNFT));
    ramNFT.setChoosingRamContract(address(choosingRam));
    vm.stopPrank();

    vm.startPrank(player1);
    vm.deal(player1, 1 ether);
    dussehra.enterPeopleWhoLikeRam{value: 1 ether}();
    vm.stopPrank();

    // the second player will predict the outcomes and
    // will become the Ram
	    vm.startPrank(player2);
	    vm.deal(player2, 1 ether);
	    dussehra.enterPeopleWhoLikeRam{value: 1 ether}();
	    uint256 winnings = 0;
	    uint256 time = 1;
	    // this loop will be executed until the second player
	    // wins 5 times
	    while (winnings < 5) {
	        vm.warp(++time);
	        if (
	            uint256(
	                keccak256(
	                    abi.encodePacked(
	                        block.timestamp,
	                        block.prevrandao,
	                        player2
	                    )
	                )
	            ) %
	                2 ==
	            0
	        ) {
	            // the following block will be executed only if the user
	            // is gonna win the challenge
	            ++winnings;
	            choosingRam.increaseValuesOfParticipants(1, 0);
	        }
	    }
	    vm.stopPrank();

	    // as we can see the second player is now the Ram
	    assertEq(choosingRam.selectedRam(), player2);
}
```

## Recommended Mitigation:

To ensure randomness cannot be predicted or manipulated, use a Verifiable Random Function (VRF) service. VRF services provide secure and verifiable random numbers that are resistant to prediction and manipulation attacks. Some recommended services include:

- Chainlink VRF (Recommended): Provides cryptographically secure randomness.
- Gelato: Offers automation and randomness services.
- Pyth: Delivers reliable and tamper-proof random numbers.
  By integrating one of these VRF services, the randomness logic in increaseValuesOfParticipants() will be significantly more secure, preventing the vulnerabilities associated with the current implementation.

## <a id='H-02'></a>H-02. [H-3] Lack of Access Control in `RamNFT::mintRamNFT()` Allows Free Minting

### Relevant GitHub Links

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/RamNFT.sol#L49

## Description:

The `mintRamNFT()` function in the `RamNFT` contract lacks proper access control, allowing anyone to mint a RAM NFT for free outside of the contract's intended behavior.

## impact:

This vulnerability enables attackers to mint RAM NFTs without authorization, potentially leading to manipulations of various functions within the protocol.

## Proof of Concept:

Execute the following code in `Dussehra.t.sol`:

```
function test_mintRamNft() public {
        address hacker = address(1234);
        vm.prank(hacker);
        ramNFT.mintRamNFT(hacker);

        assertEq(ramNFT.balanceOf(hacker), 1);
        console.log("ramNFT balance of hacker: %e", ramNFT.balanceOf(hacker));
    }
```

Output :

```
Logs:
  ramNFT balance of hacker: 1e0

```

## Recommended Mitigation:

Implement access control for the `mintRamNFT()` function using a modifier:

```
modifier onlyDussehra() {
        if(msg.sender != dussehraContract) {
            revert callerNotAllowed();
        }
        _;
    }
```

Apply this modifier to the `mintRamNFT()` function to restrict minting privileges to authorized contracts or addresses only.

## <a id='H-03'></a>H-03. [H-4] Inconsistent `block.prevrandao` Values Across Chains Compromise Randomness Logic and `PUSH0` Opcode Compatibility Issues

### Relevant GitHub Links

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/ChoosingRam.sol#L51

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/ChoosingRam.sol#L90

## Description:

**Issue 1:** block.prevrandao Differences
In the functions `choosingRam::selectRamIfNotSelected()` and `choosingRam::increaseValuesOfParticipants()`, the block.prevrandao value differs significantly across some chains, causing predictable randomness, which compromises security:

- Arbitrum: Returns a constant value of 1 for block.prevrandao.
- zkSync: Returns a constant value of 2500000000000000 for block.prevrandao.
  This behavior allows an attacker to predict the selected RAM, undermining the randomness logic.

**Issue 2:** PUSH0 Opcode Compatibility
The PUSH0 opcode, introduced with the Ethereum Shanghai/Capella upgrades (EIP-3855), simplifies pushing a zero onto the stack. However, several blockchains and Layer 2 solutions may not support this opcode yet, leading to deployment failures and execution errors in contracts that use it.
**Chains and L2s that may not support PUSH0:**

- Binance Smart Chain (BSC)
- ZK-Rollups (e.g., zkSync, StarkNet)
- Arbitrum

## Impact:

- Randomness Compromise: The predictability of block.prevrandao on Arbitrum and zkSync breaks the randomness logic, enabling attackers to manipulate and predict the randomly selected RAM.
- PUSH0 Incompatibility: Contracts using PUSH0 will face deployment failures and runtime errors on non-supporting chains, leading to incompatibility issues.

## Proof of Concept:

`block.prevrandao`:

- Arbitrum docs: [Arbitrum vs Ethereum - Solidity Support](https://docs.arbitrum.io/build-decentralized-apps/arbitrum-vs-ethereum/solidity-support#differences-from-solidity-on-ethereum)
- zkSync docs: [zkSync - EVM Instructions](https://docs.zksync.io/build/developer-reference/ethereum-differences/evm-instructions#difficulty-prevrandao)

## Recommended Mitigation:

- Randomness: Use a more secure and reliable method for randomness, such as Chainlink VRF (Verifiable Random Function), to avoid predictability issues across different chains.
- PUSH0 Compatibility: Verify the support for PUSH0 on the target chain before deploying contracts. For broader compatibility, consider alternative approaches to achieve similar functionality without relying on PUSH0.

## <a id='H-04'></a>H-04. [H-5] Lack of Access Control in `ChoosingRam::increaseValuesOfParticipants` Allows Free Value Increase

### Relevant GitHub Links

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/ChoosingRam.sol#L33

## Description:

The `ChoosingRam::increaseValuesOfParticipants` function lacks proper access control, allowing unauthorized participants to increase their values without paying the entrance fee. This vulnerability can lead to unfair advantages and potential manipulation of the RAM selection process.

## Impact:

The lack of access control enables anyone to enter the challenge and increase their value for free. This increases the likelihood of unauthorized participants winning the RAM selection, undermining the fairness and integrity of the protocol.

## Proof of Concept:

Execute the following code in `Dussehra.t.sol`. Ensure to update the variables `player3` and `player4` to `attacker` and `attacker2` respectively:

```solidity
function test_anyoneCanIncreaseHisValuesAndBeTheRamWithoutPayEntranceFee() public {
        vm.prank(attacker);
        ramNFT.mintRamNFT(attacker);

        vm.prank(attacker2);
        ramNFT.mintRamNFT(attacker2);

        vm.startPrank(attacker2);
        choosingRam.increaseValuesOfParticipants(1, 1);
        choosingRam.increaseValuesOfParticipants(1, 1);
        choosingRam.increaseValuesOfParticipants(1, 1);
        choosingRam.increaseValuesOfParticipants(1, 1);
        choosingRam.increaseValuesOfParticipants(1, 1);
        vm.stopPrank();

        assertEq(ramNFT.getCharacteristics(1).isJitaKrodhah, true);
        console.log("Characteristics of Ram: ", ramNFT.getCharacteristics(1).isJitaKrodhah);
        console.log("Characteristics of Ram: ", ramNFT.getCharacteristics(1).isDhyutimaan);
        console.log("Characteristics of Ram: ", ramNFT.getCharacteristics(1).isVidvaan);
        console.log("Characteristics of Ram: ", ramNFT.getCharacteristics(1).isAatmavan);
        console.log("Characteristics of Ram: ", ramNFT.getCharacteristics(1).isSatyavaakyah);
    }
```

output :

```
      forge test --mt test_anyoneCanIncreaseHisValuesAndBeTheRamWithoutPayEntranceFee -vv

Logs:
  Characteristics of Ram:  true
  Characteristics of Ram:  true
  Characteristics of Ram:  true
  Characteristics of Ram:  true
  Characteristics of Ram:  true

```

## Recommended Mitigation:

Implement robust access control mechanisms to ensure that only participants who have paid the entrance fee can increase their values. Consider restricting value increases to a specific array of authorized participants, such as address[] public WantToBeLikeRam in Dussehra.sol. This approach will help maintain fairness and prevent unauthorized participants from manipulating the RAM selection process.

# Low Risk Findings

## <a id='L-01'></a>L-01. [H-1] Predictable Randomness Logic in `ChoosingRam::selectRamIfNotSelected()`

### Relevant GitHub Links

https://github.com/Cyfrin/2024-06-Dussehra/blob/9c86e1b09ed9516bfbb3851c145929806da75d87/src/ChoosingRam.sol#L83

## Description:

The `selectRamIfNotSelected()` function in the ChoosingRam contract uses a logic that relies on `block.timestamp` and `block.prevrandao` to select a random RAM. However, this approach makes the randomness predictable, especially on certain blockchains where `block.prevrandao` returns constant values, such as Arbitrum and zkSync. This predictability compromises the security and integrity of the selection process.

## Impact:

Predictable randomness allows attackers to predict the selected RAM, breaking the randomness logic and potentially manipulating the outcome. This vulnerability can lead to unfair advantages and exploitation within the system.

## Proof of Concept:

Run the following code in `Dussehra.t.sol` :

```
function test_predictRandomNumber() public participants {
        vm.prank(player1);
        vm.warp(1728691201); // Set time within the valid range

        // Predictable random number using the same logic as in the contract
        uint256 predictedRandom =
            uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % ramNFT.tokenCounter();
        address expectedRam = ramNFT.getCharacteristics(predictedRandom).ram;

        // Call the function to select Ram
        vm.startPrank(organiser);
        choosingRam.selectRamIfNotSelected();
        vm.stopPrank();

        // Ensure the selected ram matches the predicted ram
        assertEq(choosingRam.selectedRam(), expectedRam);
        assertTrue(choosingRam.isRamSelected());

        console.log("Predicted Ram: ", expectedRam);
        console.log("Selected Ram: ", choosingRam.selectedRam());
    }
```

Output :

```
Logs:
  Predicted Ram:  0xEb0A3b7B96C1883858292F0039161abD287E3324
  Selected Ram:  0xEb0A3b7B96C1883858292F0039161abD287E3324
```

## Recommended Mitigation:

To ensure the randomness cannot be predicted or manipulated, use a Verifiable Random Function (VRF) service. VRF services provide secure and verifiable random numbers that are resistant to prediction and manipulation attacks. Some recommended services include:

- Chainlink VRF (Recommended): Provides cryptographically secure randomness.
- Gelato: Offers automation and randomness services.
- Pyth: Delivers reliable and tamper-proof random numbers.
  By integrating one of these VRF services, the randomness logic in selectRamIfNotSelected() will be significantly more secure, preventing the vulnerabilities associated with the current implementation.

## <a id='L-02'></a>L-02. [L-1] Mark Unused `public` Functions as `external`

## Description:

Consider marking functions as `external` instead of `public` if they are not used internally within the contract. This optimization can enhance gas efficiency and reduce contract complexity.

- `ChoosingRam::increaseValuesOfParticipants()`
- `ChoosingRam::selectRamIfNotSelected()`
- `Dussehra::enterPeopleWhoLikeRam()`
- `Dussehra::killRavana()`
- `Dussehra::withdraw()`

## Recommended Mitigation:

Mark the mentioned functions as `external` to improve gas efficiency and contract clarity.
