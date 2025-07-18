# Staking-Contract-Vulnerabilities

##  Issue 1 : ByPassing Withdrawal Approval

### 🧪 Code snippet:

```solidity
function approveWithdrawRequest(address user) public onlyOwner nonReentrant {
        PrimeStakedXDCStorage storage s = _getPrimeStakedXDCStorage();
        mapping(address => bool) storage _canWithdraw = s.canWithdraw;
        _canWithdraw[user] = true;
        emit WithdrawRequestApproved(user);
    }
```

### Description:
The approveWithdrawRequest() function sets a boolean flag _canWithdraw[user] = true, allowing a user to withdraw funds. However, this flag is not time-bound or tied to the stake amount at the time of approval.
An attacker can exploit this by getting approval for a small stake and delaying their actual withdrawal.

Later, they can stake a large amount and withdraw without requiring further approval, thus bypassing the intended per-withdrawal approval mechanism.

This behavior breaks the intended protocol security model, where every withdrawal should be approved based on the user's current stake and context.

### Attack Scenerio:
-Attacker stakes 1 wei of XDC.

-Attacker calls requestWithdraw().

-Owner approves the request: _canWithdraw[attacker] = true.

-Attacker does not withdraw, but instead stakes a large amount, e.g., 1000 XDC.

-Later, attacker calls withdraw() and is not required to request or receive approval again.

-The attacker withdraws all funds based on a previous approval, bypassing approval for 1000 XDC.


##  Issue 2 :Stake function allows staking NFTs with token ID 0
### 🧪 Code snippet:

```solidity
function stake(GalileoStakingStorage.StakeTokens calldata stakeTokens) external whenNotPaused nonReentrant {
    // Recover and verify the voucher signature to ensure its authenticity.
    _recover(stakeTokens);
    // Call the internal function to handle the actual staking process
    _stakeTokens(
      stakeTokens.collectionAddress,
      stakeTokens.tokenId,
      stakeTokens.citizen,
      stakeTokens.timelockEndTime,
      stakeTokens.stakedLeox
    );
  }
```
## Description:
The _stakeTokens function allows users to stake NFTs with a token ID of 0. However, unstaking of token ID 0 is disallowed, leading to an inconsistency in the staking logic. If a user stakes a token with ID 0, they might face issues retrieving their NFT later, as the unstaking functionality does not account for this scenario.

### Impact:

-Users can stake NFTs with token ID 0 but will not be able to unstake them due to unstaking restrictions.
-This could result in locked NFTs that cannot be retrieved, leading to frustration and potential loss of assets for users.	






## Issue 3: Missing Pool Total Stake Update in Emergency Withdrawal
```solidity
function emergencyWithdraw(uint256 _pid) external nonReentrant {
        require(_pid < poolInfo.length, "ShareRewardPool: Pool does not exist");

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        uint256 amount = user.amount;
        pendingRewards[_pid][msg.sender] = 0;
        user.amount = 0;
        user.rewardDebt = 0;

        // For pools with PoL enabled, execute delegateWithdraw before transferring tokens.
        if (pool.polConfig.enabled && address(pool.polConfig.rewardVault) != address(0)) {
            pool.polConfig.rewardVault.delegateWithdraw(msg.sender, amount);
        }

        pool.token.safeTransfer(msg.sender, amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }
```


### Description:
The emergencyWithdraw function in ShareRewardPool contract fails to decrease the pool.totalStaked value when users perform emergency withdrawals. This leads to an inconsistent state where the pool's total staked amount does not reflect the actual staked tokens after emergency withdrawals.
Which impacts incorrect reward calculations due to inflated totalStaked value.







## Issue 4: Unstake() transfers amount + reward while transferring reward
``` solidity
/// @dev Allow user to unstake their RITE after staking duration
    /// @param _index The index of the stake
    function unstake(uint _index) external {
        require(stakes[msg.sender].length > 0, "Staking: no stake");
        require(_index < stakes[msg.sender].length, "Staking: invalid stake");
        require(
            block.timestamp >= stakes[msg.sender][_index].endAt,
            "Staking: staking is not ended yet"
        );

        uint256 amount = stakes[msg.sender][_index].amount;
        uint256 reward = (amount * APY) / 100;
        require(
            ERC20(RITE).balanceOf(self) >= amount + reward,
            "Staking: insufficient balance"
        );

        ERC20(RITE).safeTransfer(msg.sender, amount + reward);
        emit Unstaked(
            msg.sender,
            amount,
            block.timestamp,
            stakes[msg.sender][_index].month
        );

        stakes[msg.sender][_index] = stakes[msg.sender][
            stakes[msg.sender].length - 1
        ];
        stakes[msg.sender].pop();
    }

```
### Description:
In unstake() the intentional logic for unstaking is to calculate 50% of the amount staked amount and transfer it to the user. But while transferring it transfers the amount + reward. Here amount wasn't actually staked by the operator (i.e it wasn't transferred to the staking contract while staking). But while sending it is getting sent. which will create problem as the users will get more amount. i.e reward and the amount also ( which was never transferred while staking).

## Issue 5: copying and poping elements can create a confusion while unstaking with index
``` solidity
/// @dev Allow user to unstake their RITE after staking duration
    /// @param _index The index of the stake
    function unstake(uint _index) external {
        require(stakes[msg.sender].length > 0, "Staking: no stake");
        require(_index < stakes[msg.sender].length, "Staking: invalid stake");
        require(
            block.timestamp >= stakes[msg.sender][_index].endAt,
            "Staking: staking is not ended yet"
        );

        uint256 amount = stakes[msg.sender][_index].amount;
        uint256 reward = (amount * APY) / 100;
        require(
            ERC20(RITE).balanceOf(self) >= amount + reward,
            "Staking: insufficient balance"
        );

        ERC20(RITE).safeTransfer(msg.sender, amount + reward);
        emit Unstaked(
            msg.sender,
            amount,
            block.timestamp,
            stakes[msg.sender][_index].month
        );

        stakes[msg.sender][_index] = stakes[msg.sender][
            stakes[msg.sender].length - 1
        ];
        stakes[msg.sender].pop();
    }
```

### Description:
E.g Operator stakes 5 times for 5 months for specific user for some stakes the end date is reached so for them users can now unstake.

From stakes of 5 months (08/2025, 09/2025, 10/2025, 11/2025, 12/2025) User decides to unstake for the first one i.e 08/2023 So the code will copy element of the month 12/2025 (last element) to the first (i.e 0th element) and will pop the last one which would be duplicate of 12/2025

so after unstaking the array element’s sequence will be changed because of copy and pop operation so the index of the elements for month is also changed.

So before unstaking it was in this sequence:
(08/2025, 09/2025, 10/2025, 11/2025, 12/2025) and 
after unstaking it is in this sequence:
 (12/2025, 09/2025, 10/2025, 11/2025) where the index of element is changed.

In this case, the user can get confused if he assumed that the stake of any month is going to be at the specific index because that got staked (pushed to array) in the same order of increasing month.


## Issue 6: The contract increases the global rewardsPerSecond each time a pool starts, leading to more reward distributions. 

```Solidity
 /**
     * @dev Add a new token to the reward pool system
     * @param _allocPoint Allocation points for the new pool
     * @param _depFee Deposit fee in basis points (1 = 0.01%)
     * @param _token Token to be staked
     * @param _withUpdate Whether to update all pools
     * @param _lastRewardTime Last reward time for this pool
     */
    function add(uint256 _allocPoint, uint256 _depFee, address _token, bool _withUpdate, uint256 _lastRewardTime)
        public
        onlyOperator
    {
        checkPoolDuplicate(IERC20(_token));
        require(_depFee < 200, "GenesisRewardPool: deposit fee too high"); // deposit fee can't be more than 2%

        if (_withUpdate) {
            massUpdatePools();
        }

        if (block.timestamp < poolStartTime) {
            // chef is sleeping
            if (_lastRewardTime == 0) {
                _lastRewardTime = poolStartTime;
            } else {
                if (_lastRewardTime < poolStartTime) {
                    _lastRewardTime = poolStartTime;
                }
            }
        } else {
            // chef is cooking
            if (_lastRewardTime == 0 || _lastRewardTime < block.timestamp) {
                _lastRewardTime = block.timestamp;
            }
        }
        bool _isStarted = (_lastRewardTime <= poolStartTime) || (_lastRewardTime <= block.timestamp);

        uint256 pid = poolInfo.length;

        poolInfo.push(
            PoolInfo({
                token: IERC20(_token),
                depFee: _depFee,
                allocPoint: _allocPoint,
                poolRewardPerSec: _allocPoint,
                lastRewardTime: _lastRewardTime,
                accRewardsPerShare: 0,
                isStarted: _isStarted,
                totalStaked: 0
            })
        );

        if (_isStarted) {
            totalAllocPoint = totalAllocPoint.add(_allocPoint);
            rewardsPerSecond = rewardsPerSecond.add(_allocPoint);
        }

        emit PoolAdded(pid, _token, _allocPoint, _depFee);
    }
```

### Description:
The contract increases the global rewardsPerSecond each time a pool starts, leading to more reward distributions. Each new pool adds its allocation points to rewardsPerSecond, causing the total rewards to multiply with each pool addition.
This could allow protocol to distribute significantly more rewards than intended.




## Issue 7: The contract doesn't properly handle historical reward rate changes when calculating rewards. 

```Solidity
// Add helper function to calculate rewards across rate changes
    function getGeneratedReward(uint256 _fromTime, uint256 _toTime) public view returns (uint256) {
        if (_fromTime >= _toTime) return 0;
        
        uint256 totalRewards = 0;
        uint256 totalWeeks = (_toTime - _fromTime) / 1 weeks;
        uint256 startWeek = (_fromTime - poolStartTime) / 1 weeks;
        
        // Iterate through weeks and add up rewards
        for (uint256 i = 0; i <= totalWeeks; i++) {
            uint256 weekNumber = startWeek + i;
            uint256 weekRate = weeklyShareRate[weekNumber];
            if (weekRate == 0) {
                weekRate = sharePerSecond; // Use current rate if no specific rate set
            }
            
            uint256 weekStart = _fromTime + (i * 1 weeks);
            uint256 weekEnd = weekStart + 1 weeks;
            if (weekEnd > _toTime) weekEnd = _toTime;
            
            totalRewards = totalRewards.add(
                (weekEnd - weekStart).mul(weekRate)
            );
        }
        
        return totalRewards;
    }
```

### Description:
- If rate was 2 GHOG/sec for first 7 days then changed to 1 GHOG/sec
- A user claiming after 14 days would get: 14 days * current_rate(1 GHOG/sec)
- Instead of correct: 7 days * old_rate(2 GHOG/sec) + 7 days * new_rate(1 GHOG/sec)




