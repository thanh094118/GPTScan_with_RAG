// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Limbo_Vulnerable {
    address public owner;
    address public bank_addr;
    address public random_addr;

    // Config game
    uint256 public max_multiplier;
    uint256 public min_bet_amount;

    // --- BUG ID #1 & #2: Missing validation in instantiation ---
    // [cite: 100, 105] Bug #1: Thiếu kiểm tra địa chỉ (address validation).
    // [cite: 124, 129] Bug #2: Thiếu kiểm tra max_multiplier (có thể bằng 0).
    constructor(
        address _bank_addr,
        address _random_addr,
        uint256 _max_multiplier
    ) {
        // LỖ HỔNG #1: Không kiểm tra address(0) cho _bank_addr hoặc _random_addr.
        // Nếu nhập sai địa chỉ 0, tiền hoặc logic random sẽ bị hỏng vĩnh viễn.
        bank_addr = _bank_addr;
        random_addr = _random_addr;

        // LỖ HỔNG #2: Không kiểm tra _max_multiplier > 0.
        // Nếu set là 0, game sẽ bị lỗi logic tính thưởng hoặc payout = 0.
        max_multiplier = _max_multiplier;

        owner = msg.sender;
        min_bet_amount = 1 ether; // Giá trị mặc định
    }

    // --- BUG ID #4: Unchecked minimum bet amount ---
    // [cite: 165, 170] Cho phép đặt min_bet bằng 0 (illogical).
    function update_min_bet_amount(uint256 _amount) external {
        require(msg.sender == owner, "Only owner");

        // LỖ HỔNG #4: Thiếu dòng require(_amount > 0, "Amount must be > 0");
        min_bet_amount = _amount;
    }

    // --- BUG ID #3: Truncation of betting reward ---
    // [cite: 143, 148, 149] Ép kiểu dữ liệu (Typecasting) gây mất dữ liệu.
    function calculate_payout(
        uint256 _betAmount,
        uint256 _multiplier
    ) external view returns (uint128) {
        // Giả lập tính toán reward: bet * multiplier
        uint256 scaled_result = _betAmount * _multiplier;

        // LỖ HỔNG #3: Ép kiểu từ uint256 xuống uint128 mà không kiểm tra giới hạn.
        // Trong Rust gốc: Uint128::try_from(scaled_result)
        // Nếu scaled_result lớn hơn giá trị max của uint128, nó sẽ bị cắt bớt (truncation)
        // dẫn đến tính sai tiền thưởng.
        return uint128(scaled_result);
    }

    // --- BUG ID #5: Missing ownership transfer mechanism ---
    //  Không có cơ chế chuyển quyền sở hữu (Ownership Transfer).

    // LỖ HỔNG #5: Contract này hoàn toàn KHÔNG có hàm transferOwnership.
    // Nếu ví owner bị mất private key, contract sẽ vĩnh viễn không ai quản lý được.
    // (Trong code chuẩn cần có hàm transferOwnership và acceptOwnership).

    function withdraw_funds() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
