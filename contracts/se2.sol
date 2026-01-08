// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CoinFlip_Vulnerable {
    // Giả lập state global
    uint256 public global_bet_id;

    struct AutoBet {
        uint256 flips; // Số lượng lần lật đồng xu (iteration)
        uint256 amount;
    }

    struct Bet {
        uint256 id;
        AutoBet auto_bet;
        bool is_multiple; // GameType: Multiple
    }

    // Lưu trữ kết quả game.
    // Key là bet_id, Value là kết quả (giả lập là 1 số uint)
    mapping(uint256 => uint256) public gameResults;

    Bet[] public betQueue;

    constructor() {
        global_bet_id = 0;
    }

    // --- BUG ID #1: Incorrect validation leading to stuck funds (Critical) ---
    //
    // Mô tả: Hàm không kiểm tra trường hợp user gửi auto_bet.flips = 0.
    //
    function submit_flip_coin(
        uint256 _flips,
        uint256 _amount,
        bool _is_multiple
    ) public {
        global_bet_id += 1; //

        // --- LỖ HỔNG TẠI ĐÂY ---
        // Báo cáo: "validation for the number of flips is incorrectly implemented... does not handle cases where auto_bet.flips equal to 0"
        // Code đúng phải là: require(_flips > 0, "Flips must be > 0");

        AutoBet memory ab = AutoBet({flips: _flips, amount: _amount});

        betQueue.push(
            Bet({id: global_bet_id, auto_bet: ab, is_multiple: _is_multiple})
        );
    }

    // --- Hàm xử lý đặt cược (Mô phỏng resolve_bet) ---
    function resolve_bet(uint256 queueIndex) public {
        Bet memory bet = betQueue[queueIndex];

        // --- BUG ID #1 TRIGGER (Kích hoạt lỗi) ---
        // Báo cáo: "dividing initial_balance by auto_bet.flips. Here dividing by 0 will cause panic"
        // Nếu user nhập flips = 0 ở bước submit, dòng dưới đây sẽ gây ra Panic (Revert) toàn bộ transaction.
        // Hậu quả: Tiền bị kẹt (Stuck funds / DoS).

        uint256 bal_for_single_flip = bet.auto_bet.amount / bet.auto_bet.flips;

        // --- BUG ID #2: Incorrect storage key handling (High) ---
        //
        // Mô tả: Khi xử lý "Multiple" bets, code dùng chung global bet_id làm key lưu trữ thay vì unique ID cho từng lần lật.

        if (bet.is_multiple) {
            for (uint256 i = 0; i < bet.auto_bet.flips; i++) {
                // Giả lập tính toán kết quả ngẫu nhiên
                uint256 result = uint256(
                    keccak256(abi.encodePacked(block.timestamp, i))
                );

                // --- LỖ HỔNG TẠI ĐÂY ---
                // Báo cáo: "resolve_bet() function stores the results in GAME using the global state.bet_id as the key instead of using the unique bet.bet_id"
                // Báo cáo: "causing the previously saved record to be overwritten"

                // Sai: Dùng chung `global_bet_id` (hoặc bet.id của batch) cho mọi vòng lặp
                gameResults[bet.id] = result;

                // Đúng ra phải là: gameResults[unique_derived_id] = result;
            }
        } else {
            // Xử lý single bet
            gameResults[bet.id] = 1;
        }
    }
}
