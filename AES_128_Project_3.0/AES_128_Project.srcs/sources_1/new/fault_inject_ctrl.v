`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company:
// Engineer:
//
// Create Date: 2026/03/23 13:18:04
// Design Name:
// Module Name: fault_inject_ctrl
// Project Name:
// Target Devices:
// Tool Versions:
// Description:
//   Fault-model controller for round-9 pre-MixColumns injection.
//   Random choices are sampled only on the active clock edge of fault_req.
//   A seeded internal LFSR keeps simulation runs reproducible.
//
//   Model A is implemented as a reproducible random-bit model with controlled
//   Hamming weight. The fault is injected on one byte, and the number of flipped
//   bits is randomly selected from {2,3,4} with a biased distribution.
//
// Revision:
// Revision 0.04 - Controlled-HW reproducible Model A
//
//////////////////////////////////////////////////////////////////////////////////

module fault_inject_ctrl #(
    parameter [31:0] RNG_SEED = 32'h1A2B3C4D
) (
    input              clk,
    input              rst,

    input              fault_req,
    input      [1:0]   fault_model_sel,    // 00:A 01:B 10:C 11:D
    input      [3:0]   fault_byte_pos_in,

    output reg         fault_en_out,
    output reg [3:0]   fault_byte_pos_out,
    output reg [7:0]   fault_val_out,
    output reg [127:0] fault_mask_dbg
);

    localparam [31:0] EFFECTIVE_SEED = (RNG_SEED == 32'b0) ? 32'h1 : RNG_SEED;     //防止种子为0，为0则种子为32'h1

    integer offset_sel;  //字节位置偏移量
    integer hw_sel;

    reg       tmp_fault_en;
    reg [3:0] tmp_fault_pos;
    reg [7:0] tmp_fault_val;
    reg [127:0] tmp_mask128;
    reg [31:0] rng_state;

//决定目标字节中哪个 bit 被翻转
    function [7:0] onehot8;       
        input [2:0] idx;
        begin
            case (idx)
                3'd0: onehot8 = 8'b0000_0001;
                3'd1: onehot8 = 8'b0000_0010;
                3'd2: onehot8 = 8'b0000_0100;
                3'd3: onehot8 = 8'b0000_1000;
                3'd4: onehot8 = 8'b0001_0000;
                3'd5: onehot8 = 8'b0010_0000;
                3'd6: onehot8 = 8'b0100_0000;
                3'd7: onehot8 = 8'b1000_0000;
                default: onehot8 = 8'b0000_0001;
            endcase
        end
    endfunction

//把输入位置限制在 0 ~ 15，用于防止 Model C 的随机偏移导致字节位置越界
    function [3:0] clamp_0_15;
        input integer pos;
        begin
            if (pos < 0)
                clamp_0_15 = 4'd0;
            else if (pos > 15)
                clamp_0_15 = 4'd15;
            else
                clamp_0_15 = pos;
        end
    endfunction

//取 state[31]、state[21]、state[1]、state[0] 做异或
//得到 feedback
//然后整体左移一位，把 feedback 放到最低位
    function [31:0] lfsr_next;
        input [31:0] state;
        reg feedback;
        begin
            feedback = state[31] ^ state[21] ^ state[1] ^ state[0];
            lfsr_next = {state[30:0], feedback};
            if (lfsr_next == 32'b0)
                lfsr_next = EFFECTIVE_SEED;
        end
    endfunction

    // 逐级展开，确保每次 fault_req 只采样一次随机序列
    wire [31:0] rng1  = lfsr_next(rng_state);
    wire [31:0] rng2  = lfsr_next(rng1);
    wire [31:0] rng3  = lfsr_next(rng2);
    wire [31:0] rng4  = lfsr_next(rng3);
    wire [31:0] rng5  = lfsr_next(rng4);
    wire [31:0] rng6  = lfsr_next(rng5);
    wire [31:0] rng7  = lfsr_next(rng6);
    wire [31:0] rng8  = lfsr_next(rng7);
    wire [31:0] rng9  = lfsr_next(rng8);
    wire [31:0] rng10 = lfsr_next(rng9);
    wire [31:0] rng11 = lfsr_next(rng10);
    wire [31:0] rng12 = lfsr_next(rng11);    
    //一次故障请求中会同时使用 rng1 ~ rng12 的不同部分来决定
    //翻转哪个 bit
    //翻转几个 bit
    //字节位置偏移多少
    //Model D 是否注入成功
    //Model D 选择哪个子模型

    wire [2:0] rand_idx0_w = rng1[2:0];
    wire [2:0] rand_idx1_w = rng2[2:0];
    wire [2:0] rand_idx2_w = rng3[2:0];
    wire [2:0] rand_idx3_w = rng4[2:0];
    //随机bit下标，表示目标字节中的 bit 位置

    // =====================================================
    // 受控 HW 的 Model A / D-A 子模型
    // =====================================================

    // A: 2~4 bit 随机翻转
    reg [7:0] modelA_fault_w;
    reg [2:0] modelA_hw_sel;

    always @(*) begin
        modelA_fault_w = 8'b0;

        // 分布: 2bit(50%), 3bit(35%), 4bit(15%)
        case (rng5[3:0] % 20)
            0,1,2,3,4,5,6,7,8,9:           modelA_hw_sel = 3'd2; // 10/20
            10,11,12,13,14,15,16:          modelA_hw_sel = 3'd3; // 7/20
            default:                       modelA_hw_sel = 3'd4; // 3/20
        endcase

        modelA_fault_w = onehot8(rand_idx0_w);
        if (modelA_hw_sel >= 2)
            modelA_fault_w = modelA_fault_w | onehot8(rand_idx1_w);
        if (modelA_hw_sel >= 3)
            modelA_fault_w = modelA_fault_w | onehot8(rand_idx2_w);
        if (modelA_hw_sel >= 4)
            modelA_fault_w = modelA_fault_w | onehot8(rand_idx3_w);

        // 若随机位置重复导致HW下降，补一个bit
        if (modelA_fault_w == 8'b0)
            modelA_fault_w = onehot8(rand_idx0_w) | onehot8(rand_idx1_w);
        else if (modelA_hw_sel == 3'd2 && (modelA_fault_w == onehot8(rand_idx0_w)))
            modelA_fault_w = modelA_fault_w | onehot8(rand_idx2_w);
    end

    // D 中 mimic A：同样用受控 HW bit 随机模型
    reg [7:0] modelD_A_fault_w;
    reg [2:0] modelD_A_hw_sel;

    always @(*) begin
        modelD_A_fault_w = 8'b0;

        case (rng12[3:0] % 20)
            0,1,2,3,4,5,6,7,8,9:           modelD_A_hw_sel = 3'd2;
            10,11,12,13,14,15,16:          modelD_A_hw_sel = 3'd3;
            default:                       modelD_A_hw_sel = 3'd4;
        endcase

        modelD_A_fault_w = onehot8(rand_idx0_w);
        if (modelD_A_hw_sel >= 2)
            modelD_A_fault_w = modelD_A_fault_w | onehot8(rand_idx1_w);
        if (modelD_A_hw_sel >= 3)
            modelD_A_fault_w = modelD_A_fault_w | onehot8(rand_idx2_w);
        if (modelD_A_hw_sel >= 4)
            modelD_A_fault_w = modelD_A_fault_w | onehot8(rand_idx3_w);

        if (modelD_A_fault_w == 8'b0)
            modelD_A_fault_w = onehot8(rand_idx0_w) | onehot8(rand_idx1_w);
        else if (modelD_A_hw_sel == 3'd2 && (modelD_A_fault_w == onehot8(rand_idx0_w)))
            modelD_A_fault_w = modelD_A_fault_w | onehot8(rand_idx2_w);
    end

    // =====================================================
    // Sample the random fault behavior exactly once per request
    // =====================================================
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            rng_state          <= EFFECTIVE_SEED;
            fault_en_out       <= 1'b0;
            fault_byte_pos_out <= 4'b0;
            fault_val_out      <= 8'b0;
        end
        else if (fault_req) begin
            tmp_fault_en  = 1'b0;
            tmp_fault_pos = fault_byte_pos_in;
            tmp_fault_val = 8'b0;
            offset_sel    = (rng7[2:0] % 5) - 2;  // -2 ~ +2
            hw_sel        = 1;

            case (fault_model_sel)
                // A: reproducible random-bit multi-bit flip with controlled HW
                2'b00: begin
                    tmp_fault_en  = 1'b1;
                    tmp_fault_pos = fault_byte_pos_in;
                    tmp_fault_val = modelA_fault_w;
                end

                // B: sparse random bit-flip with low Hamming weight
                //1 bit：5/10 = 50%
                //2 bit：3/10 = 30%
                //3 bit：1/10 = 10%
                //4 bit：1/10 = 10%
                2'b01: begin
                    tmp_fault_en  = 1'b1;
                    tmp_fault_pos = fault_byte_pos_in;

                    case (rng6[3:0] % 10)
                        0,1,2,3,4: hw_sel = 1;
                        5,6,7    : hw_sel = 2;
                        8        : hw_sel = 3;
                        default  : hw_sel = 4;
                    endcase

                    tmp_fault_val = onehot8(rand_idx0_w);
                    if (hw_sel >= 2)
                        tmp_fault_val = tmp_fault_val | onehot8(rand_idx1_w);
                    if (hw_sel >= 3)
                        tmp_fault_val = tmp_fault_val | onehot8(rand_idx2_w);
                    if (hw_sel >= 4)
                        tmp_fault_val = tmp_fault_val | onehot8(rand_idx3_w);
                end

                // C: random bit model with spatial offset
                2'b10: begin
                    tmp_fault_en  = 1'b1;
                    tmp_fault_pos = clamp_0_15(fault_byte_pos_in + offset_sel);

                    case (rng8[2:0] % 8)
                        0,1,2,3: begin
                            tmp_fault_val = onehot8(rand_idx0_w);
                        end
                        4,5,6: begin
                            tmp_fault_val = onehot8(rand_idx0_w) | onehot8(rand_idx1_w);
                        end
                        default: begin
                            tmp_fault_val = onehot8(rand_idx0_w);
                            if ((rng9 % 100) < 30)
                                tmp_fault_val = tmp_fault_val | onehot8(rand_idx1_w);
                        end
                    endcase
                end

                // D: mixed fault model with timing jitter
                2'b11: begin
                    // ~75% chance to inject successfully
                    if ((rng10[1:0] % 4) != 2'b11) begin    //0,1,2 → 注入成功，约 75% ；3 → 不注入，约 25%
                        tmp_fault_en = 1'b1;

                        case (rng11[1:0] % 3)
                            2'd0: begin
                                // mimic A
                                tmp_fault_pos = fault_byte_pos_in;
                                tmp_fault_val = modelD_A_fault_w;
                            end

                            2'd1: begin
                                // mimic B
                                tmp_fault_pos = fault_byte_pos_in;
                                tmp_fault_val = onehot8(rand_idx0_w);
                                if ((rng12 % 100) < 35)
                                    tmp_fault_val = tmp_fault_val | onehot8(rand_idx1_w);
                                    //先翻转 1 bit，有 35% 概率再加一个 bit
                            end

                            default: begin
                                // mimic C
                                tmp_fault_pos = clamp_0_15(fault_byte_pos_in + offset_sel);
                                tmp_fault_val = onehot8(rand_idx0_w);
                                if ((rng12 % 100) < 25)
                                    tmp_fault_val = tmp_fault_val | onehot8(rand_idx1_w);
                                    //先翻转 1 bit，有 25% 概率再加一个 bit
                            end
                        endcase
                    end
                    else begin
                        tmp_fault_en  = 1'b0;
                        tmp_fault_pos = fault_byte_pos_in;
                        tmp_fault_val = 8'b0;
                    end
                end

                default: begin
                    tmp_fault_en  = 1'b0;
                    tmp_fault_pos = fault_byte_pos_in;
                    tmp_fault_val = 8'b0;
                end
            endcase

            rng_state          <= rng12;
            fault_en_out       <= tmp_fault_en;
            fault_byte_pos_out <= tmp_fault_pos;
            fault_val_out      <= tmp_fault_val;
        end
        else begin
            fault_en_out       <= 1'b0;
            fault_byte_pos_out <= fault_byte_pos_in;
            fault_val_out      <= 8'b0;
        end
    end

    always @(*) begin
        tmp_mask128 = 128'b0;
        if (fault_en_out) begin
            tmp_mask128 = {{120{1'b0}}, fault_val_out} << (fault_byte_pos_out * 8);
        end
        fault_mask_dbg = tmp_mask128;
    end

endmodule