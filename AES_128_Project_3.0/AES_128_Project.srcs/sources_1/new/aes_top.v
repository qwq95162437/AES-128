`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/06 18:27:14
// Design Name: 
// Module Name: aes_top
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module aes_top(
    input              clk,
    input              rst,

    input              fault_req,        // 原来的 fault_en，建议改名
    input      [1:0]   fault_model_sel,  // 00:A 01:B 10:C 11:D
    input      [3:0]   fault_byte_pos,

    input      [127:0] plaintext,
    input      [127:0] key,
    output     [127:0] ciphertext,

    // debug
    output     [7:0]   fault_val_dbg,
    output     [127:0] fault_mask_dbg,
    output     [3:0]   fault_pos_dbg,
    output             fault_en_dbg
);

    wire [1407:0] round_keys;
    wire [127:0] round_states [0:10];

    wire         fault_en_w;
    wire [3:0]   fault_pos_w;
    wire [7:0]   fault_val_w;
    wire [127:0] fault_mask_w;

    genvar i;

    // --------- Key Expansion ---------
    key_expansion u_key (
        .key_in(key),
        .round_keys(round_keys)
    );

    // --------- 初始轮：AddRoundKey ---------
    assign round_states[0] = plaintext ^ round_keys[1407-:128];

    // --------- 故障控制模块 ---------
    fault_inject_ctrl u_fault_ctrl (
        .clk               (clk),
        .rst               (rst),
        .fault_req         (fault_req),                 //故障请求信号
        .fault_model_sel   (fault_model_sel),           //故障模型选择
        .fault_byte_pos_in (fault_byte_pos),            //故障注入位置

        .fault_en_out      (fault_en_w),                //故障是否注入
        .fault_byte_pos_out(fault_pos_w),               //实际注入字节位置
        .fault_val_out     (fault_val_w),               //实际注入的 8 位故障值，也就是 bit 翻转 mask
        .fault_mask_dbg    (fault_mask_w)               //展开成 128 位后的故障 mask 
    );

    assign fault_en_dbg   = fault_en_w;
    assign fault_pos_dbg  = fault_pos_w;
    assign fault_val_dbg  = fault_val_w;
    assign fault_mask_dbg = fault_mask_w;

    // --------- 第1~第8轮：正常轮 ---------
    generate
        for (i = 1; i < 9; i = i + 1) begin : normal_rounds
            aes_round u_round (
                .state_in(round_states[i-1]),
                .round_key(round_keys[1407-128*i -: 128]),
                .state_out(round_states[i])
            );
        end
    endgenerate

    // --------- 第9轮：MixColumns 前注入故障 ---------
    aes_round_fault_mc_pre u_round9_fault (
        .state_in       (round_states[8]),
        .round_key      (round_keys[1407-128*9 -: 128]),
        .fault_en       (fault_en_w),
        .fault_byte_pos (fault_pos_w),
        .fault_val      (fault_val_w),
        .state_out      (round_states[9])
    );

    // --------- 第10轮：最后一轮 ---------
    final_round u_final (
        .state_in(round_states[9]),
        .round_key(round_keys[1407-128*10 -: 128]),
        .state_out(ciphertext)
    );

endmodule








