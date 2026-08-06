`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/15 14:29:29
// Design Name: 
// Module Name: aes_round_fault_mc_pre
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


module aes_round_fault_mc_pre (
    input  [127:0] state_in,
    input  [127:0] round_key,

    input          fault_en,
    input  [3:0]   fault_byte_pos,
    input  [7:0]   fault_val,

    output [127:0] state_out
);

    wire [127:0] subbytes_out;
    wire [127:0] shiftrows_out;
    wire [127:0] fault_injected_state;
    wire [127:0] mixcolumns_out;

    reg  [127:0] fault_mask;

    // 1) SubBytes
    sub_bytes u_sub_bytes (
        .state_in(state_in),
        .state_out(subbytes_out)
    );

    // 2) ShiftRows
    shift_rows u_shift_rows (
        .state_in(subbytes_out),
        .state_out(shiftrows_out)
    );

    // 3) 在 MixColumns 前注入故障
    always @(*) begin
        fault_mask = 128'b0;
        if (fault_en) begin
            fault_mask[fault_byte_pos*8 +: 8] = fault_val;
        end
    end

    assign fault_injected_state = shiftrows_out ^ fault_mask;

    // 4) MixColumns
    mix_columns u_mix_columns (
        .state_in(fault_injected_state),
        .state_out(mixcolumns_out)
    );

    // 5) AddRoundKey
    assign state_out = mixcolumns_out ^ round_key;

endmodule

