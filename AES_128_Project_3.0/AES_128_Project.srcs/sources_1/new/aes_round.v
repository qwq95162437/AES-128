`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/06 18:26:21
// Design Name: 
// Module Name: aes_round
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


module aes_round(
    input  [127:0] state_in,
    input  [127:0] round_key,
    output [127:0] state_out
);

wire [127:0] sub, sh, mix;

// SubBytes
sub_bytes u_sub(.state_in(state_in), .state_out(sub));

// ShiftRows
shift_rows u_shift(.state_in(sub), .state_out(sh));

// MixColumns
mix_columns u_mix(.state_in(sh), .state_out(mix));

// AddRoundKey
assign state_out = mix ^ round_key;

endmodule

