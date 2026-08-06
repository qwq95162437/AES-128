`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/06 18:26:47
// Design Name: 
// Module Name: final_round
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


module final_round(
    input  [127:0] state_in,
    input  [127:0] round_key,
    output [127:0] state_out
);

wire [127:0] sub, sh;

// SubBytes
sub_bytes u_sub(.state_in(state_in), .state_out(sub));

// ShiftRows
shift_rows u_shift(.state_in(sub), .state_out(sh));

// AddRoundKey
assign state_out = sh ^ round_key;

endmodule

