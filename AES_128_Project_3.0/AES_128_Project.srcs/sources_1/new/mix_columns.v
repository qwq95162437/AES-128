`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/06 18:36:24
// Design Name: 
// Module Name: mix_columns
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


module mix_columns(
    input  [127:0] state_in,
    output [127:0] state_out
);

// GF(2^8) 乘法
function [7:0] xtime;
    input [7:0] b;
    begin
        xtime = {b[6:0],1'b0} ^ (8'h1b & {8{b[7]}});   //AES 中 GF(2^8) 乘以 02 的标准实现
    end
endfunction

function [7:0] mul2;
    input [7:0] b; mul2 = xtime(b); endfunction
function [7:0] mul3;
    input [7:0] b; mul3 = xtime(b) ^ b; endfunction

genvar c;
generate                                          
    for(c=0;c<4;c=c+1) begin : col_loop       //综合时展开硬件结构
        wire [7:0] s0,s1,s2,s3;
        assign s0 = state_in[127-32*c -:8];
        assign s1 = state_in[119-32*c -:8];
        assign s2 = state_in[111-32*c -:8];
        assign s3 = state_in[103-32*c -:8];
        assign state_out[127-32*c -:8] = mul2(s0) ^ mul3(s1) ^ s2 ^ s3;
        assign state_out[119-32*c -:8] = s0 ^ mul2(s1) ^ mul3(s2) ^ s3;
        assign state_out[111-32*c -:8] = s0 ^ s1 ^ mul2(s2) ^ mul3(s3);
        assign state_out[103-32*c -:8] = mul3(s0) ^ s1 ^ s2 ^ mul2(s3);
    end
endgenerate

endmodule

