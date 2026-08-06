`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/23 21:20:39
// Design Name: 
// Module Name: aes_fault_modelA_tb
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


module aes_fault_modelA_tb;

    // ----------------------------------------
    // 信号定义
    // ----------------------------------------
    reg clk;
    reg rst;

    reg         fault_req;
    reg [1:0]   fault_model_sel;
    reg [3:0]   fault_byte_pos;
    reg [127:0] plaintext;
    reg [127:0] key;

    wire [127:0] ciphertext;

    reg [127:0] correct_cipher;
    reg [127:0] fault_cipher;

    integer file;
    integer i, j;
    integer NUM_SAMPLES;

    // ----------------------------------------
    // AES模块实例
    // ----------------------------------------
    aes_top uut (
        .clk             (clk),
        .rst             (rst),
        .fault_req       (fault_req),
        .fault_model_sel (fault_model_sel),
        .fault_byte_pos  (fault_byte_pos),
        .plaintext       (plaintext),
        .key             (key),
        .ciphertext      (ciphertext)
    );

    // ----------------------------------------
    // 时钟生成 10ns
    // ----------------------------------------
    always #5 clk = ~clk;

    // ----------------------------------------
    // 主流程
    // ----------------------------------------
    initial begin
        clk   = 0;
        rst   = 1;
        fault_req       = 0;
        fault_model_sel = 2'b00;
        fault_byte_pos  = 4'd0;
        plaintext       = 128'd0;
        key             = 128'h000102030405060708090a0b0c0d0e0f;

        NUM_SAMPLES = 2000; // 模型A样本数量，可以改大

        #20;
        rst = 0;
        @(posedge clk); #1;

        // 打开CSV文件
        file = $fopen("dfa_model_A_attacker.csv", "w");
        if (file == 0) begin
            $display("ERROR: cannot open CSV file!");
            $finish;
        end

        // 写CSV表头
        $fwrite(file, "model_sel,sample_id,plaintext,correct_cipher,fault_cipher\n");

        // -----------------------------
        // 生成样本
        // -----------------------------
        for (j = 0; j < NUM_SAMPLES; j = j + 1) begin
            // 随机plaintext
            plaintext = 128'h00112233445566778899aabbccddeeff + j;

            // -------- 正常加密 --------
            fault_req = 1'b0;
            @(posedge clk); #1;
            correct_cipher = ciphertext;

            // -------- 故障加密 --------
            fault_req       = 1'b1;
            fault_model_sel = 2'b00; // 模型A
            fault_byte_pos  = $urandom_range(0, 15);
            @(posedge clk); #1;
            fault_cipher = ciphertext;

            // -------- 写CSV --------
            $fwrite(file, "0,%0d,%032h,%032h,%032h\n",
                j,
                plaintext,
                correct_cipher,
                fault_cipher
            );

            // 清除故障
            fault_req = 1'b0;
            @(posedge clk); #1;
        end

        $fclose(file);
        $display("✅ 模型A CSV数据生成完成: dfa_model_A_attacker.csv");
        $finish;
    end

endmodule

