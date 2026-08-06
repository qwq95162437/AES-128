`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 2026/03/06 20:02:25
// Design Name: 
// Module Name: aes_fault_tb
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


module aes_fault_tb;

    reg clk;
    reg rst;

    reg         fault_req;           //fault_req = 0 → 正常加密，不请求故障；fault_req = 1 → 请求故障控制模块产生一次故障
    reg [1:0]   fault_model_sel;
    reg [3:0]   fault_byte_pos;
    reg [127:0] plaintext;
    reg [127:0] key;

    wire [127:0] ciphertext;
    wire [7:0]   fault_val_dbg;      //实际生成的故障值，也就是 8 位 bit 翻转 mask
    wire [127:0] fault_mask_dbg;     //实际 128 位故障 mask，也就是把 fault_val_dbg 放到实际注入字节位置后的完整 128 位掩码
    wire [3:0]   fault_pos_dbg;      //实际注入的字节位置，不一定等于请求的 fault_byte_pos
    wire         fault_en_dbg;       //实际是否注入成功，Model D 里有约 25% 的 miss，所以这个值可能为 0

    reg [127:0] correct_cipher;
    reg [127:0] fault_cipher;
    reg [127:0] diff;

    integer file;                    //CSV 文件句柄
    integer i, j, m;                 //i主要用于遍历 16 个 diff 字节，遍历 fault_val_dbg 的 8 个 bit，打印 16 个字节位置命中分布
    integer NUM_PLAINTEXTS_PER_MODEL;

    reg [3:0]  first_diff_byte;      //第一个出现密文差异的字节编号，从低位开始扫描
    reg [15:0] diff_byte_mask;       //记录哪些字节发生了密文差异
    integer    diff_nonzero_count;   //统计 diff 中有多少个非零字节

    integer    fault_hw;             //实际翻转了几个 bit
    integer    dfa_valid;            //这条样本是否满足代码定义的 DFA 有效条件

    // -----------------------------
    // 统计变量
    // -----------------------------
    integer total_samples      [0:3];          //每个模型总样本数
    integer inject_success_cnt [0:3];          //每个模型实际注入成功的次数
    integer miss_cnt           [0:3];          //每个模型未注入成功的次数
    integer diff_nonzero_sum   [0:3];          //每个模型所有样本的 diff_nonzero_count 总和
    integer hit_dist           [0:3][0:15];    //统计每个模型实际命中各个字节位置的次数
    integer dfa_valid_cnt      [0:3];          //每个模型中 DFA 有效样本的数量
    integer fault_hw_sum       [0:3];          //每个模型所有样本的故障汉明重量总和

    real avg_diff_nonzero_bytes;               //平均每条样本有多少个密文字节不同
    real inject_success_rate;                  //实际注入成功率
    real miss_rate_d;                          //Model D 的 miss 率
    real avg_fault_hw;                         //平均故障汉明重量
    real dfa_valid_rate;                       //DFA 有效样本率

    // AES模块实例
    aes_top uut (
        .clk             (clk),
        .rst             (rst),
        .fault_req       (fault_req),
        .fault_model_sel (fault_model_sel),
        .fault_byte_pos  (fault_byte_pos),
        .plaintext       (plaintext),
        .key             (key),
        .ciphertext      (ciphertext),
        .fault_val_dbg   (fault_val_dbg),
        .fault_mask_dbg  (fault_mask_dbg),
        .fault_pos_dbg   (fault_pos_dbg),
        .fault_en_dbg    (fault_en_dbg)
    );

    // 时钟：10ns周期
    always #5 clk = ~clk;

//时钟从 0 开始
//系统进入复位
//暂时不请求故障
//默认选择 Model A
//默认故障位置为 byte0
//明文先清零
//密钥设为固定 AES-128 密钥
//每个模型跑 320 条样本
    initial begin
        clk                     = 0;
        rst                     = 1;
        fault_req               = 0;
        fault_model_sel         = 2'b00;
        fault_byte_pos          = 4'd0;
        plaintext               = 128'd0;
        key                     = 128'h2b7e151628aed2a6abf7158809cf4f3c;
        NUM_PLAINTEXTS_PER_MODEL = 320;   

        // 初始化统计变量
        for (m = 0; m < 4; m = m + 1) begin
            total_samples[m]      = 0;
            inject_success_cnt[m] = 0;
            miss_cnt[m]           = 0;
            diff_nonzero_sum[m]   = 0;
            dfa_valid_cnt[m]      = 0;
            fault_hw_sum[m]       = 0;
            for (i = 0; i < 16; i = i + 1) begin
                hit_dist[m][i] = 0;
            end
        end

        file = $fopen("fault_dataset.csv", "w");
        if (file == 0) begin
            $display("ERROR: cannot open file!");
            $finish;
        end

        $fwrite(file,
            "model_sel,sample_id,plaintext,req_inject_byte_pos,actual_inject_en,actual_inject_byte_pos,fault_val,fault_hw,dfa_valid,fault_mask,correct_cipher,fault_cipher,diff,diff_nonzero_count,diff_byte_mask,first_diff_byte\n"
        );

//等待 20ns
//释放复位 rst = 0
//再等一个时钟上升沿
//再延迟 1ns，保证输出稳定后开始正式采样
        #20;
        rst = 0;

        @(posedge clk);
        #1;

        // -----------------------------
        // 按模型分别跑
        // -----------------------------
        for (m = 0; m < 4; m = m + 1) begin
            for (j = 0; j < NUM_PLAINTEXTS_PER_MODEL; j = j + 1) begin

                // 1) 正常加密
                plaintext       = 128'h00112233445566778899aabbccddeeff + (m * NUM_PLAINTEXTS_PER_MODEL + j);
                fault_req       = 1'b0;
                fault_model_sel = m[1:0];
                fault_byte_pos  = 4'd0;

                @(posedge clk);
                #1;
                correct_cipher = ciphertext;

                // 2) 故障加密
                fault_model_sel = m[1:0];
                fault_byte_pos  = $urandom_range(0, 15);
                fault_req       = 1'b1;

                @(posedge clk);
                #1;

                fault_cipher = ciphertext;
                diff         = correct_cipher ^ fault_cipher;

                // 3) 统计 diff 非零字节
                first_diff_byte    = 4'd0;
                diff_byte_mask     = 16'b0;
                diff_nonzero_count = 0;

                for (i = 0; i < 16; i = i + 1) begin
                    if (diff[i*8 +: 8] != 8'b0) begin
                        diff_byte_mask[i] = 1'b1;
                        diff_nonzero_count = diff_nonzero_count + 1;
                        if (diff_nonzero_count == 1)
                            first_diff_byte = i[3:0];
                    end
                end

                // 4) 计算 fault_hw
                fault_hw = 0;
                for (i = 0; i < 8; i = i + 1) begin
                    if (fault_val_dbg[i])
                        fault_hw = fault_hw + 1;
                end

                // 5) 计算 dfa_valid
                if ((fault_en_dbg == 1'b1) && (diff_nonzero_count == 4))
                    dfa_valid = 1;
                else
                    dfa_valid = 0;

                // 6) 写CSV
                $fwrite(file,
                    "%0d,%0d,%032h,%0d,%0d,%0d,%02h,%0d,%0d,%032h,%032h,%032h,%032h,%0d,%04h,%0d\n",
                    m,
                    j,
                    plaintext,
                    fault_byte_pos,
                    fault_en_dbg,
                    fault_pos_dbg,
                    fault_val_dbg,
                    fault_hw,
                    dfa_valid,
                    fault_mask_dbg,
                    correct_cipher,
                    fault_cipher,
                    diff,
                    diff_nonzero_count,
                    diff_byte_mask,
                    first_diff_byte
                );

                // 7) 更新统计
                total_samples[m]    = total_samples[m] + 1;
                diff_nonzero_sum[m] = diff_nonzero_sum[m] + diff_nonzero_count;
                fault_hw_sum[m]     = fault_hw_sum[m] + fault_hw;

                if (fault_en_dbg) begin
                    inject_success_cnt[m] = inject_success_cnt[m] + 1;
                    hit_dist[m][fault_pos_dbg] = hit_dist[m][fault_pos_dbg] + 1;
                end
                else begin
                    miss_cnt[m] = miss_cnt[m] + 1;
                end

                if (dfa_valid)
                    dfa_valid_cnt[m] = dfa_valid_cnt[m] + 1;

                // 8) 清故障
                fault_req = 1'b0;
                @(posedge clk);
                #1;
            end
        end

        // -----------------------------
        // 打印统计结果
        // -----------------------------
        $display("\n====================================================");
        $display("                Fault Injection Summary             ");
        $display("====================================================");

        for (m = 0; m < 4; m = m + 1) begin
            avg_diff_nonzero_bytes = 1.0 * diff_nonzero_sum[m] / total_samples[m];
            inject_success_rate    = 100.0 * inject_success_cnt[m] / total_samples[m];
            avg_fault_hw           = 1.0 * fault_hw_sum[m] / total_samples[m];
            dfa_valid_rate         = 100.0 * dfa_valid_cnt[m] / total_samples[m];

            $display("\n--------------------------------------------");
            case (m)
                0: $display("Model A : Ideal single-byte random multi-bit flip");
                1: $display("Model B : Sparse random bit-flip model");
                2: $display("Model C : Random bit model with spatial offset");
                3: $display("Model D : Mixed fault model with timing jitter");
            endcase
            $display("--------------------------------------------");

            $display("Total samples                = %0d", total_samples[m]);
            $display("Actual inject success count  = %0d", inject_success_cnt[m]);
            $display("Actual inject success rate   = %0.2f%%", inject_success_rate);
            $display("Average diff nonzero bytes   = %0.4f", avg_diff_nonzero_bytes);
            $display("Average fault HW             = %0.4f", avg_fault_hw);
            $display("DFA-valid sample count       = %0d", dfa_valid_cnt[m]);
            $display("DFA-valid sample rate        = %0.2f%%", dfa_valid_rate);

            if (m == 3) begin
                miss_rate_d = 100.0 * miss_cnt[m] / total_samples[m];
                $display("Model D miss count           = %0d", miss_cnt[m]);
                $display("Model D miss rate            = %0.2f%%", miss_rate_d);
            end

            $display("Actual hit distribution over byte positions:");
            for (i = 0; i < 16; i = i + 1) begin
                $display("  byte[%0d] : %0d", i, hit_dist[m][i]);
            end
        end

        $display("\n====================================================");
        $display("All simulations finished, time = %0t", $time);
        $display("====================================================\n");

        $fclose(file);
        $display("Simulation Finished");
        $finish;
    end

endmodule





