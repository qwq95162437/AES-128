from pathlib import Path
import pandas as pd
from collections import defaultdict
from itertools import permutations
import matplotlib.pyplot as plt

# =========================================================
# 路径配置
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# =========================================================
# 配置
# =========================================================
MODELS = ["A", "B", "C", "D"]
MIN_SAMPLES_PER_MASK = 20
TOP_N = 8
MASTER_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"

# =========================================================
# AES SBOX / INV_SBOX
# =========================================================
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

ROW_PATTERNS = [
    [2, 1, 1, 3],
    [3, 2, 1, 1],
    [1, 3, 2, 1],
    [1, 1, 3, 2],
]

# =========================================================
# 工具函数
# =========================================================
# 把十六进制字符串转成字节数组
def hex2bytes(s):
    return bytes.fromhex(str(s).strip())

# 找出差分中非零字节的位置
def nonzero_positions(diff_hex):
    b = hex2bytes(diff_hex)
    return [i for i, x in enumerate(b) if x != 0]

def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# =========================================================
# AES key schedule 与逆 key schedule
# =========================================================
# 循环左移一个字节
def rot_word(w):
    return w[1:] + w[:1]

# s盒替换
def sub_word(w):
    return [SBOX[x] for x in w]

def key_expansion_128(master_key_bytes):
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    key = list(master_key_bytes)
    words = [key[i:i+4] for i in range(0, 16, 4)]         # 把主密钥拆成 4 个 word
    for i in range(4, 44):                                # 生成 44 个 word
        temp = words[i-1].copy()
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[(i // 4) - 1]
        new_word = [words[i-4][j] ^ temp[j] for j in range(4)]
        words.append(new_word)
    round_keys = []
    for r in range(11):
        rk = []
        for w in words[r*4:(r+1)*4]:
            rk.extend(w)
        round_keys.append(bytes(rk))
    return round_keys

def inv_key_schedule_128_from_round10(round10_key_bytes):
    RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    def xor_words(a, b):
        return [x ^ y for x, y in zip(a, b)]
    def rot_word(w):
        return w[1:] + w[:1]
    def sub_word(w):
        return [SBOX[x] for x in w]
    cur_words = [list(round10_key_bytes[i:i+4]) for i in range(0, 16, 4)]
    for round_idx in range(10, 0, -1):
        prev_words = [None] * 4
        prev_words[3] = xor_words(cur_words[3], cur_words[2])
        prev_words[2] = xor_words(cur_words[2], cur_words[1])
        prev_words[1] = xor_words(cur_words[1], cur_words[0])
        g = sub_word(rot_word(prev_words[3]))
        g[0] ^= RCON[round_idx-1]
        prev_words[0] = xor_words(cur_words[0], g)
        cur_words = prev_words
    master_key = bytes(sum(cur_words, []))
    return master_key

# =========================================================
# 数据读取
# =========================================================
def load_god_dataframe(csv_file):
    df = pd.read_csv(csv_file)
    df.columns = [c.strip() for c in df.columns]        # 去掉 CSV 表头两边的空格
    if "diff_nonzero_count" not in df.columns:
        df["diff_nonzero_count"] = df["diff"].apply(lambda x: len(nonzero_positions(x)))
    df["diff_nonzero_count"] = pd.to_numeric(df["diff_nonzero_count"], errors="coerce")
    if "diff_byte_mask_norm" not in df.columns:
        df["diff_byte_mask_norm"] = df["diff_byte_mask"].apply(lambda x: str(x).zfill(4))
    return df

# =========================================================
# 构建 mask 样本
# =========================================================
def build_samples_for_mask(df_mask):
    active_positions = nonzero_positions(df_mask.iloc[0]["diff"])   # 非零差分位置
    samples = []
    for _, row in df_mask.iterrows():
        pos = nonzero_positions(row["diff"])
        if pos != active_positions:
            continue
        samples.append({
            "correct": hex2bytes(row["correct_cipher"]),
            "faulty": hex2bytes(row["fault_cipher"]),
            "fault_val": int(str(row["fault_val"]), 16),
            "inject_pos": int(row["actual_inject_byte_pos"]),
        })
    return samples, active_positions

# =========================================================
# 预计算 delta 桶
# =========================================================
def precompute_delta_buckets(samples, active_positions):
    precomp = []
    for s in samples:
        sample_map = {}
        c = s["correct"]
        f = s["faulty"]
        for pos in active_positions:
            buckets = defaultdict(list)
            c_byte = c[pos]
            f_byte = f[pos]
            for k in range(256):
                delta = INV_SBOX[c_byte ^ k] ^ INV_SBOX[f_byte ^ k]
                buckets[delta].append(k)
            sample_map[pos] = buckets
        precomp.append(sample_map)
    return precomp

# =========================================================
# 单个配置评分
# =========================================================
def evaluate_config(samples, active_positions, precomp, inject_map, pos_order, top_n=TOP_N):
    candidate_counts = {pos: [0] * 256 for pos in active_positions}
    for s_idx, s in enumerate(samples):
        e = s["fault_val"]
        inj = s["inject_pos"]
        if inj not in inject_map:
            continue
        row_idx = inject_map[inj]
        coeffs = ROW_PATTERNS[row_idx]
        target_delta = {pos: gf_mul(coeffs[i], e) for i, pos in enumerate(pos_order)}
        for pos in active_positions:
            delta_need = target_delta[pos]
            keys = precomp[s_idx][pos].get(delta_need, [])
            for k in keys:
                candidate_counts[pos][k] += 1
    total_score = 0
    details = {}
    for pos in active_positions:
        counts = candidate_counts[pos]
        ranked = sorted([(k, c) for k, c in enumerate(counts)], key=lambda x: x[1], reverse=True)
        top1 = ranked[0][1] if ranked else 0
        top2 = ranked[1][1] if len(ranked) > 1 else 0
        total_score += (top1 - top2) + top1
        details[pos] = ranked[:top_n]
    return total_score, candidate_counts, details

# =========================================================
# 单个 mask 恢复
# =========================================================
def recover_for_mask(mask, df_mask):
    samples, active_positions = build_samples_for_mask(df_mask)
    if len(samples) < MIN_SAMPLES_PER_MASK:
        return None
    inject_values = sorted({s["inject_pos"] for s in samples})
    if len(inject_values) != 4:
        return None
    precomp = precompute_delta_buckets(samples, active_positions)
    best, best_result = None, None
    for row_perm in permutations(range(4), 4):
        inject_map = {inj: row_perm[i] for i, inj in enumerate(inject_values)}
        for pos_order in permutations(active_positions, len(active_positions)):
            score, candidate_counts, details = evaluate_config(samples, active_positions, precomp, inject_map, pos_order)
            if best is None or score > best:
                best = score
                best_result = {
                    "mask": mask, "score": score, "samples": len(samples),
                    "active_positions": active_positions, "inject_map": inject_map,
                    "pos_order": pos_order, "candidate_counts": candidate_counts,
                    "details": details
                }
    # 对每个受影响的位置，取排名第一的 key 候选作为恢复结果
    partial = {pos: best_result["details"][pos][0][0] for pos in active_positions if best_result["details"][pos]}
    best_result["partial_key"] = partial
    return best_result

# =========================================================
# 批量处理四个模型
# =========================================================
def process_all_models():
    for model in MODELS:
        print(f"\n========== 处理模型 {model} ==========")
        csv_file = RESULTS_DIR / f"dfa_model_{model}_god.csv"
        df = load_god_dataframe(csv_file)
        mask_counts = df["diff_byte_mask_norm"].value_counts()
        results = []

        for mask, count in mask_counts.items():
            if count < MIN_SAMPLES_PER_MASK:
                continue
            df_mask = df[df["diff_byte_mask_norm"] == mask].copy()
            try:
                res = recover_for_mask(mask, df_mask)
                if res:
                    results.append(res)
            except Exception as e:
                print(f"mask {mask} 处理失败: {e}")

        merged_key = [None] * 16
        for res in results:
            for pos, val in res["partial_key"].items():
                merged_key[pos] = val

        print(f"模型 {model} 合并后的 Round10 key:")
        print(" ".join(["??" if v is None else f"{v:02x}" for v in merged_key]))

        if MASTER_KEY_HEX:
            master = bytes.fromhex(MASTER_KEY_HEX)
            round10 = key_expansion_128(master)[10]
            ok_count = sum(1 for i, v in enumerate(merged_key) if v is not None and v == round10[i])
            print(f"已恢复正确字节数: {ok_count}/{sum(v is not None for v in merged_key)}")

        rows = []
        for res in results:
            for pos in res["active_positions"]:
                for rank, (k, score) in enumerate(res["details"][pos], start=1):
                    rows.append({
                        "mask": res["mask"],
                        "samples": res["samples"],
                        "byte_pos": pos,
                        "rank": rank,
                        "candidate": f"{k:02x}",
                        "score": score
                    })

        pd.DataFrame(rows).to_csv(
            RESULTS_DIR / f"round10_candidates_model_{model}.csv",
            index=False,
            encoding="utf-8-sig"
        )

        plt.figure(figsize=(8, 4))
        plt.bar([res["mask"] for res in results], [res["score"] for res in results])
        plt.xlabel("diff_byte_mask")
        plt.ylabel("Recovery score")
        plt.title(f"Model {model} Recovery Score")
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / f"mask_recovery_scores_{model}.png")
        plt.close()

        print(f"✅ 已保存 CSV 和图像 for 模型 {model}")

if __name__ == "__main__":
    process_all_models()