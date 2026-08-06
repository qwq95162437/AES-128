from pathlib import Path
from collections import Counter
import itertools

import pandas as pd
import matplotlib.pyplot as plt

from dfa_recover_god import INV_SBOX


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
CSV_FILES = [
    RESULTS_DIR / "dfa_model_A_attacker_good.csv",
    RESULTS_DIR / "dfa_model_B_attacker_good.csv",
    RESULTS_DIR / "dfa_model_C_attacker_good.csv",
    RESULTS_DIR / "dfa_model_D_attacker_good.csv",
]

MODEL_TYPES = {
    "A": "multi_bit_random",
    "B": "sparse_bit",
    "C": "spatial_shift",
    "D": "timing_jitter",
}

MASTER_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"

# Model A 参数
MODEL_A_NUM_GROUPS = 4            # 自动学出 4 个分组
MODEL_A_PER_BYTE_TOPK = 8         # 每个字节先保留前 8 个候选
MODEL_A_GROUP_TOPK = 10           # 组联合搜索后保留前 10 个组合候选


# =========================================================
# 样本加载
# =========================================================
def load_samples(csv_file):
    csv_file = Path(csv_file)
    if not csv_file.exists():
        raise FileNotFoundError(f"样本文件不存在: {csv_file.resolve()}")
    df = pd.read_csv(csv_file)
    return samples_from_dataframe(df)


def samples_from_dataframe(df):
    samples = []
    for _, row in df.iterrows():
        c = bytes.fromhex(row["correct_cipher"])      # 把 32 位 hex 字符串转成 16 字节 bytes
        f = bytes.fromhex(row["fault_cipher"])
        samples.append((c, f))                        # 形成样本列表
    return samples


# =========================================================
# AES key schedule 反推主密钥
# =========================================================
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def rot_word(w):
    return w[1:] + w[:1]


def sub_word(w):
    return [SBOX[x] for x in w]


# 把 AES-128 主密钥扩展成 11 轮轮密钥
def key_expansion_128(master_key_bytes):
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    key = list(master_key_bytes)
    words = [key[i:i + 4] for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i // 4 - 1]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    return [bytes(sum(words[r * 4:(r + 1) * 4], [])) for r in range(11)]


# 主密钥逆推程序
def inv_key_schedule_128_from_round10(round10_key_bytes):
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def xor_words(a, b):
        return [x ^ y for x, y in zip(a, b)]

    cur_words = [list(round10_key_bytes[i:i + 4]) for i in range(0, 16, 4)]

    for round_idx in range(10, 0, -1):
        prev = [None] * 4
        prev[3] = xor_words(cur_words[3], cur_words[2])
        prev[2] = xor_words(cur_words[2], cur_words[1])
        prev[1] = xor_words(cur_words[1], cur_words[0])
        g = sub_word(rot_word(prev[3]))
        g[0] ^= rcon[round_idx - 1]
        prev[0] = xor_words(cur_words[0], g)
        cur_words = prev

    return bytes(sum(cur_words, []))


# =========================================================
# Model A: 自动分组
# =========================================================
def diff_mask_from_pair(c, f):
    return tuple(1 if c[i] != f[i] else 0 for i in range(16))      # 得到一个 16 位的 0/1 mask


def active_positions_from_mask(mask):
    return [i for i, b in enumerate(mask) if b]


def hamming_overlap_score(mask_a, mask_b):
    inter = sum(1 for a, b in zip(mask_a, mask_b) if a and b)
    union = sum(1 for a, b in zip(mask_a, mask_b) if a or b)
    return inter - 0.2 * union


# 统计所有 diff mask 出现频次
# 取出现最多的前若干个 mask
# 选出彼此不过于相似的 4 个代表 mask
def learn_model_a_group_masks(samples, num_groups=4):
    mask_counter = Counter()

    for c, f in samples:
        mask = diff_mask_from_pair(c, f)
        if any(mask):
            mask_counter[mask] += 1

    ranked_masks = [m for m, _ in mask_counter.most_common(50)]

    chosen = []
    for m in ranked_masks:
        if not chosen:
            chosen.append(m)
            continue

        too_similar = False
        for cm in chosen:
            inter = sum(1 for a, b in zip(m, cm) if a and b)
            if inter >= max(sum(m), sum(cm)) - 1:
                too_similar = True
                break

        if not too_similar:
            chosen.append(m)

        if len(chosen) >= num_groups:
            break

    for m in ranked_masks:
        if len(chosen) >= num_groups:
            break
        if m not in chosen:
            chosen.append(m)

    return chosen


# 对每个样本计算它和每个组 mask 的重叠得分
def assign_sample_to_group(c, f, group_masks):
    mask = diff_mask_from_pair(c, f)
    if not any(mask):
        return None

    best_gid = None
    best_score = -10**9

    for gid, gmask in enumerate(group_masks):
        score = hamming_overlap_score(mask, gmask)
        if score > best_score:
            best_score = score
            best_gid = gid

    return best_gid


def split_model_a_samples_by_learned_groups(samples, num_groups=4):
    group_masks = learn_model_a_group_masks(samples, num_groups=num_groups)
    buckets = {gid: [] for gid in range(len(group_masks))}
    unknown = []

    for c, f in samples:
        gid = assign_sample_to_group(c, f, group_masks)
        if gid is None:
            unknown.append((c, f))
        else:
            buckets[gid].append((c, f))

    return group_masks, buckets, unknown

def exact_mask_samples(samples, group_mask):
    """
    只保留 diff mask 与 group_mask 完全相同的样本。
    """
    return [(c, f) for c, f in samples if diff_mask_from_pair(c, f) == group_mask]


def sample_has_exactly_four_diffs(c, f):
    return sum(1 for i in range(16) if c[i] != f[i]) == 4

# =========================================================
# Model A: GF(2^8) & MixColumns 结构判别
# =========================================================
def gf256_xtime(x):
    x <<= 1
    if x & 0x100:
        x ^= 0x11B
    return x & 0xFF


def gf256_mul(x, c):
    if c == 1:
        return x
    if c == 2:
        return gf256_xtime(x)
    if c == 3:
        return gf256_xtime(x) ^ x
    raise ValueError(f"unsupported constant: {c}")

VALID_MC_TUPLES_ANY_ORDER = None


def build_valid_mc_tuples_any_order():
    """
    预计算所有合法的 4 字节差分组合。
    这样匹配时，不需要每次都枚举 e 和 permutation。
    """
    base_patterns = [
        (2, 1, 1, 3),
        (3, 2, 1, 1),
        (1, 3, 2, 1),
        (1, 1, 3, 2),
    ]

    valid = set()
    for e in range(1, 256):
        for p in base_patterns:
            vals = (
                gf256_mul(e, p[0]),
                gf256_mul(e, p[1]),
                gf256_mul(e, p[2]),
                gf256_mul(e, p[3]),
            )
            for perm in set(itertools.permutations(vals)):
                valid.add(perm)
    return valid


# 检查某个 4 元组 deltas 是否属于上述合法集合
def match_mixcolumns_single_byte_pattern_any_order(deltas):
    global VALID_MC_TUPLES_ANY_ORDER
    if VALID_MC_TUPLES_ANY_ORDER is None:
        VALID_MC_TUPLES_ANY_ORDER = build_valid_mc_tuples_any_order()

    if (deltas[0] | deltas[1] | deltas[2] | deltas[3]) == 0:
        return False

    return tuple(deltas) in VALID_MC_TUPLES_ANY_ORDER

def match_mixcolumns_single_byte_pattern(deltas):
    """
    判断4-byte delta是否符合单字节故障经过 MixColumns 后的4种模式之一:
      [2e,1e,1e,3e]
      [3e,2e,1e,1e]
      [1e,3e,2e,1e]
      [1e,1e,3e,2e]
    """
    d0, d1, d2, d3 = deltas

    if (d0 | d1 | d2 | d3) == 0:
        return False

    patterns = [
        (2, 1, 1, 3),
        (3, 2, 1, 1),
        (1, 3, 2, 1),
        (1, 1, 3, 2),
    ]

    for p in patterns:
        # 找一个系数为1的位置，直接取它对应的delta作为 e
        for idx, coeff in enumerate(p):
            if coeff == 1:
                e = deltas[idx]
                if e == 0:
                    continue
                if (
                    d0 == gf256_mul(e, p[0]) and
                    d1 == gf256_mul(e, p[1]) and
                    d2 == gf256_mul(e, p[2]) and
                    d3 == gf256_mul(e, p[3])
                ):
                    return True

    return False

# =========================================================
# Model A: 单字节粗筛
# =========================================================
# 先用统计一致性，把 256 个候选缩成每字节前 8 个
def per_byte_candidate_scores(samples, byte_pos):
    scores = {}

    for k in range(256):
        delta_counter = Counter()
        valid_samples = 0

        for c, f in samples:
            if c[byte_pos] == f[byte_pos]:
                continue

            delta = INV_SBOX[c[byte_pos] ^ k] ^ INV_SBOX[f[byte_pos] ^ k]
            if delta == 0:
                continue

            delta_counter[delta] += 1
            valid_samples += 1

        if valid_samples == 0:
            scores[k] = float("-inf")
            continue
        # 最常见差分出现次数
        dominant_count = delta_counter.most_common(1)[0][1]
        # 分布是否集中
        concentration = sum(cnt * cnt for cnt in delta_counter.values()) / (valid_samples * valid_samples)
        # 最主要差分占比
        support_ratio = dominant_count / valid_samples
        # 差分太分散要扣分
        diversity_penalty = 0.03 * (len(delta_counter) - 1)

        score = (
            2.0 * dominant_count
            + 4.0 * concentration
            + 2.0 * support_ratio
            - diversity_penalty
        )
        scores[k] = score

    return scores


# =========================================================
# Model A: 组内联合评分
# =========================================================
def score_group_key_candidate(samples, positions, key_bytes):
    """
    更适合 bit级随机模型A 的组内评分：
    1. 只看恰好4字节差分的样本
    2. 4-byte delta 允许任意顺序匹配 MixColumns 单字节故障模式
    3. 以命中率为主，命中数为辅
    """
    hit_count = 0
    usable_count = 0

    for c, f in samples:
        # 只看恰好 4 字节差分的样本
        if not sample_has_exactly_four_diffs(c, f):
            continue

        deltas = []
        nz = 0

        for pos, kb in zip(positions, key_bytes):
            d = INV_SBOX[c[pos] ^ kb] ^ INV_SBOX[f[pos] ^ kb]
            deltas.append(d)
            if d != 0:
                nz += 1

        # 对模型A，这里要求这4个位置都给出有效差分
        if nz != 4:
            continue

        usable_count += 1
        if match_mixcolumns_single_byte_pattern_any_order(tuple(deltas)):
            hit_count += 1

    if usable_count == 0:
        return float("-inf")

    hit_ratio = hit_count / usable_count
    return 1000.0 * hit_ratio + hit_count

# =========================================================
# Model A 恢复
# =========================================================
# 对样本按故障输出模式自动聚类
# 每个组找出那 4 个最相关的输出字节
# 用精确 mask 样本优先，减少噪声
# 每个字节独立粗筛 top-8 候选
# 组内 4 字节联合搜索
# 把每组最佳组合写回 round10_key
# 对没覆盖到的位置退化为单字节粗筛
def recover_round10_multibit_modelA(samples, top_n=3):
    round10_key = [0] * 16
    round10_topn = [[0x00] for _ in range(16)]

    group_masks, buckets, unknown = split_model_a_samples_by_learned_groups(
        samples, num_groups=MODEL_A_NUM_GROUPS
    )

    print("[Model A] 自动学习到的分组 mask:")
    for gid, gmask in enumerate(group_masks):
        active = active_positions_from_mask(gmask)
        print(f"  group{gid}: active={active}  samples={len(buckets[gid])}")
    if unknown:
        print(f"  unknown: {len(unknown)}")

    assigned_positions = set()

    for gid, gmask in enumerate(group_masks):
        group_samples = buckets[gid]
        positions = active_positions_from_mask(gmask)

        if len(positions) != 4 or len(group_samples) == 0:
            continue

        # 优先使用“精确命中该mask”的样本，减少近邻mask噪声
        exact_samples = exact_mask_samples(group_samples, gmask)
        if len(exact_samples) >= max(12, len(group_samples) // 2):
            work_samples = exact_samples
        else:
            work_samples = group_samples

        # 对这4个位置分别做粗筛，筛选出top-8 候选
        candidate_lists = []
        for pos in positions:
            scores = per_byte_candidate_scores(work_samples, pos)
            ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            top_candidates = [k for k, _ in ranked[:MODEL_A_PER_BYTE_TOPK]]
            if not top_candidates:
                top_candidates = [0x00]
            candidate_lists.append(top_candidates)

        # 组内联合搜索
        group_candidates = []
        for key_bytes in itertools.product(*candidate_lists):
            score = score_group_key_candidate(work_samples, positions, key_bytes)
            group_candidates.append((key_bytes, score))

        group_candidates.sort(key=lambda x: x[1], reverse=True)
        best_candidates = group_candidates[:MODEL_A_GROUP_TOPK]

        if not best_candidates:
            continue
        # 把每组最佳组合写回 round10_key
        best_key = best_candidates[0][0]

        for idx, pos in enumerate(positions):
            round10_key[pos] = best_key[idx]
            assigned_positions.add(pos)

            byte_candidates = []
            seen = set()
            for key_bytes, _ in best_candidates:
                kb = key_bytes[idx]
                if kb not in seen:
                    seen.add(kb)
                    byte_candidates.append(kb)
                if len(byte_candidates) >= top_n:
                    break

            round10_topn[pos] = byte_candidates if byte_candidates else [best_key[idx]]

    # 对没覆盖到的位置退化为单字节粗筛
    for pos in range(16):
        if pos in assigned_positions:
            continue

        scores = per_byte_candidate_scores(samples, pos)
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_candidates = [k for k, _ in ranked[:top_n]]

        if top_candidates:
            round10_key[pos] = top_candidates[0]
            round10_topn[pos] = top_candidates
        else:
            round10_key[pos] = 0x00
            round10_topn[pos] = [0x00]

    return bytes(round10_key), round10_topn


# =========================================================
# B/C/D 恢复
# =========================================================
def recover_round10_generic(samples, top_n=3):
    key_candidates = [Counter() for _ in range(16)]

    for c, f in samples:
        for i in range(16):
            if c[i] == f[i]:
                continue
            for k in range(256):
                delta = INV_SBOX[c[i] ^ k] ^ INV_SBOX[f[i] ^ k]       # 最重要的公式
                if delta != 0:
                    key_candidates[i][k] += 1 / (1 + delta)           # 若 delta != 0，则给候选密钥 k 加分

    round10_key = []
    round10_topn = []

    for i in range(16):
        if key_candidates[i]:
            top_keys = [k for k, _ in key_candidates[i].most_common(top_n)]
            round10_key.append(top_keys[0])
            round10_topn.append(top_keys)
        else:
            round10_key.append(0x00)
            round10_topn.append([0x00])

    return bytes(round10_key), round10_topn


def recover_round10(samples, model_type, top_n=3):
    if model_type == "multi_bit_random":
        return recover_round10_multibit_modelA(samples, top_n)
    return recover_round10_generic(samples, top_n)


# =========================================================
# 主流程
# =========================================================
def main():
    master_key_bytes = bytes.fromhex(MASTER_KEY_HEX)             # 从 MASTER_KEY_HEX 得到真实主密钥
    round10_truth = key_expansion_128(master_key_bytes)[10]      # 用 key_expansion_128() 算出真实的 round10_truth

    summary = []

    for csv_file in CSV_FILES:
        model_name = csv_file.stem.split("_")[2].upper()
        model_type = MODEL_TYPES[model_name]

        # 读样本
        print(f"\n========== 模型 {model_name} ==========")
        samples = load_samples(csv_file)
        print("样本数:", len(samples))

        # 调 recover_round10(samples, model_type, top_n=3) 恢复第 10 轮轮密钥
        round10_key, round10_topn = recover_round10(samples, model_type, top_n=3)
        # 调 inv_key_schedule_128_from_round10() 反推主密钥
        recovered_master = inv_key_schedule_128_from_round10(round10_key)

        # 与 round10_truth 对比，统计恢复字节数和恢复率
        ok_count = sum(1 for i, b in enumerate(round10_key) if b == round10_truth[i])
        recovery_rate = ok_count / 16

        print("Round10 key:")
        print(" ".join(f"{b:02x}" for b in round10_key))
        print(f"恢复字节: {ok_count}/16  ({recovery_rate * 100:.1f}%)")
        print("Recovered master key :", recovered_master.hex())

        # 保存每个字节的 top 候选
        rows = []
        for i, topk in enumerate(round10_topn):
            rows.append({
                "byte_pos": i,
                "top_candidates": ",".join(f"{k:02x}" for k in topk)
            })

        pd.DataFrame(rows).to_csv(
            RESULTS_DIR / f"round10_top_candidates_model_{model_name}.csv",
            index=False
        )

        summary.append({
            "model": model_name,
            "recovery_rate": recovery_rate
        })

    df_summary = pd.DataFrame(summary)
    df_summary.to_csv(RESULTS_DIR / "models_compare.csv", index=False)

    plt.figure(figsize=(8, 5))

    # 画恢复率对比图，没意义全是100%
    bars = plt.bar(
        df_summary["model"],
        df_summary["recovery_rate"] * 100,
        color="white",
        edgecolor="black",
        linewidth=1.2
    )

    # 给柱子添加斜线纹理，黑白打印时更清楚
    for bar in bars:
        bar.set_hatch("//")

    # 在柱子上方标注数值
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            height + 1,
            f"{height:.1f}%",
            ha="center",
            va="bottom",
            fontsize=10
        )

    plt.rcParams["font.sans-serif"] = ["SimHei"]
    plt.rcParams["axes.unicode_minus"] = False
    plt.xlabel("故障模型")
    plt.ylabel("恢复率 / %")
    plt.title("四种故障模型下 Round10 key 恢复率对比")
    plt.ylim(0, 110)

    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "dfa_compare_bw.png", dpi=300)
    plt.close()

    print(f"\n✅ 已生成: {RESULTS_DIR / 'models_compare.csv'}")
    print(f"✅ 已生成: {RESULTS_DIR / 'dfa_compare.png'}")


if __name__ == "__main__":
    main()