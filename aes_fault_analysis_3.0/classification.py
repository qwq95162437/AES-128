from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_DIR / "fault_dataset.csv")


# =========================================================
# 基础工具
# =========================================================
def hamming_weight(hex_val):
    return bin(int(hex_val, 16)).count("1")


def byte_hw(x: int) -> int:
    return bin(x).count("1")


def derive_attacker_features(correct_hex: str, fault_hex: str):
    """
    只基于攻击者可见的 correct_cipher / fault_cipher 派生特征
    """
    # 把十六进制字符串转换成 16 字节数组
    c = bytes.fromhex(correct_hex)
    f = bytes.fromhex(fault_hex)

    diff_bytes = [a ^ b for a, b in zip(c, f)]
    # 重新拼成十六进制字符串，方便保存到 CSV
    diff_hex = "".join(f"{x:02x}" for x in diff_bytes)

    diff_positions = [i for i, x in enumerate(diff_bytes) if x != 0]
    diff_nonzero_count = len(diff_positions)
    first_diff_byte = diff_positions[0] if diff_positions else -1
    diff_hw_sum = sum(byte_hw(x) for x in diff_bytes)

    # 攻击者分组标签：直接用非零差分位置
    # 例如 "1_4_11_14"
    group_tag = "_".join(str(i) for i in diff_positions) if diff_positions else "none"

    return {
        "diff": diff_hex,
        "diff_nonzero_count": diff_nonzero_count,
        "diff_positions": ",".join(str(i) for i in diff_positions),
        "first_diff_byte": first_diff_byte,
        "diff_hw_sum": diff_hw_sum,
        "group_tag": group_tag,
    }


# =========================================================
# God 侧辅助字段
# =========================================================
df["hw"] = df["fault_val"].apply(hamming_weight)
df["offset"] = abs(df["req_inject_byte_pos"] - df["actual_inject_byte_pos"])

# 上帝视角：只保留理论可用样本
df_valid = df[(df["dfa_valid"] == 1) & (df["diff_nonzero_count"] > 0)].copy()

# 攻击者原始可见字段
attacker_fields = [
    "model_sel",
    "sample_id",
    "plaintext",
    "correct_cipher",
    "fault_cipher",
]

# 模型映射
model_mapping = {0: "A", 1: "B", 2: "C", 3: "D"}


# =========================================================
# 主处理
# =========================================================
for sel, model_name in model_mapping.items():
    df_model = df_valid[df_valid["model_sel"] == sel].copy()

    # -------------------------
    # God 视角：保留你原来的筛选
    # -------------------------
    if model_name == "A":
        df_god = df_model[(df_model["hw"] >= 2) & (df_model["offset"] == 0)].copy()
    elif model_name == "B":
        df_god = df_model[(df_model["hw"] <= 2) & (df_model["offset"] == 0)].copy()
    elif model_name == "C":
        df_god = df_model[(df_model["hw"] >= 1) & (df_model["offset"] <= 2)].copy()
    elif model_name == "D":
        df_god = df_model[(df_model["hw"] >= 1)].copy()
    else:
        df_god = df_model.copy()

    god_path = RESULTS_DIR / f"dfa_model_{model_name}_god.csv"
    df_god.to_csv(god_path, index=False)

    # -------------------------
    # Attacker 视角：只用可见信息做派生和筛选
    # -------------------------
    df_attacker = df_model[attacker_fields].copy()

    attacker_extra = []
    for _, row in df_attacker.iterrows():
        attacker_extra.append(
            derive_attacker_features(
                row["correct_cipher"],
                row["fault_cipher"]
            )
        )

    df_extra = pd.DataFrame(attacker_extra)
    df_attacker = pd.concat([df_attacker.reset_index(drop=True), df_extra], axis=1)

    # -------------------------
    # 攻击者侧筛选规则（启发式）
    # -------------------------
    if model_name == "A":
        # A: 先只保留 4-byte 差分，再去掉 fault 太重的样本
        # 这个最重要，适合你现在的恢复器
        df_attacker["is_good_candidate"] = (
             df_attacker["diff_nonzero_count"] == 4
        )

    elif model_name == "B":
        # B: 稀疏 bit 模型，优先总差分 HW 较小
        df_attacker["is_good_candidate"] = (
             df_attacker["diff_nonzero_count"] >= 1
        )


    elif model_name == "C":
        # C: 有空间偏移，保留 4-byte 差分，但放宽总 HW
        df_attacker["is_good_candidate"] = (
             df_attacker["diff_nonzero_count"] > 0

        )

    elif model_name == "D":
        # D: 混合模型，不筛太狠
        df_attacker["is_good_candidate"] = (
            (df_attacker["diff_nonzero_count"] >= 1)
        )

    else:
        df_attacker["is_good_candidate"] = True

    # 保存完整 attacker CSV
    attacker_path = RESULTS_DIR / f"dfa_model_{model_name}_attacker.csv"
    df_attacker.to_csv(attacker_path, index=False)

    # 保存筛选后的 attacker CSV
    attacker_good_path = RESULTS_DIR / f"dfa_model_{model_name}_attacker_good.csv"
    df_attacker[df_attacker["is_good_candidate"]].to_csv(attacker_good_path, index=False)

    print(f"模型 {model_name} 样本数量:")
    print(f"  上帝视角: {len(df_god)}")
    print(f"  攻击者视角(全量): {len(df_attacker)}")
    print(f"  攻击者视角(筛选后): {df_attacker['is_good_candidate'].sum()}")
    print(f"  已保存: {god_path}")
    print(f"  已保存: {attacker_path}")
    print(f"  已保存: {attacker_good_path}")
    print(f"  group_tag统计: {df_attacker['group_tag'].value_counts().to_dict()}")
    print("-" * 60)