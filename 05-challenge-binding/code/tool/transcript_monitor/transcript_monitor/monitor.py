#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
transcript monitor v2：语言无关的 challenge-binding 检查

v1 → v2 的两处修正（都是跑真实系统时发现的）
------------------------------------------------
1. Required 必须排除 Post(c)：依赖 challenge c 的响应值，本来就只能在 c 之后确定。
2. Dep 必须是传递的，且 check 必须显式声明「它属于哪个 challenge」：
   reset + 链式重吸收的写法（snarkjs Plonk）会让「所有含 c 的方程」这种朴素归属产生大量误报。

事件格式
--------
("init",    domain, [])
("reset",   "",     [])            # 清空 transcript（snarkjs 的 transcript.reset()）
("absorb",  label,  [vars])
("squeeze", label,  [])
("check",   challenge, [vars])     # 该方程由 challenge 负责随机化
"""

from dataclasses import dataclass, field


@dataclass
class Spec:
    name: str
    events: list
    pc: set
    post: dict = field(default_factory=dict)
    has_domain: bool = True
    # 约束层绑定的值：不进入 transcript，但在约束里被校验（如 Plonky3 的 public values）
    constraint_bound: set = field(default_factory=set)
    challenges: set = field(default_factory=set)

    def __post_init__(self):
        self.challenges = {e[1] for e in self.events if e[0] == "squeeze"}


def analyze(spec: Spec) -> list:
    violations = []
    if not spec.has_domain:
        violations.append(("B3-no-domain", "-", set()))

    dep = {}
    absorbed = set()
    for kind, label, args in spec.events:
        if kind == "reset":
            absorbed = set()
        elif kind == "absorb":
            absorbed |= set(args)
        elif kind == "squeeze":
            dep[label] = set(absorbed)

    required = {c: set() for c in spec.challenges}
    for kind, label, args in spec.events:
        if kind != "check":
            continue
        c = label
        required[c] |= (set(args) & spec.pc) - spec.post.get(c, set()) - {c}

    # 传递闭包：若 Dep(c) 里出现了另一个 challenge c'，则 c 也依赖 Dep(c')
    changed = True
    while changed:
        changed = False
        for c in dep:
            extra = set()
            for v in dep[c]:
                if v in dep:
                    extra |= dep[v]
            if not extra <= dep[c]:
                dep[c] |= extra
                changed = True

    for c in spec.challenges:
        missing = required[c] - dep[c] - spec.constraint_bound
        if missing:
            violations.append(("B1-coverage", c, missing))
    return violations


def fmt(violations) -> str:
    if not violations:
        return "  OK"
    out = []
    for kind, ch, missing in violations:
        if kind == "B1-coverage":
            out.append(f"  VIOLATION {kind}: '{ch}' 未绑定 {sorted(missing)}")
        else:
            out.append(f"  WEAKNESS {kind}")
    return "\n".join(out)


# ---------------- 示例 case ----------------

def weak_schnorr():
    return Spec(
        name="weak-schnorr",
        events=[
            ("init", "schnorr-v1", []),
            ("absorb", "a", ["a"]),
            ("squeeze", "c", []),
            ("absorb", "z", ["z"]),
            ("check", "c", ["x", "a", "z"]),
        ],
        pc={"x", "a", "z"},
        post={"c": {"z"}},
    )


def strong_schnorr():
    return Spec(
        name="strong-schnorr",
        events=[
            ("init", "schnorr-v1", []),
            ("absorb", "x", ["x"]),
            ("absorb", "a", ["a"]),
            ("squeeze", "c", []),
            ("absorb", "z", ["z"]),
            ("check", "c", ["x", "a", "z"]),
        ],
        pc={"x", "a", "z"},
        post={"c": {"z"}},
    )


def _phantom(bind_c0):
    ev = [
        ("init", "or-proof-v1", []),
        ("absorb", "stmt", ["x0", "x1"]),
        ("absorb", "a", ["a0", "a1"]),
        ("squeeze", "c", []),
    ]
    if bind_c0:
        ev.append(("absorb", "c0", ["c0"]))
    ev += [
        ("absorb", "z", ["z0", "z1"]),
        ("squeeze", "w", []),
        ("check", "c", ["x0", "a0", "z0"]),
        ("check", "w", ["c0", "z0"]),
    ]
    return Spec(
        name="phantom-fixed" if bind_c0 else "phantom-buggy",
        events=ev,
        pc={"x0", "x1", "a0", "a1", "c0", "z0", "z1"},
        post={"c": {"z0", "z1"}, "w": set()},
    )


def snarkjs_plonk():
    """按 src/plonk_verify.js 的 calculatechallenges 转写。

    注意：每轮都 transcript.reset()，且从不吸收域标识。
    """
    ev = [
        ("absorb", "vk", ["Qm", "Ql", "Qr", "Qo", "Qc", "S1", "S2", "S3"]),
        ("absorb", "pub", ["pub"]),
        ("absorb", "abc", ["A", "B", "C"]),
        ("squeeze", "beta", []),
        ("check", "beta", ["pub", "A", "B", "C"]),

        ("reset", "", []),
        ("absorb", "beta", ["beta"]),
        ("squeeze", "gamma", []),

        ("reset", "", []),
        ("absorb", "beta_gamma_Z", ["beta", "gamma", "Z"]),
        ("squeeze", "alpha", []),
        ("check", "alpha", ["Z"]),

        ("reset", "", []),
        ("absorb", "alpha_T", ["alpha", "T1", "T2", "T3"]),
        ("squeeze", "xi", []),

        ("reset", "", []),
        ("absorb", "xi_evals", ["xi", "eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw"]),
        ("squeeze", "v", []),

        ("reset", "", []),
        ("absorb", "W", ["Wxi", "Wxiw"]),
        ("squeeze", "u", []),                 # u 不吸收 v / xi —— 见审计笔记
    ]
    return Spec(
        name="snarkjs-plonk",
        events=ev,
        pc={"pub", "A", "B", "C", "Z", "T1", "T2", "T3",
            "eval_a", "eval_b", "eval_c", "eval_s1", "eval_s2", "eval_zw",
            "Wxi", "Wxiw"},
        post={"beta": set()},
        has_domain=False,
    )


def fastcrypto_kcp():
    """FastCrypto KeyConsistencyProof::verify 的调度（复现 zkSecurity 2026-09 的 Batched FS 案例）。

    c        = H(G,H,spk,recipients,ciphertexts,a1,a2,a3)      —— 不含 z1,z2
    mu/rho/alpha/beta = H(label, c)                            —— 只依赖 c
    但最终 MSM 方程用到了 z1,z2。
    """
    ev = [
        ("reset", "", []),
        ("absorb", "stmt", ["spk", "recipients", "cts"]),
        ("absorb", "a", ["a1", "a2", "a3"]),
        ("squeeze", "c", []),
        ("absorb", "c", ["c"]),
        ("squeeze", "mu", []),
        ("squeeze", "rho", []),
        ("squeeze", "alpha", []),
        ("squeeze", "beta", []),
        ("check", "mu", ["z1", "a1", "cts", "c"]),
        ("check", "rho", ["z1", "z2", "a2", "cts", "c"]),
        ("check", "beta", ["z2", "a3", "spk", "c"]),
    ]
    return Spec(
        name="fastcrypto-kcp",
        events=ev,
        pc={"spk", "recipients", "cts", "a1", "a2", "a3", "z1", "z2"},
        post={"c": {"z1", "z2"}},
        has_domain=False,
    )


def circl_qndleq(vulnerable: bool):
    """CIRCL zk/qndleq 的 Lossy FS（修复前）。

    旧版 doChallenge 用 g.FillBytes(nBytes) —— FillBytes 编码的是绝对值，
    因此 g 与 -g 产生相同字节，challenge 无法区分符号。
    修复（commit 19848a5）增加了 checkBounds: 0 < x < N。

    建模方式：把被吸收的值记作 abs(g)，验证方程用 g；二者不同即 B1 违规。
    """
    absorbed = "abs_g" if vulnerable else "g"
    ev = [
        ("init", "qndleq-v1", []),
        ("absorb", "stmt", [absorbed, "gx", "h", "hx", "gP", "hP"]),
        ("squeeze", "c", []),
        ("check", "c", ["g", "gx", "h", "hx", "gP", "hP", "z"]),
    ]
    return Spec(
        name="circl-qndleq-vuln" if vulnerable else "circl-qndleq-fixed",
        events=ev,
        pc={"g", "gx", "h", "hx", "gP", "hP", "z", "abs_g"},
        post={"c": {"z"}},
        has_domain=True,
    )


def signal_zkcredential(vulnerable: bool):
    """Signal libsignal zkcredential/presentation.rs 的 Ambiguous FS。

    脆弱版本只把「第二个属性承诺与密文点之差」C_y2 - E_A2 吸收进 transcript，
    没有单独吸收 C_y2 与 E_A2；二者可以同时平移 a*G_y2 而保持该差值不变。
    修复：分别吸收 C_y2 与 E_A2。
    """
    if vulnerable:
        absorbed = ["C_y2_minus_EA2"]
        name = "signal-zkcred-vuln"
    else:
        absorbed = ["C_y2", "EA2"]
        name = "signal-zkcred-fixed"

    ev = [
        ("init", "Signal_ZKCredential_Presentation_20230410", []),
        ("absorb", "label", ["label"]),
        ("absorb", "commitments", ["C_x0", "C_x1", "C_V", "C_y0", "C_y1"] + absorbed),
        ("squeeze", "z", []),
        ("check", "z", ["C_x0", "C_x1", "C_V", "C_y0", "C_y1", "C_y2", "EA2"]),
    ]
    return Spec(
        name=name,
        events=ev,
        pc={"C_x0", "C_x1", "C_V", "C_y0", "C_y1", "C_y2", "EA2", "C_y2_minus_EA2"},
        has_domain=True,
    )


def halo2_vk(vulnerable: bool):
    """Halo2 issue #171：verification key 未进入 transcript（Circuit-substitution FS）。

    原始 issue 原文："You need to feed the verification key (or a binding commitment
    to it) into the transcript at the beginning... If you don't, then challenges only
    depend on the prover's messages."

    修复后：开头吸收 vk 的绑定摘要——在规格里记作 vk（摘要即代表 vk）。
    """
    ev = [
        ("init", "halo2-plonk", []),
        ("absorb", "a", ["a"]),
        ("squeeze", "c", []),
        ("check", "c", ["vk", "a"]),
    ]
    if not vulnerable:
        ev.insert(1, ("absorb", "vk", ["vk"]))
    return Spec(
        name="halo2-vk-missing" if vulnerable else "halo2-vk-bound",
        events=ev,
        pc={"vk", "a"},
        has_domain=True,
    )


def plonky3(constraint_bound: bool):
    """Plonky3 uni-stark：public values 不进入 transcript，而是靠 AIR 约束绑定。

    源码："Public inputs reach this proof only through AIR constraints."
    constraint_bound=True 时应判定通过；False 时才是真违规。
    """
    ev = [
        ("init", "uni-stark", []),
        ("absorb", "trace", ["trace_commit", "preprocessed_commit"]),
        ("squeeze", "zeta", []),
        ("check", "zeta", ["trace_commit", "preprocessed_commit", "public_values"]),
    ]
    return Spec(
        name="plonky3-constraint-bound" if constraint_bound else "plonky3-unbound",
        events=ev,
        pc={"trace_commit", "preprocessed_commit", "public_values"},
        constraint_bound={"public_values"} if constraint_bound else set(),
        has_domain=True,
    )


def marlin():
    """arkworks Marlin 验证器（`src/lib.rs` 的 `verify`）。

    初始化吸收协议名、index_vk、public_input；随后每轮吸收承诺与消息再抽取
    challenge；最后吸收 evaluations 再抽 opening challenge。
    """
    return Spec(
        name="marlin",
        events=[
            ("init", "marlin", []),
            ("absorb", "init", ["PROTOCOL_NAME", "index_vk", "public_input"]),
            ("absorb", "round1", ["first_comms", "msg0"]),
            ("squeeze", "alpha", []),
            ("absorb", "round2", ["second_comms", "msg1"]),
            ("squeeze", "beta", []),
            ("absorb", "round3", ["third_comms", "msg2"]),
            ("squeeze", "gamma", []),
            ("absorb", "evals", ["evaluations"]),
            ("squeeze", "v", []),
            ("check", "alpha", ["first_comms", "msg0"]),
            ("check", "beta", ["second_comms", "msg1"]),
            ("check", "gamma", ["third_comms", "msg2"]),
            ("check", "v", ["evaluations"]),
        ],
        pc={"first_comms", "msg0", "second_comms", "msg1",
            "third_comms", "msg2", "evaluations"},
        post={},
        has_domain=True,
    )


def barretenberg_oink():
    """Aztec Barretenberg UltraHonk 的 Oink 验证器。

    顺序由协议强制：`w_4 = f(eta, w_1..w_3)` 与 `inverses = g(beta, gamma, wires)`
    都必须先拿到 challenge 才能算，故它们属于 `Post(eta)` 与 `Post(beta/gamma)`。
    `alpha` 在 Oink 全部消息之后才抽样。

    这个案例同时是一堂归因课：把 `w_4` 归给 `eta` 的方程而不放进 `Post(eta)`，
    会误报三处违规；正确归因后判定为通过。
    """
    return Spec(
        name="barretenberg-oink",
        events=[
            ("init", "bb", []),
            ("absorb", "vk_pub", ["vk_hash", "public_inputs"]),
            ("absorb", "masking", ["masking_poly_comm"]),
            ("absorb", "wires", ["w_l", "w_r", "w_o"]),
            ("squeeze", "eta", []),
            ("squeeze", "rom_logup_gamma", []),
            ("absorb", "lookup_comms", ["read_counts", "read_tags", "w_4"]),
            ("squeeze", "beta", []),
            ("squeeze", "gamma", []),
            ("absorb", "logderiv", ["lookup_inverses"]),
            ("absorb", "zperm", ["z_perm"]),
            ("squeeze", "alpha", []),
            ("check", "eta", ["w_l", "w_r", "w_o", "w_4"]),
            ("check", "beta", ["read_counts", "read_tags", "w_l", "w_r", "w_o", "lookup_inverses"]),
            ("check", "gamma", ["read_counts", "read_tags", "w_l", "w_r", "w_o", "lookup_inverses"]),
            ("check", "alpha", ["w_l", "w_r", "w_o", "w_4", "z_perm", "lookup_inverses"]),
        ],
        pc={"masking_poly_comm", "w_l", "w_r", "w_o", "read_counts",
            "read_tags", "w_4", "lookup_inverses", "z_perm"},
        post={"eta": {"w_4"}, "beta": {"lookup_inverses"}, "gamma": {"lookup_inverses"}},
        has_domain=True,
    )


def winterfell():
    """Winterfell STARK 验证器（`verifier/src/lib.rs`）。

    seed = proof.context + pub_inputs；随后每读入一个承诺就 reseed 并抽取
    对应的一组随机系数（主 trace、辅助 trace、约束组合），再做 DEEP 与 FRI。
    """
    return Spec(
        name="winterfell",
        events=[
            ("init", "winterfell", []),
            ("absorb", "seed", ["context", "pub_inputs"]),
            ("absorb", "main", ["main_trace_commitment"]),
            ("squeeze", "alpha", []),
            ("absorb", "aux", ["aux_trace_commitment"]),
            ("squeeze", "beta", []),
            ("absorb", "constr", ["constraint_commitment"]),
            ("squeeze", "z", []),
            ("absorb", "deep", ["deep_evaluations"]),
            ("squeeze", "fri", []),
            ("check", "alpha", ["main_trace_commitment"]),
            ("check", "beta", ["main_trace_commitment", "aux_trace_commitment"]),
            ("check", "z", ["constraint_commitment"]),
            ("check", "fri", ["deep_evaluations"]),
        ],
        pc={"main_trace_commitment", "aux_trace_commitment",
            "constraint_commitment", "deep_evaluations"},
        post={},
        has_domain=True,
    )


def gnark_std():
    """gnark 的电路内验证器（`std/recursion/plonk/verifier.go`）。

    与 backend 同构：`bindPublicData(fs, "gamma", vk, witness)` 把 vk 与公开输入
    绑到 gamma 之前。
    """
    return Spec(
        name="gnark-std",
        events=[
            ("init", "", []),
            ("absorb", "vk", ["S0", "S1", "S2", "Ql", "Qr", "Qm", "Qo", "Qk", "Qcp"]),
            ("absorb", "pub", ["public"]),
            ("absorb", "lro", ["LRO0", "LRO1", "LRO2"]),
            ("squeeze", "gamma", []),
            ("check", "gamma", ["vk", "pub", "LRO0", "LRO1", "LRO2"]),
            ("squeeze", "beta", []),
            ("absorb", "zbsb", ["Bsb22", "Z"]),
            ("squeeze", "alpha", []),
            ("check", "alpha", ["Bsb22", "Z"]),
            ("absorb", "h", ["H0", "H1", "H2"]),
            ("squeeze", "zeta", []),
            ("check", "zeta", ["H0", "H1", "H2"]),
        ],
        pc={"S0", "S1", "S2", "Ql", "Qr", "Qm", "Qo", "Qk", "Qcp", "public",
            "LRO0", "LRO1", "LRO2", "Bsb22", "Z", "H0", "H1", "H2"},
        has_domain=False,
    )


def halo2():
    """zcash Halo2 的 Plonk 验证器（`halo2_proofs/src/plonk/verifier.rs`）。

    先把 vk 摘要、实例承诺、advice 承诺吸入，抽 theta；再吸入 lookup 置换承诺，
    抽 beta、gamma；然后是置换/查询乘积承诺、h 承诺，抽 y；随机多项式承诺后抽 x。
    """
    return Spec(
        name="halo2",
        events=[
            ("init", "halo2", []),
            ("absorb", "vk", ["vk"]),
            ("absorb", "instances", ["instance_comms"]),
            ("absorb", "advice", ["advice_comms"]),
            ("squeeze", "theta", []),
            ("absorb", "lookup_perm", ["lookup_perm_comms"]),
            ("squeeze", "beta", []),
            ("squeeze", "gamma", []),
            ("absorb", "perm_products", ["perm_comms"]),
            ("absorb", "lookup_products", ["lookup_product_comms"]),
            ("absorb", "vanishing_before", ["h_comms"]),
            ("squeeze", "y", []),
            ("absorb", "vanishing_after", ["random_comms"]),
            ("squeeze", "x", []),
            ("check", "theta", ["advice_comms"]),
            ("check", "beta", ["perm_comms"]),
            ("check", "gamma", ["perm_comms"]),
            ("check", "y", ["h_comms"]),
            ("check", "x", ["random_comms"]),
        ],
        pc={"advice_comms", "lookup_perm_comms", "perm_comms",
            "lookup_product_comms", "h_comms", "random_comms"},
        # 乘积承诺由 beta/gamma 派生；随机多项式承诺由 y 派生。
        post={"theta": {"lookup_perm_comms"},
              "beta": {"perm_comms", "lookup_product_comms"},
              "gamma": {"perm_comms", "lookup_product_comms"},
              "y": {"random_comms"}},
        has_domain=True,
    )


def dusk_plonk():
    """dusk-network/plonk 的验证器（`proof_system/proof.rs`）。

    先吸入四条 wire 承诺，抽 beta（并回吸）、gamma；再吸 z、抽 alpha；
    吸商多项式四段，抽 zeta。
    """
    return Spec(
        name="dusk-plonk",
        events=[
            ("init", "dusk", []),
            ("absorb", "wires", ["a_comm", "b_comm", "c_comm", "d_comm"]),
            ("squeeze", "beta", []),
            ("absorb", "beta", ["beta"]),
            ("squeeze", "gamma", []),
            ("absorb", "z", ["z_comm"]),
            ("squeeze", "alpha", []),
            ("absorb", "t", ["t_low", "t_mid", "t_high", "t_fourth"]),
            ("squeeze", "zeta", []),
            ("check", "beta", ["a_comm", "b_comm", "c_comm", "d_comm"]),
            ("check", "gamma", ["a_comm", "b_comm", "c_comm", "d_comm"]),
            ("check", "alpha", ["z_comm"]),
            ("check", "zeta", ["t_low", "t_mid", "t_high", "t_fourth"]),
        ],
        pc={"a_comm", "b_comm", "c_comm", "d_comm", "z_comm",
            "t_low", "t_mid", "t_high", "t_fourth"},
        post={},
        has_domain=True,
    )


def jellyfish_plonk():
    """Espresso jellyfish 的 PLONK 验证器（`plonk/src/proof_system/verifier.rs`）。

    序列：域标签 + vk/pub → witness 承诺 → tau → h 承诺 → beta,gamma →
    perm/plookup 承诺 → alpha → 商多项式承诺 → zeta → 求值 → v →
    打开证明 → u。派生值（h/perm/quot/evals/openings）分别属于对应 challenge 的 Post。
    """
    return Spec(
        name="jellyfish-plonk",
        events=[
            ("init", "jellyfish", []),
            ("absorb", "vk_pi", ["vk", "public_input"]),
            ("absorb", "wires", ["wires_poly_comms"]),
            ("squeeze", "tau", []),
            ("absorb", "h", ["h_poly_comms"]),
            ("squeeze", "beta", []),
            ("squeeze", "gamma", []),
            ("absorb", "perm", ["perm_poly_comms", "plookup_poly_comms"]),
            ("squeeze", "alpha", []),
            ("absorb", "quot", ["quot_poly_comms"]),
            ("squeeze", "zeta", []),
            ("absorb", "evals", ["poly_evals", "plookup_evals"]),
            ("squeeze", "v", []),
            ("absorb", "openings", ["opening_proof", "shifted_opening_proof"]),
            ("squeeze", "u", []),
            ("check", "tau", ["h_poly_comms"]),
            ("check", "beta", ["perm_poly_comms"]),
            ("check", "gamma", ["perm_poly_comms"]),
            ("check", "alpha", ["quot_poly_comms"]),
            ("check", "zeta", ["poly_evals"]),
            ("check", "v", ["opening_proof"]),
            ("check", "u", ["opening_proof"]),
        ],
        pc={"wires_poly_comms", "h_poly_comms", "perm_poly_comms",
            "plookup_poly_comms", "quot_poly_comms", "poly_evals",
            "plookup_evals", "opening_proof", "shifted_opening_proof"},
        post={"tau": {"h_poly_comms"},
              "beta": {"perm_poly_comms", "plookup_poly_comms"},
              "gamma": {"perm_poly_comms", "plookup_poly_comms"},
              "alpha": {"quot_poly_comms"},
              "zeta": {"poly_evals", "plookup_evals"},
              "v": {"opening_proof", "shifted_opening_proof"}},
        has_domain=True,
    )


def cl_signatures():
    """Hyperledger AnonCreds 的 CL 签名证明验证器（`anoncreds-clsignatures-rs`）。

    与 sponge 式 transcript 不同，这里的 challenge 是一次列表哈希：

        c_hver = H( tau_list ‖ c_list ‖ nonce )

    tau_list 由各子证明的验证方程产出，c_list 是 prover 的承诺，nonce 由验证方提供。
    验证器重算 c_hver 并与证明中的 c_hash 比较。
    """
    return Spec(
        name="cl-signatures",
        events=[
            ("init", "anoncreds", []),
            ("absorb", "statement", ["credential_pub_keys", "sub_proof_requests"]),
            ("absorb", "commitments", ["c_list"]),
            ("absorb", "tau", ["tau_values"]),
            ("absorb", "nonce", ["nonce"]),
            ("squeeze", "c", []),
            ("check", "c", ["c_list", "tau_values", "nonce"]),
        ],
        pc={"c_list", "tau_values"},
        post={},
        has_domain=True,
    )


def kimchi():
    """Mina Kimchi 验证器（`kimchi/src/verifier.rs` 的 `oracles`）。

    先吸收 verifier index 摘要、此前挑战的承诺、公开输入承诺、witness 承诺，
    再由 Fq-sponge 抽取 joint_combiner、beta、gamma、alpha、zeta。
    """
    comms = ["prev_challenges", "public_comm", "witness_commitments"]
    return Spec(
        name="kimchi",
        events=[
            ("init", "kimchi", []),
            ("absorb", "index", ["verifier_index_digest"]),
            ("absorb", "prev", ["prev_challenges"]),
            ("absorb", "public", ["public_comm"]),
            ("absorb", "witness", ["witness_commitments"]),
            ("squeeze", "joint_combiner", []),
            ("squeeze", "beta", []),
            ("squeeze", "gamma", []),
            ("squeeze", "alpha", []),
            ("squeeze", "zeta", []),
            ("check", "joint_combiner", ["verifier_index_digest"] + comms),
            ("check", "beta", ["verifier_index_digest"] + comms),
            ("check", "gamma", ["verifier_index_digest"] + comms),
            ("check", "alpha", ["verifier_index_digest"] + comms),
            ("check", "zeta", ["verifier_index_digest"] + comms),
        ],
        pc=set(comms),
        post={},
        has_domain=True,
    )


def fastcrypto_kcp_fixed():
    """FastCrypto KCP 的修复版本：批处理系数在吸收响应之后才派生。

    上游修复是用新的验证者随机数派生系数；这里把它建模为"系数依赖 z"，
    因为二者的安全性质相同——prover 无法在选定 z 之前知道系数。
    """
    return Spec(
        name="fastcrypto-kcp-fixed",
        events=[
            ("absorb", "stmt", ["spk", "recipients", "cts"]),
            ("absorb", "a", ["a1", "a2", "a3"]),
            ("squeeze", "c", []),
            ("absorb", "c", ["c"]),
            ("absorb", "z", ["z1", "z2"]),
            ("squeeze", "mu", []),
            ("squeeze", "rho", []),
            ("squeeze", "alpha", []),
            ("squeeze", "beta", []),
            ("check", "mu", ["z1", "a1", "cts", "c"]),
            ("check", "rho", ["z1", "z2", "a2", "cts", "c"]),
            ("check", "beta", ["z2", "a3", "spk", "c"]),
        ],
        pc={"spk", "recipients", "cts", "a1", "a2", "a3", "z1", "z2"},
        post={"c": {"z1", "z2"}},
        has_domain=False,
    )


def bulletproofs():
    """dalek Bulletproofs 的范围证明验证转录（外层，不含 IPP 轮）。"""
    return Spec(
        name="bulletproofs",
        events=[
            ("init", "rangeproof", []),
            ("absorb", "V", ["V"]),
            ("absorb", "AS", ["A", "S"]),
            ("squeeze", "y", []),
            ("squeeze", "z", []),
            ("absorb", "T", ["T1", "T2"]),
            ("squeeze", "x", []),
            ("absorb", "t", ["t_x", "t_x_blinding", "e_blinding"]),
            ("squeeze", "w", []),
            ("check", "x", ["T1", "T2"]),
            ("check", "w", ["t_x", "t_x_blinding", "e_blinding"]),
        ],
        pc={"V", "A", "S", "T1", "T2", "t_x", "t_x_blinding", "e_blinding"},
        post={"x": {"t_x", "t_x_blinding", "e_blinding"}},
    )


def gnark_backend():
    """gnark backend Plonk 验证器的转录（bls12-381/verify.go）。"""
    return Spec(
        name="gnark-backend",
        events=[
            ("init", "", []),
            ("absorb", "vk", ["S0", "S1", "S2", "Ql", "Qr", "Qm", "Qo", "Qk", "Qcp"]),
            ("absorb", "pub", ["public"]),
            ("absorb", "lro", ["LRO0", "LRO1", "LRO2"]),
            ("squeeze", "gamma", []),
            ("check", "gamma", ["vk", "pub", "LRO0", "LRO1", "LRO2"]),
            ("squeeze", "beta", []),
            ("absorb", "zbsb", ["Bsb22", "Z"]),
            ("squeeze", "alpha", []),
            ("check", "alpha", ["Bsb22", "Z"]),
            ("absorb", "h", ["H0", "H1", "H2"]),
            ("squeeze", "zeta", []),
            ("check", "zeta", ["H0", "H1", "H2"]),
        ],
        pc={"S0", "S1", "S2", "Ql", "Qr", "Qm", "Qo", "Qk", "Qcp", "public",
            "LRO0", "LRO1", "LRO2", "Bsb22", "Z", "H0", "H1", "H2"},
        has_domain=False,
    )


def main():
    for s in [weak_schnorr(), strong_schnorr(), _phantom(False), _phantom(True),
              snarkjs_plonk(), fastcrypto_kcp(), fastcrypto_kcp_fixed(),
              circl_qndleq(True), circl_qndleq(False),
              signal_zkcredential(True), signal_zkcredential(False),
              marlin(), barretenberg_oink(), winterfell(), kimchi(), gnark_std(), halo2(), dusk_plonk(), jellyfish_plonk(), cl_signatures(),
              halo2_vk(True), halo2_vk(False),
              plonky3(True), plonky3(False), bulletproofs(), gnark_backend()]:
        print(f"[{s.name}]")
        print(fmt(analyze(s)))
        print()


if __name__ == "__main__":
    main()




