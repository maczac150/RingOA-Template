#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Decision Trees on:
  wine, breast, digits, spambase, diabetes, BOSTON, MNIST
and export separate uint64 databases for each field:
  threshold, left, right, feature_val, label.

feature_val is rebuilt per input x using the exported feature_id array.
"""

from __future__ import annotations

import argparse
import math
import os
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

import numpy as np

from sklearn.datasets import load_wine, load_breast_cancer, load_digits, load_diabetes, fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor


# -----------------------------
# Helpers: dataset loading
# -----------------------------
def load_dataset(name: str) -> Tuple[np.ndarray, np.ndarray, str]:
    """
    Returns (X, y, task_type) where task_type in {"clf", "reg"}.
    """
    name_l = name.lower()
    if name_l == "wine":
        d = load_wine()
        return d.data.astype(np.float64), d.target.astype(np.int64), "clf"
    if name_l in ("breast", "breast_cancer", "cancer"):
        d = load_breast_cancer()
        return d.data.astype(np.float64), d.target.astype(np.int64), "clf"
    if name_l == "digits":
        d = load_digits()
        return d.data.astype(np.float64), d.target.astype(np.int64), "clf"
    if name_l == "diabetes":
        # sklearn's diabetes is regression
        d = load_diabetes()
        return d.data.astype(np.float64), d.target.astype(np.float64), "reg"
    if name_l == "spambase":
        # OpenML dataset
        d = fetch_openml(name="spambase", version=1, as_frame=False)
        X = d.data.astype(np.float64)
        y = d.target
        # target can be strings; convert to int
        if y.dtype.kind in ("U", "S", "O"):
            y = y.astype(np.int64)
        else:
            y = y.astype(np.int64)
        return X, y, "clf"
    if name_l in ("boston", "bostonhousing", "boston_housing", "boston house prices"):
        # Boston is removed from sklearn.datasets; use OpenML
        d = fetch_openml(name="boston", version=1, as_frame=False)
        X = d.data.astype(np.float64)
        y = d.target.astype(np.float64)
        return X, y, "reg"
    if name_l in ("mnist", "mnist_784"):
        d = fetch_openml(name="mnist_784", version=1, as_frame=False)
        X = d.data.astype(np.float64)
        y = d.target
        if y.dtype.kind in ("U", "S", "O"):
            y = y.astype(np.int64)
        else:
            y = y.astype(np.int64)
        return X, y, "clf"
    raise ValueError(f"Unknown dataset name: {name}")


# -----------------------------
# Quantization (float -> uint)
# -----------------------------
@dataclass
class QuantParams:
    # per-feature
    shift: np.ndarray   # added before scaling (>=0)
    scale: np.ndarray   # multiply after shifting
    bits: int           # qbits for feature/threshold
    # label quant (regression)
    y_shift: float = 0.0
    y_scale: float = 1.0
    y_bits: int = 0     # bits needed for labels


def make_feature_quant_params(X: np.ndarray, qbits: int) -> QuantParams:
    # shift x by -min so it becomes non-negative, then scale to [0, 2^qbits-1]
    x_min = np.min(X, axis=0)
    x_max = np.max(X, axis=0)
    span = np.maximum(x_max - x_min, 1e-12)

    shift = -x_min  # so x+shift >= 0
    max_int = (1 << qbits) - 1
    scale = max_int / span
    return QuantParams(shift=shift, scale=scale, bits=qbits)


def quantize_features(X: np.ndarray, qp: QuantParams) -> np.ndarray:
    Z = (X + qp.shift) * qp.scale
    Z = np.clip(np.rint(Z), 0, (1 << qp.bits) - 1)
    return Z.astype(np.uint64)


def quantize_threshold(thr: float, qp: QuantParams) -> int:
    """
    Thresholds are learned on already-quantized features, so they are already in
    the same domain as feature_val (uint). Just round and clip to qbits.
    """
    z = int(np.clip(np.rint(thr), 0, (1 << qp.bits) - 1))
    return z


def make_label_quant_params(y: np.ndarray, y_qbits: int, fixed_scale: Optional[float]) -> Tuple[float, float, int]:
    """
    Returns (y_shift, y_scale, y_bits)
    For regression:
      encode y' = round((y + y_shift) * y_scale) into uint.
    """
    y_min = float(np.min(y))
    y_max = float(np.max(y))
    # shift to non-negative
    y_shift = -y_min
    span = max(y_max - y_min, 1e-12)

    if fixed_scale is not None:
        y_scale = float(fixed_scale)
    else:
        # fit range into y_qbits
        max_int = (1 << y_qbits) - 1
        y_scale = max_int / span

    # compute required bits for safety
    max_enc = int(round((y_max + y_shift) * y_scale))
    y_bits = max(1, max_enc.bit_length())
    return y_shift, y_scale, y_bits


def quantize_labels_reg(y: np.ndarray, y_shift: float, y_scale: float) -> np.ndarray:
    z = (y + y_shift) * y_scale
    z = np.clip(np.rint(z), 0, np.iinfo(np.uint64).max)
    return z.astype(np.uint64)


# -----------------------------
# Tree export in heap layout
# -----------------------------
@dataclass
class HeapTree:
    depth: int
    node_count: int  # 2^depth  (matches your attached style)
    threshold: np.ndarray  # uint64 [node_count]
    left: np.ndarray       # uint64 [node_count]
    right: np.ndarray      # uint64 [node_count]
    feature_id: np.ndarray # int64  [node_count]  (-1 for leaf)
    label: np.ndarray      # uint64 [node_count]  (non-leaf may be 0)
    # for rebuilding feature values
    quant: QuantParams
    task: str
    n_features: int
    n_classes: int = 0


def build_heap_from_sklearn_tree(
    sk_tree,
    depth: int,
    qp: QuantParams,
    task: str,
    leaf_value_as_label: bool,
) -> HeapTree:
    node_count = int(sk_tree.node_count)
    thr = np.zeros(node_count, dtype=np.uint64)
    left = np.zeros(node_count, dtype=np.uint64)
    right = np.zeros(node_count, dtype=np.uint64)
    fid = np.full(node_count, -1, dtype=np.int64)
    lab = np.zeros(node_count, dtype=np.uint64)

    # sklearn arrays
    children_left = sk_tree.children_left
    children_right = sk_tree.children_right
    feature = sk_tree.feature
    threshold = sk_tree.threshold
    value = sk_tree.value  # shape: (n_nodes, 1, n_classes) or (n_nodes, 1, 1) for reg
    for nid in range(node_count):
        is_leaf = (children_left[nid] == children_right[nid]) or (children_left[nid] < 0)
        if is_leaf:
            fid[nid] = -1
            thr[nid] = 0
            left[nid] = nid
            right[nid] = nid
            # leaf label
            if task == "clf":
                cls = int(np.argmax(value[nid, 0]))
                lab[nid] = np.uint64(cls)
            else:
                pred = float(value[nid, 0, 0])
                if leaf_value_as_label:
                    lab[nid] = np.uint64(int(round(pred)))
                else:
                    lab[nid] = np.uint64(0)
            continue

        f = int(feature[nid])
        fid[nid] = f
        thr[nid] = np.uint64(quantize_threshold(float(threshold[nid]), qp))
        lab[nid] = np.uint64(0)
        left[nid] = np.uint64(children_left[nid])
        right[nid] = np.uint64(children_right[nid])

    return HeapTree(
        depth=depth,
        node_count=node_count,
        threshold=thr,
        left=left,
        right=right,
        feature_id=fid,
        label=lab,
        quant=qp,
        task=task,
        n_features=sk_tree.n_features,
        n_classes=getattr(sk_tree, "n_classes", 0),
    )


def build_feature_values_for_input_x(ht: HeapTree, x_raw: np.ndarray) -> np.ndarray:
    """
    Create per-node feature values for a given input x.
    feature_val[i] = quantized x[feature_id[i]] (leaf -> 0)
    """
    assert x_raw.shape[0] == ht.n_features
    xq = quantize_features(x_raw.reshape(1, -1), ht.quant).reshape(-1)  # uint64

    node_count = ht.node_count
    fv = np.zeros(node_count, dtype=np.uint64)
    for i in range(node_count):
        f = int(ht.feature_id[i])
        if f >= 0:
            fv[i] = xq[f]
    return fv


def pick_ring_bits(layout_entries: int) -> int:
    """
    Pick the minimum d such that 2^d >= layout_entries (OA address space).
    """
    if layout_entries < 1:
        raise ValueError("layout_entries must be >= 1")
    return max(1, int(math.ceil(math.log2(layout_entries))))


def write_u64_bin(path: str, arr_u64: np.ndarray) -> None:
    arr_u64 = np.asarray(arr_u64, dtype=np.uint64)
    with open(path, "wb") as f:
        f.write(arr_u64.tobytes(order="C"))


def write_u64_dat(path: str, arr_u64: np.ndarray) -> None:
    """Write RingOA FileIo-compatible binary: [count(size_t)][data]."""
    arr_u64 = np.asarray(arr_u64, dtype=np.uint64)
    count = np.uint64(arr_u64.size)
    with open(path, "wb") as f:
        f.write(count.tobytes())
        if arr_u64.size:
            f.write(arr_u64.tobytes(order="C"))


def pad_database_to_bits(db: np.ndarray, d_bits: int) -> np.ndarray:
    target = 1 << d_bits
    if db.size > target:
        raise ValueError(f"database size {db.size} exceeds 2^d ({target})")
    if db.size == target:
        return db
    out = np.zeros(target, dtype=np.uint64)
    out[: db.size] = db
    return out


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True,
                    choices=["wine", "breast", "digits", "spambase", "diabetes", "BOSTON", "MNIST"])
    ap.add_argument("--depth", type=str, default="12",
                    help="Fixed heap depth D (node_count=2^D). Match your evaluator's kTreeDepth, "
                         "or use 'auto' to match the learned tree depth.")
    ap.add_argument("--qbits", type=int, default=16,
                    help="Quantization bits for feature/threshold (uint).")
    ap.add_argument("--y_qbits", type=int, default=20,
                    help="Quantization bits for regression label if no fixed scale is given.")
    ap.add_argument("--y_scale", type=float, default=None,
                    help="Optional fixed scaling for regression label (e.g. 1000.0 for 3 decimals).")
    ap.add_argument("--d_bits", type=int, default=None,
                    help="Pad database to size 2^d_bits for RingOA OA domain. "
                         "Defaults to the minimum required bits.")
    ap.add_argument("--outdir", type=str, default="out")
    ap.add_argument("--emit-expected", action="store_true",
                    help="Write expected label to a binary file for pdte bench.")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--test_size", type=float, default=0.2)
    ap.add_argument("--max_depth", type=int, default=None,
                    help="sklearn decision tree max_depth (independent from heap depth).")
    args = ap.parse_args()

    ds_name = args.dataset
    depth_arg = args.depth.strip().lower()
    X, y, task = load_dataset(ds_name)
    os.makedirs(args.outdir, exist_ok=True)

    # split
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed,
        stratify=y if task == "clf" else None
    )

    # quant params for features
    qp = make_feature_quant_params(Xtr, qbits=args.qbits)

    # labels
    n_classes = 0
    if task == "clf":
        ytr_int = ytr.astype(np.int64)
        yte_int = yte.astype(np.int64)
        n_classes = int(np.max(ytr_int)) + 1
    else:
        y_shift, y_scale, y_bits = make_label_quant_params(ytr.astype(np.float64), args.y_qbits, args.y_scale)
        qp.y_shift = y_shift
        qp.y_scale = y_scale
        qp.y_bits = y_bits
        ytr_int = quantize_labels_reg(ytr.astype(np.float64), y_shift, y_scale)
        yte_int = quantize_labels_reg(yte.astype(np.float64), y_shift, y_scale)

    # train sklearn tree on *quantized features* for consistency with exported thresholds
    Xtr_q = quantize_features(Xtr, qp).astype(np.float64)  # sklearn expects float thresholds; safe to keep as float
    Xte_q = quantize_features(Xte, qp).astype(np.float64)

    if task == "clf":
        model = DecisionTreeClassifier(
            random_state=args.seed,
            max_depth=args.max_depth,
        )
        model.fit(Xtr_q, ytr_int)
    else:
        model = DecisionTreeRegressor(
            random_state=args.seed,
            max_depth=args.max_depth,
        )
        model.fit(Xtr_q, ytr_int.astype(np.float64))

    if depth_arg == "auto":
        heap_depth = int(model.tree_.max_depth) + 1
    else:
        heap_depth = int(depth_arg)
    if heap_depth < 1:
        raise ValueError("depth must be >= 1")

    ht = build_heap_from_sklearn_tree(
        model.tree_,
        depth=heap_depth,
        qp=qp,
        task=task,
        leaf_value_as_label=True,
    )
    ht.n_classes = n_classes

    # quick sanity on a single sample: run a plain heap eval
    x0 = Xte[0]
    feature_vals0 = build_feature_values_for_input_x(ht, x0)
    node_count = ht.node_count
    idx = 0
    for _ in range(ht.depth):
        fv = int(feature_vals0[idx])
        thr = int(ht.threshold[idx])
        go_left = (fv < thr)
        idx = int(ht.left[idx] if go_left else ht.right[idx])
        if idx >= node_count:
            idx = node_count - 1
    pred_heap = int(ht.label[idx])

    # ring bits recommendation / padding
    layout_entries = max(ht.node_count, 1 << ht.depth)
    addr_bits = max(1, int(ht.node_count - 1).bit_length())
    value_bits = max(ht.quant.bits, ht.quant.y_bits, addr_bits) + 2
    d_bits = max(pick_ring_bits(layout_entries), value_bits, 10)
    if args.d_bits is not None:
        d_bits = args.d_bits
        if (1 << d_bits) < layout_entries:
            raise ValueError("d_bits too small for node layout")

    thr_db = pad_database_to_bits(ht.threshold, d_bits)
    left_db = pad_database_to_bits(ht.left, d_bits)
    right_db = pad_database_to_bits(ht.right, d_bits)
    feat_db = pad_database_to_bits(feature_vals0, d_bits)
    label_db = pad_database_to_bits(ht.label, d_bits)

    learned_node_count = int(model.tree_.node_count)

    # export artifacts
    prefix = f"{ds_name.lower()}_D{ht.depth}_q{args.qbits}"
    np.savez_compressed(
        os.path.join(args.outdir, prefix + ".npz"),
        depth=np.int64(ht.depth),
        threshold=ht.threshold,
        left=ht.left,
        right=ht.right,
        feature_id=ht.feature_id,
        label=ht.label,
        shift=ht.quant.shift.astype(np.float64),
        scale=ht.quant.scale.astype(np.float64),
        qbits=np.int64(ht.quant.bits),
        task=np.string_(task),
        y_shift=np.float64(ht.quant.y_shift),
        y_scale=np.float64(ht.quant.y_scale),
        y_bits=np.int64(ht.quant.y_bits),
        pred_heap=np.int64(pred_heap),
        d_bits=np.int64(d_bits),
        learned_node_count=np.int64(learned_node_count),
        n_features=np.int64(X.shape[1]),
    )

    # write example databases for x0 (like the offline generator does)
    thr_bin = os.path.join(args.outdir, prefix + "_threshold_x0.bin")
    left_bin = os.path.join(args.outdir, prefix + "_left_x0.bin")
    right_bin = os.path.join(args.outdir, prefix + "_right_x0.bin")
    feat_bin = os.path.join(args.outdir, prefix + "_feature_x0.bin")
    label_bin = os.path.join(args.outdir, prefix + "_label_x0.bin")
    write_u64_bin(thr_bin, thr_db)
    write_u64_bin(left_bin, left_db)
    write_u64_bin(right_bin, right_db)
    write_u64_bin(feat_bin, feat_db)
    write_u64_bin(label_bin, label_db)
    write_u64_dat(thr_bin + ".dat", thr_db)
    write_u64_dat(left_bin + ".dat", left_db)
    write_u64_dat(right_bin + ".dat", right_db)
    write_u64_dat(feat_bin + ".dat", feat_db)
    write_u64_dat(label_bin + ".dat", label_db)
    if args.emit_expected:
        expected = np.array([pred_heap], dtype=np.uint64)
        expected_bin = os.path.join(args.outdir, prefix + "_expected.bin")
        write_u64_bin(expected_bin, expected)
        write_u64_dat(expected_bin + ".dat", expected)

    meta_txt = os.path.join(args.outdir, prefix + "_meta.txt")
    with open(meta_txt, "w", encoding="utf-8") as f:
        f.write(f"dataset={ds_name}\n")
        f.write(f"task={task}\n")
        f.write(f"heap_depth={ht.depth}\n")
        f.write(f"node_count={ht.node_count}\n")
        f.write(f"padded_node_count={thr_db.size}\n")
        f.write(f"learned_node_count={learned_node_count}\n")
        f.write(f"n_features={X.shape[1]}\n")
        f.write(f"layout_entries={layout_entries}\n")
        f.write(f"recommended_d_bits={d_bits}\n")
        f.write(f"database_size={thr_db.size}\n")
        f.write(f"feature_qbits={ht.quant.bits}\n")
        if task == "reg":
            f.write(f"y_shift={ht.quant.y_shift}\n")
            f.write(f"y_scale={ht.quant.y_scale}\n")
            f.write(f"y_bits={ht.quant.y_bits}\n")
        f.write(f"example_pred_heap={pred_heap}\n")

    print(f"[OK] wrote: {os.path.join(args.outdir, prefix + '.npz')}")
    print(f"[OK] wrote: {thr_bin}")
    print(f"[OK] wrote: {left_bin}")
    print(f"[OK] wrote: {right_bin}")
    print(f"[OK] wrote: {feat_bin}")
    print(f"[OK] wrote: {label_bin}")
    print(f"[OK] wrote: {thr_bin + '.dat'}")
    print(f"[OK] wrote: {left_bin + '.dat'}")
    print(f"[OK] wrote: {right_bin + '.dat'}")
    print(f"[OK] wrote: {feat_bin + '.dat'}")
    print(f"[OK] wrote: {label_bin + '.dat'}")
    if args.emit_expected:
        print(f"[OK] wrote: {os.path.join(args.outdir, prefix + '_expected.bin')}")
        print(f"[OK] wrote: {os.path.join(args.outdir, prefix + '_expected.bin.dat')}")
    print(f"[OK] wrote: {meta_txt}")
    print(f"[INFO] recommended d bits = {d_bits} (need 2^d >= node_count and enough value bits)")


if __name__ == "__main__":
    main()
