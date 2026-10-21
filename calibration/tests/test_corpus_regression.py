"""Calibration corpus regression check.

These tests assert that the current state of the corpus + classifier
hits the "stable" threshold defined in docs/capability-classifier.md:

  - At least 10 labeled targets
  - Precision >= 0.90 on every exercised capability tag
  - Recall >= 0.75 on every exercised capability tag
  - Parameter-role accuracy >= 0.80

These are spec-floor assertions, not aspirational ones. The current
observed state (2026-06-11) is 100% precision and 100% recall across
6 exercised tags on 11 targets, with 90% param-role accuracy. The
floor is set at the spec's published threshold so a regression has
to be material before CI trips.

If you tune a rule and this test fails, you've dropped below the spec.
Either revert the tuning, or update the spec and update these tests in
the same commit.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from calibration.eval import evaluate_all

CALIBRATION_DIR = Path(__file__).resolve().parents[1]

# Spec-floor thresholds. Source: docs/capability-classifier.md.
SPEC_MIN_TARGETS = 10
SPEC_MIN_PRECISION = 0.90
SPEC_MIN_RECALL = 0.75
SPEC_MIN_PARAM_ROLE_ACCURACY = 0.80

# The four original calibration tags from v0.1. Removing one of these
# from the corpus is a coverage regression even if the metrics on the
# remaining tags stay high. New tags being added is fine; the originals
# disappearing is not.
ORIGINAL_TAGS = {"exec", "fs_read", "fs_write", "net_egress"}


@pytest.fixture(scope="module")
def aggregate():
    return evaluate_all(CALIBRATION_DIR)


def test_corpus_meets_spec_target_count(aggregate):
    assert aggregate.n_targets >= SPEC_MIN_TARGETS, (
        f"corpus shrank to {aggregate.n_targets} labeled targets; "
        f"spec stable threshold is {SPEC_MIN_TARGETS}"
    )


def test_per_tag_precision_meets_spec(aggregate):
    failing = []
    for tag, m in sorted(aggregate.by_tag.items()):
        if m.precision is None:
            continue  # no positives predicted; not a precision case
        if m.precision < SPEC_MIN_PRECISION:
            failing.append((tag, m.precision, m.true_pos, m.false_pos))
    assert not failing, f"tags below {SPEC_MIN_PRECISION:.2f} precision spec floor:\n" + "\n".join(
        f"  {tag}: precision={p:.2f} (tp={tp}, fp={fp})" for tag, p, tp, fp in failing
    )


def test_per_tag_recall_meets_spec(aggregate):
    failing = []
    for tag, m in sorted(aggregate.by_tag.items()):
        if m.recall is None:
            continue  # no ground-truth positives; not a recall case
        if m.recall < SPEC_MIN_RECALL:
            failing.append((tag, m.recall, m.true_pos, m.false_neg))
    assert not failing, f"tags below {SPEC_MIN_RECALL:.2f} recall spec floor:\n" + "\n".join(
        f"  {tag}: recall={r:.2f} (tp={tp}, fn={fn})" for tag, r, tp, fn in failing
    )


def test_param_role_accuracy_meets_spec(aggregate):
    acc = aggregate.param_role_accuracy
    if acc is None:
        pytest.skip("no parameter-role labels in corpus")
    assert acc >= SPEC_MIN_PARAM_ROLE_ACCURACY, (
        f"param-role accuracy {acc:.2%} below {SPEC_MIN_PARAM_ROLE_ACCURACY:.0%} spec floor "
        f"({aggregate.param_role_correct}/{aggregate.param_role_total})"
    )


def test_original_calibration_tags_still_exercised(aggregate):
    """Catches the case where ground-truth removal drops a whole capability area.

    The original four tags from v0.1 must remain in the corpus. New tags
    can be added freely; losing one of the originals is a coverage regression.
    """
    exercised = set(aggregate.by_tag.keys())
    missing = ORIGINAL_TAGS - exercised
    assert not missing, f"original calibration tags no longer exercised: {sorted(missing)}"


def test_no_zero_recall_tags(aggregate):
    """A tag with zero recall but nonzero ground-truth positives is broken.

    Distinct from the spec-floor recall check above: this catches the case
    where a tag is listed in ground truth but the classifier produces zero
    correct predictions for it. Recall would be 0.0 in that case, which is
    below the 0.75 spec floor, but the failure mode is different enough to
    deserve its own assertion (signals a totally-missing detector, not a
    tuning regression).
    """
    broken = []
    for tag, m in sorted(aggregate.by_tag.items()):
        if (m.true_pos + m.false_neg) > 0 and m.true_pos == 0:
            broken.append((tag, m.false_neg))
    assert not broken, "tags with ground-truth positives but zero true positives:\n" + "\n".join(
        f"  {tag}: fn={fn}, no detections at all" for tag, fn in broken
    )
