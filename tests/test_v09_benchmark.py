from scripts.run_v09_benchmark import percentile


def test_percentile_uses_sorted_samples():
    values = [5.0, 1.0, 4.0, 2.0, 3.0]

    assert percentile(values, 0.50) == 3.0
    assert percentile(values, 0.95) == 5.0
