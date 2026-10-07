# Kacknex Agent Report

**Task:** Customers say discounted totals in the cart are wrong. Find out why and fix it
**Model:** `openai/gpt-oss-120b`

**Result:** ✅ success (c1, 7 turns, 8s, ~13800 tokens)

**Branch:** `agent/20261007-151448-c1` (review with `git diff HEAD...agent/20261007-151448-c1`) · patch: `patch.diff`

## What was failing before the fix
```
exit=1 passed=5 failed=2 skipped=0
FAILED tests.test_cart::test_total_with_discount
tests\test_cart.py:20: in test_total_with_discount
    assert c.total() == 80
E   assert 60 == 80
E    +  where 60 = total()
E    +    where total = <cart.cart.Cart object at 0x000001DA1544AE90>.total
FAILED tests.test_pricing::test_ten_percent_discount
tests\test_pricing.py:10: in test_ten_percent_discount
    assert apply_discount(200, 10) == 180
E   assert 190 == 180
E    +  where 190 = apply_discount(200, 10)
```

## Root cause
apply_discount incorrectly subtracted the discount percentage from the price, returning price - percent, which gave wrong discounted totals for both the pricing function and Cart.total().

## Summary
Updated apply_discount to correctly calculate the discounted price as price * (1 - percent/100) after validating the percent range. This fixes the discount calculations, making Cart.total() and apply_discount produce correct results. All tests now pass.

## Proof of fix (red → green)
| test | before | after |
|---|---|---|
| `tests.test_cart::test_total_with_discount` | FAIL | PASS |
| `tests.test_pricing::test_ten_percent_discount` | FAIL | PASS |

## Gates passed
- ✅ no regressions (5 baseline tests still pass)
- ✅ source diff 2 ≤ 150 changed lines
- ✅ existing tests untouched (append-only)
- ✅ no credentials in diff · env scrubbed · secret files unreadable
- ✅ every edit syntax-checked · worked in an isolated git worktree

## Files changed
- `cart/pricing.py`

## Diff stat
```
cart/pricing.py | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)
```
