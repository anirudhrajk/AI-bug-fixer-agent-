"""Creates ./demo-repo: a small shopping-cart project with a hidden bug spread across two files.
Run once:  python make_demo.py     (run it again any time to reset the bug)
"""
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "demo-repo"
FILES = {
    "conftest.py": "",
    "cart/__init__.py": "",
    "cart/pricing.py": '''def apply_discount(price, percent):
    """Return price after taking `percent` percent off."""
    if percent < 0 or percent > 100:
        raise ValueError("percent must be between 0 and 100")
    return price - percent


def format_money(amount):
    return f"${amount:,.2f}"
''',
    "cart/cart.py": '''from cart.pricing import apply_discount


class Cart:
    def __init__(self):
        self.items = []  # (name, unit_price, qty, discount_percent)

    def add(self, name, price, qty=1, discount=0):
        self.items.append((name, price, qty, discount))

    def total(self):
        total = 0
        for _name, price, qty, discount in self.items:
            total += apply_discount(price, discount) * qty
        return round(total, 2)

    def count(self):
        return sum(qty for _n, _p, qty, _d in self.items)
''',
    "tests/test_pricing.py": '''import pytest
from cart.pricing import apply_discount, format_money


def test_no_discount():
    assert apply_discount(50, 0) == 50


def test_ten_percent_discount():
    assert apply_discount(200, 10) == 180


def test_invalid_percent():
    with pytest.raises(ValueError):
        apply_discount(10, 150)


def test_format_money():
    assert format_money(1234.5) == "$1,234.50"
''',
    "tests/test_cart.py": '''from cart.cart import Cart


def test_count():
    c = Cart()
    c.add("pen", 2, qty=3)
    c.add("book", 10)
    assert c.count() == 4


def test_total_without_discount():
    c = Cart()
    c.add("pen", 2, qty=3)
    assert c.total() == 6


def test_total_with_discount():
    c = Cart()
    c.add("shoes", 80, qty=2, discount=50)
    assert c.total() == 80
''',
}


def git(*a):
    subprocess.run(["git", "-c", "user.name=demo", "-c", "user.email=demo@local", *a], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if ROOT.exists():
    shutil.rmtree(ROOT, ignore_errors=True)
for rel, text in FILES.items():
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
git("init", "-q")
git("add", "-A")
git("commit", "-q", "-m", "demo shopping cart with a pricing bug")
print(f"Created {ROOT}\n\nCheck the bug:   python -m pytest demo-repo -q   (expect 2 failed, 5 passed)\n")
print('Run the agent:   python agent.py --repo ./demo-repo --task "Customers say discounted totals in the cart are wrong. Find out why and fix it" --apply')
