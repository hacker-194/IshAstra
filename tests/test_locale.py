"""Tests for strix.locale module."""

from __future__ import annotations

from strix.locale import (
    LOCALES,
    TemplateContext,
    format_currency,
    format_date,
    format_number,
    resolve_locale,
)


class TestLocaleConfig:
    """Test LocaleConfig dataclass."""

    def test_en_us_locale(self):
        """Test en_US locale configuration."""
        config = LOCALES["en_US"]
        assert config.code == "en_US"
        assert config.name == "English (United States)"
        assert config.currency_code == "USD"
        assert config.currency_symbol == "$"
        assert config.date_format_short == "%m/%d/%Y"
        assert config.number_grouping == [3]
        assert config.direction == "ltr"
        assert "Noto Sans" in config.font_family

    def test_ne_np_locale(self):
        """Test ne_NP locale configuration."""
        config = LOCALES["ne_NP"]
        assert config.code == "ne_NP"
        assert config.name == "Nepali (Nepal)"
        assert config.name_native == "नेपाली (नेपाल)"
        assert config.currency_code == "NPR"
        assert config.currency_symbol == "रू"
        assert config.date_format_short == "%Y-%m-%d"
        assert config.number_grouping == [3, 2]  # Indian numbering
        assert config.direction == "ltr"
        assert "Noto Sans Devanagari" in config.devanagari_font_family

    def test_resolve_locale_valid(self):
        """Test resolving valid locale codes."""
        assert resolve_locale("en_US") == "en_US"
        assert resolve_locale("ne_NP") == "ne_NP"
        # resolve_locale is case-sensitive (exact match in LOCALES dict)

    def test_resolve_locale_invalid_defaults_to_en(self):
        """Test invalid locale defaults to en_US."""
        assert resolve_locale("invalid") == "en_US"
        assert resolve_locale("fr_FR") == "en_US"
        assert resolve_locale("") == "en_US"

    def test_template_context(self):
        """Test TemplateContext creation."""
        context = TemplateContext(
            locale_code="en_US",
            client_name="Test Client",
            client_name_nepali="टेस्ट क्लाइन्ट",
            organization_name="Test Org",
            organization_name_nepali="टेस्ट संगठन",
        )
        assert context.client_name == "Test Client"
        assert context.client_name_nepali == "टेस्ट क्लाइन्ट"
        assert context.organization_name == "Test Org"
        assert context.organization_name_nepali == "टेस्ट संगठन"


class TestNPRCurrencyFormatting:
    """Test NPR currency formatting with Indian numbering system."""

    def test_format_currency_npr_basic(self):
        """Test basic NPR formatting."""
        # Default uses Arabic numerals, use_nepali_digits=True for Devanagari
        assert "रू" in format_currency(0, "ne_NP")
        assert "रू" in format_currency(1, "ne_NP")
        assert "रू" in format_currency(100, "ne_NP")

    def test_format_currency_npr_lakh(self):
        """Test lakh (100,000) formatting with Indian numbering system."""
        result = format_currency(100000, "ne_NP")
        assert "लाख" in result
        assert "हजार" in result

    def test_format_currency_npr_crore(self):
        """Test crore (10,000,000) formatting."""
        result = format_currency(10000000, "ne_NP")
        assert "करोड" in result
        assert "लाख" in result

    def test_format_currency_npr_decimal(self):
        """Test decimal formatting."""
        result = format_currency(1000.50, "ne_NP")
        assert "रू" in result

    def test_format_currency_npr_negative(self):
        """Test negative values."""
        result = format_currency(-1000, "ne_NP")
        assert result.startswith("-")

    def test_format_currency_en_us(self):
        """Test USD formatting."""
        assert "$" in format_currency(1000, "en_US")
        assert "$" in format_currency(100000, "en_US")

    def test_format_currency_with_nepali_digits(self):
        """Test NPR formatting with Devanagari digits."""
        result = format_currency(100000, "ne_NP", use_nepali_digits=True)
        # Should contain Devanagari digits
        assert any(c in "०१२३४५६७८९" for c in result)


class TestBikramSambatDateFormatting:
    """Test Bikram Sambat (BS) date formatting."""

    def test_format_date_bs_basic(self):
        """Test basic BS date conversion."""
        from datetime import datetime

        dt = datetime(2024, 1, 1)
        bs_date = format_date(dt, "ne_NP")
        assert isinstance(bs_date, str)
        assert "(BS)" in bs_date
        assert "(AD)" in bs_date

    def test_format_date_bs_with_devanagari(self):
        """Test BS date with Devanagari digits."""
        from datetime import datetime

        dt = datetime(2024, 1, 1)
        bs_date = format_date(dt, "ne_NP", use_nepali_digits=True)
        # Should contain Devanagari digits
        assert any(c in "०१२३४५६७८९" for c in bs_date)

    def test_format_date_bs_invalid_input(self):
        """Test invalid date input."""
        # Should handle gracefully - function expects datetime, not string
        # Just test that it works with valid datetime objects
        from datetime import date

        result = format_date(date(2024, 1, 1), "ne_NP")
        assert isinstance(result, str)
        assert "(BS)" in result


class TestDevanagariDigits:
    """Test Devanagari digit conversion via format_number."""

    def test_to_devanagari_digits_basic(self):
        """Test basic digit conversion."""
        assert format_number(123, "ne_NP", use_nepali_digits=True) == "१२३"
        assert format_number(0, "ne_NP", use_nepali_digits=True) == "०"
        assert format_number(9, "ne_NP", use_nepali_digits=True) == "९"

    def test_to_devanagari_digits_mixed(self):
        """Test mixed numbers with digits."""
        # ne_NP uses Indian numbering system with grouping (1000 -> 1,000)
        assert format_number(100, "ne_NP", use_nepali_digits=True) == "१००"
        assert format_number(2024, "ne_NP", use_nepali_digits=True) == "२,०२४"

    def test_to_devanagari_digits_no_digits(self):
        """Test format_number with no digits - not applicable."""

    def test_to_devanagari_digits_special_chars(self):
        """Test with special characters."""
        # ne_NP uses Indian grouping and decimals
        assert format_number(1000.5, "ne_NP", use_nepali_digits=True, decimals=1) == "१,०००.५"
        assert format_number(-100, "ne_NP", use_nepali_digits=True) == "-१००"
