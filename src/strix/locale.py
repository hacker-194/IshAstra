"""Locale and internationalization support for Strix reports.

Supports: English (en_US), Nepali (ne_NP) with Devanagari script.
Provides currency formatting (NPR with lakh/crore), date formatting
(Bikram Sambat + Gregorian), and RTL-aware layout helpers.
"""

from __future__ import annotations

import datetime
import html
from dataclasses import dataclass
from typing import Any, Literal

# ─── Locale Definitions ───

LocaleCode = Literal["en_US", "ne_NP"]


@dataclass(frozen=True)
class LocaleConfig:
    """Locale-specific configuration."""

    code: LocaleCode
    name: str
    name_native: str
    language: str
    script: str
    direction: Literal["ltr", "rtl"]
    currency_code: str
    currency_symbol: str
    currency_name: str
    date_format_short: str
    date_format_long: str
    datetime_format: str
    number_grouping: list[int]
    decimal_separator: str
    grouping_separator: str
    # Bikram Sambat offset from Gregorian (approximate)
    bs_year_offset: int = 57
    # Font configuration for PDF generation
    font_family: str = "Noto Sans"
    font_family_mono: str = "Noto Sans Mono"
    devanagari_font_family: str = "Noto Sans Devanagari"


LOCALES: dict[LocaleCode, LocaleConfig] = {
    "en_US": LocaleConfig(
        code="en_US",
        name="English (United States)",
        name_native="English",
        language="en",
        script="Latn",
        direction="ltr",
        currency_code="USD",
        currency_symbol="$",
        currency_name="US Dollar",
        date_format_short="%m/%d/%Y",
        date_format_long="%B %d, %Y",
        datetime_format="%B %d, %Y at %I:%M %p",
        number_grouping=[3],
        decimal_separator=".",
        grouping_separator=",",
        bs_year_offset=57,
        font_family="Noto Sans",
        font_family_mono="Noto Sans Mono",
        devanagari_font_family="Noto Sans Devanagari",
    ),
    "ne_NP": LocaleConfig(
        code="ne_NP",
        name="Nepali (Nepal)",
        name_native="नेपाली (नेपाल)",
        language="ne",
        script="Deva",
        direction="ltr",  # Nepali is LTR but mixed scripts need awareness
        currency_code="NPR",
        currency_symbol="रू",
        currency_name="Nepali Rupee",
        date_format_short="%Y-%m-%d",  # Will use BS format in practice
        date_format_long="%Y साल %B %d गते",
        datetime_format="%Y साल %B %d गते, %I:%M %p",
        number_grouping=[3, 2],  # Indian numbering: 1,00,000 (lakh), 1,00,00,000 (crore)
        decimal_separator=".",
        grouping_separator=",",
        bs_year_offset=57,
        font_family="Noto Sans",
        font_family_mono="Noto Sans Mono",
        devanagari_font_family="Noto Sans Devanagari",
    ),
}


# ─── Currency Formatting ───

_NEPALI_DIGITS = str.maketrans("0123456789", "०१२३४५६७८९")


def _to_nepali_digits(value: str) -> str:
    """Convert ASCII digits to Devanagari digits."""
    return value.translate(_NEPALI_DIGITS)


def format_currency(
    amount: float | int,
    locale_code: LocaleCode = "en_US",
    use_nepali_digits: bool = False,
    show_symbol: bool = True,
) -> str:
    """Format currency amount according to locale.

    For NPR (ne_NP), uses Indian numbering system: लाख (lakh = 100,000),
    करोड (crore = 10,000,000).
    """
    locale = LOCALES[locale_code]

    if locale_code == "ne_NP" and locale.currency_code == "NPR":
        return _format_npr(amount, locale, use_nepali_digits, show_symbol)

    # Standard formatting for other currencies
    sign = "-" if amount < 0 else ""
    amount = abs(amount)

    integer_part = int(amount)
    decimal_part = round(amount - integer_part, 2)

    # Group integer part
    grouped = _group_number(integer_part, locale.number_grouping, locale.grouping_separator)

    if decimal_part > 0:
        decimal_str = f"{decimal_part:.2f}".split(".")[1]
        result = f"{grouped}{locale.decimal_separator}{decimal_str}"
    else:
        result = grouped

    if show_symbol:
        result = f"{locale.currency_symbol} {result}"

    if sign:
        result = f"-{result}"

    if use_nepali_digits and locale_code == "ne_NP":
        result = _to_nepali_digits(result)

    return result


def _format_npr(
    amount: float | int,
    locale: LocaleConfig,
    use_nepali_digits: bool,
    show_symbol: bool,
) -> str:
    """Format NPR using Indian numbering (lakh/crore)."""
    sign = "-" if amount < 0 else ""
    amount = abs(amount)

    crore = int(amount // 10_000_000)
    lakh = int((amount % 10_000_000) // 100_000)
    thousand = int((amount % 100_000) // 1_000)
    remainder = int(amount % 1_000)
    decimal_part = round(amount - int(amount), 2)

    parts = []
    if crore > 0:
        parts.append(f"{crore} करोड")
    if lakh > 0 or crore > 0:
        parts.append(f"{lakh:02d} लाख")
    if thousand > 0 or lakh > 0 or crore > 0:
        parts.append(f"{thousand:03d} हजार")
    parts.append(f"{remainder:03d}")

    integer_str = " ".join(parts)

    if decimal_part > 0:
        decimal_str = f"{decimal_part:.2f}".split(".")[1]
        integer_str = f"{integer_str}{locale.decimal_separator}{decimal_str}"

    if show_symbol:
        integer_str = f"{locale.currency_symbol} {integer_str}"

    if sign:
        integer_str = f"-{integer_str}"

    if use_nepali_digits:
        integer_str = _to_nepali_digits(integer_str)

    return integer_str


def _group_number(
    number: int,
    grouping: list[int],
    separator: str,
) -> str:
    """Group number according to locale grouping rules."""
    if number == 0:
        return "0"

    digits = str(number)
    result_parts = []
    idx = len(digits)

    # Apply grouping from right to left
    group_idx = 0
    while idx > 0:
        group_size = grouping[min(group_idx, len(grouping) - 1)]
        start = max(0, idx - group_size)
        result_parts.append(digits[start:idx])
        idx = start
        group_idx += 1

    return separator.join(reversed(result_parts))


# ─── Date Formatting ───

# Nepali month names (Bikram Sambat)
_BS_MONTHS_NEPALI = [
    "बैशाख",
    "जेठ",
    "असार",
    "श्रावण",
    "भाद्र",
    "आश्विन",
    "कार्तिक",
    "मंसिर",
    "पौष",
    "माघ",
    "फाल्गुन",
    "चैत्र",
]


# Approximate BS month start dates (Gregorian) for year 2080 BS
# These are approximate; exact conversion requires lunar calendar
_BS_MONTH_STARTS = {
    1: (4, 14),  # Baisakh 1 ≈ April 14
    2: (5, 15),  # Jestha 1 ≈ May 15
    3: (6, 15),  # Ashar 1 ≈ June 15
    4: (7, 17),  # Shrawan 1 ≈ July 17
    5: (8, 17),  # Bhadra 1 ≈ August 17
    6: (9, 17),  # Ashwin 1 ≈ September 17
    7: (10, 17),  # Kartik 1 ≈ October 17
    8: (11, 16),  # Mangsir 1 ≈ November 16
    9: (12, 16),  # Poush 1 ≈ December 16
    10: (1, 14),  # Magh 1 ≈ January 14
    11: (2, 13),  # Falgun 1 ≈ February 13
    12: (3, 14),  # Chaitra 1 ≈ March 14
}


def gregorian_to_bikram_sambat(date: datetime.date) -> tuple[int, int, int]:
    """Convert Gregorian date to approximate Bikram Sambat (BS).

    Returns (bs_year, bs_month, bs_day).
    Note: This is an approximation. Exact conversion requires
    a proper lunar calendar library.
    """
    bs_year = date.year + LOCALES["ne_NP"].bs_year_offset

    # Find BS month by checking approximate start dates
    bs_month = 1
    bs_day = 1

    for month in range(12, 0, -1):
        start_month, start_day = _BS_MONTH_STARTS[month]
        # Handle year wrap for Magh, Falgun, Chaitra (months 10, 11, 12)
        if month >= 10:
            # These months start in the next Gregorian year
            compare_date = datetime.date(date.year, start_month, start_day)
        else:
            compare_date = datetime.date(date.year, start_month, start_day)

        if date >= compare_date:
            bs_month = month
            bs_day = (date - compare_date).days + 1
            break

    return (bs_year, bs_month, bs_day)


def format_date(
    date: datetime.date | datetime.datetime,
    locale_code: LocaleCode = "en_US",
    include_bs: bool = True,
    use_nepali_digits: bool = False,
) -> str:
    """Format date according to locale.

    For ne_NP, includes both Gregorian and Bikram Sambat dates.
    """
    locale = LOCALES[locale_code]

    if isinstance(date, datetime.datetime):
        dt = date
        date_only = date.date()
    else:
        dt = None
        date_only = date

    if locale_code == "ne_NP" and include_bs:
        bs_year, bs_month, bs_day = gregorian_to_bikram_sambat(date_only)

        # Format BS date in Nepali
        bs_month_name = _BS_MONTHS_NEPALI[bs_month - 1]
        bs_str = f"{bs_year} {bs_month_name} {bs_day}"

        # Also include Gregorian
        greg_str = date_only.strftime("%Y-%m-%d")

        result = f"{bs_str} (BS) / {greg_str} (AD)"

        if use_nepali_digits:
            result = _to_nepali_digits(result)

        if dt:
            time_str = dt.strftime("%I:%M %p")
            result = f"{result}, {time_str}"

        return result

    # Standard locale formatting
    if dt:
        return dt.strftime(locale.datetime_format)
    return date_only.strftime(locale.date_format_long)


def format_datetime(
    dt: datetime.datetime,
    locale_code: LocaleCode = "en_US",
    include_bs: bool = True,
    use_nepali_digits: bool = False,
) -> str:
    """Format datetime according to locale."""
    return format_date(dt, locale_code, include_bs, use_nepali_digits)


# ─── RTL-Aware Layout Helpers ───


@dataclass(frozen=True)
class LayoutDirection:
    """Layout direction configuration."""

    direction: Literal["ltr", "rtl"]
    text_align: str
    flex_direction: str
    margin_start: str
    margin_end: str
    padding_start: str
    padding_end: str


LAYOUT_DIRECTIONS = {
    "ltr": LayoutDirection(
        direction="ltr",
        text_align="left",
        flex_direction="row",
        margin_start="margin-left",
        margin_end="margin-right",
        padding_start="padding-left",
        padding_end="padding-right",
    ),
    "rtl": LayoutDirection(
        direction="rtl",
        text_align="right",
        flex_direction="row-reverse",
        margin_start="margin-right",
        margin_end="margin-left",
        padding_start="padding-right",
        padding_end="padding-left",
    ),
}


def get_layout_direction(locale_code: LocaleCode) -> LayoutDirection:
    """Get layout direction for locale."""
    locale = LOCALES[locale_code]
    return LAYOUT_DIRECTIONS[locale.direction]


def get_html_dir(locale_code: LocaleCode) -> str:
    """Get HTML dir attribute for locale."""
    locale = LOCALES[locale_code]
    return locale.direction


def get_html_lang(locale_code: LocaleCode) -> str:
    """Get HTML lang attribute for locale."""
    locale = LOCALES[locale_code]
    return f"{locale.language}-{locale.code.split('_')[1].lower()}"


# ─── Template Variables ───


@dataclass(frozen=True)
class TemplateContext:
    """Template rendering context with localized values."""

    locale_code: LocaleCode
    client_name: str = ""
    client_name_nepali: str = ""
    organization_name: str = ""
    organization_name_nepali: str = ""
    program_name: str = ""
    program_name_nepali: str = ""
    authorized_by: str = ""
    authorized_by_nepali: str = ""
    authorization_ref: str = ""
    target: str = ""
    generated_at: datetime.datetime | None = None

    def get_client_name(self) -> str:
        """Get client name, preferring Nepali for ne_NP locale."""
        if self.locale_code == "ne_NP" and self.client_name_nepali:
            return self.client_name_nepali
        return self.client_name

    def get_organization_name(self) -> str:
        """Get organization name, preferring Nepali for ne_NP locale."""
        if self.locale_code == "ne_NP" and self.organization_name_nepali:
            return self.organization_name_nepali
        return self.organization_name

    def get_program_name(self) -> str:
        """Get program name, preferring Nepali for ne_NP locale."""
        if self.locale_code == "ne_NP" and self.program_name_nepali:
            return self.program_name_nepali
        return self.program_name

    def get_authorized_by(self) -> str:
        """Get authorized by, preferring Nepali for ne_NP locale."""
        if self.locale_code == "ne_NP" and self.authorized_by_nepali:
            return self.authorized_by_nepali
        return self.authorized_by

    def get_generated_date(self, include_bs: bool = True, use_nepali_digits: bool = False) -> str:
        """Get formatted generation date."""
        if self.generated_at is None:
            return ""
        return format_date(self.generated_at, self.locale_code, include_bs, use_nepali_digits)

    def get_generated_datetime(self, include_bs: bool = True, use_nepali_digits: bool = False) -> str:
        """Get formatted generation datetime."""
        if self.generated_at is None:
            return ""
        return format_datetime(self.generated_at, self.locale_code, include_bs, use_nepali_digits)


# ─── HTML Escaping with Locale Awareness ───


def esc(value: Any, locale_code: LocaleCode = "en_US") -> str:
    """HTML escape with locale-aware digit conversion."""
    locale = LOCALES[locale_code]
    escaped = html.escape(str(value if value is not None else ""), quote=True)
    if locale_code == "ne_NP" and locale.script == "Deva":
        # Keep Devanagari digits as-is, only escape HTML special chars
        pass
    return escaped


# ─── Number Formatting ───


def format_number(
    number: int | float,
    locale_code: LocaleCode = "en_US",
    use_nepali_digits: bool = False,
    decimals: int = 0,
) -> str:
    """Format number according to locale grouping rules."""
    locale = LOCALES[locale_code]

    if number == 0:
        result = "0"
    else:
        sign = "-" if number < 0 else ""
        number = abs(number)

        if isinstance(number, float) or decimals > 0:
            integer_part = int(number)
            decimal_part = round(number - integer_part, decimals)
        else:
            integer_part = int(number)
            decimal_part = 0

        grouped = _group_number(integer_part, locale.number_grouping, locale.grouping_separator)

        if decimal_part > 0:
            decimal_str = f"{decimal_part:.{decimals}f}".split(".")[1]
            result = f"{grouped}{locale.decimal_separator}{decimal_str}"
        else:
            result = grouped

        if sign:
            result = f"-{result}"

    if use_nepali_digits and locale_code == "ne_NP":
        result = _to_nepali_digits(result)

    return result


# ─── Severity Labels ───

SEVERITY_LABELS: dict[LocaleCode, dict[str, str]] = {
    "en_US": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    },
    "ne_NP": {
        "critical": "गम्भीर",
        "high": "उच्च",
        "medium": "मध्यम",
        "low": "निम्न",
        "info": "जानकारी",
    },
}

VERIFICATION_LABELS: dict[LocaleCode, dict[str, str]] = {
    "en_US": {
        "verified": "Verified",
        "unverified": "Unverified",
        "false_positive": "False Positive",
    },
    "ne_NP": {
        "verified": "पुष्टि भएको",
        "unverified": "अपुष्ट",
        "false_positive": "गलत सकारात्मक",
    },
}

CONFIDENCE_LABELS: dict[LocaleCode, dict[str, str]] = {
    "en_US": {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    },
    "ne_NP": {
        "high": "उच्च",
        "medium": "मध्यम",
        "low": "निम्न",
    },
}

STATUS_LABELS: dict[LocaleCode, dict[str, str]] = {
    "en_US": {
        "new": "New",
        "in_progress": "In Progress",
        "fixed": "Fixed",
        "wont_fix": "Won't Fix",
        "risk_accepted": "Risk Accepted",
    },
    "ne_NP": {
        "new": "नयाँ",
        "in_progress": "प्रगतिमा",
        "fixed": "सुधारिएको",
        "wont_fix": "सुधार्ने छैन",
        "risk_accepted": "जोखिम स्वीकार्य",
    },
}


def get_severity_label(severity: str, locale_code: LocaleCode = "en_US") -> str:
    """Get localized severity label."""
    return SEVERITY_LABELS.get(locale_code, SEVERITY_LABELS["en_US"]).get(severity, severity)


def get_verification_label(verification: str, locale_code: LocaleCode = "en_US") -> str:
    """Get localized verification label."""
    return VERIFICATION_LABELS.get(locale_code, VERIFICATION_LABELS["en_US"]).get(verification, verification)


def get_confidence_label(confidence: str, locale_code: LocaleCode = "en_US") -> str:
    """Get localized confidence label."""
    return CONFIDENCE_LABELS.get(locale_code, CONFIDENCE_LABELS["en_US"]).get(confidence, confidence)


def get_status_label(status: str, locale_code: LocaleCode = "en_US") -> str:
    """Get localized status label."""
    return STATUS_LABELS.get(locale_code, STATUS_LABELS["en_US"]).get(status, status)


# ─── Default Locale Resolution ───


def resolve_locale(tenant_locale: str | None = None, assessment_locale: str | None = None) -> LocaleCode:
    """Resolve locale from tenant/assessment configuration.

    Priority: assessment_locale > tenant_locale > default (en_US)
    """
    if assessment_locale and assessment_locale in LOCALES:
        return assessment_locale
    if tenant_locale and tenant_locale in LOCALES:
        return tenant_locale
    return "en_US"


# ─── Report-Specific Helpers ───


def get_report_title(locale_code: LocaleCode) -> str:
    """Get localized report title."""
    titles = {
        "en_US": "Strix Assessment Report",
        "ne_NP": "स्ट्रिक्स मूल्यांकन प्रतिवेदन",
    }
    return titles.get(locale_code, titles["en_US"])


def get_report_sections(locale_code: LocaleCode) -> dict[str, str]:
    """Get localized report section titles."""
    sections = {
        "en_US": {
            "coverage": "Coverage",
            "findings": "Findings",
            "summary": "Summary",
            "evidence": "Evidence",
            "remediation": "Remediation",
            "description": "Description",
            "lifecycle": "Lifecycle",
            "risk_rating": "Risk Rating",
            "asset": "Asset",
            "location": "Location",
            "detector": "Detector",
            "category": "Category",
            "cwe": "CWE",
            "generated_at": "Generated at",
            "job_id": "Job ID",
            "target": "Target",
            "program": "Program",
            "authorized_by": "Authorized by",
            "authorization_ref": "Authorization ref",
            "scope": "Scope",
            "audit_chain": "Audit chain",
            "no_findings": "No findings were recorded for this assessment.",
        },
        "ne_NP": {
            "coverage": "कवरेज",
            "findings": "पत्ता लगाएका",
            "summary": "सारांश",
            "evidence": "प्रमाण",
            "remediation": "उपचार",
            "description": "विवरण",
            "lifecycle": "जीवनचक्र",
            "risk_rating": "जोखिम मूल्यांकन",
            "asset": "सम्पत्ति",
            "location": "स्थान",
            "detector": "पता लगाउने",
            "category": "श्रेणी",
            "cwe": "CWE",
            "generated_at": "जनरेट भएको",
            "job_id": "कार्य ID",
            "target": "लक्ष्य",
            "program": "कार्यक्रम",
            "authorized_by": "अधिकृत गर्ने",
            "authorization_ref": "अधिकरण सन्दर्भ",
            "scope": "दायरा",
            "audit_chain": "अडिट चेन",
            "no_findings": "यस मूल्यांकनका लागि कुनै पत्ता लगाएको रेकर्ड गरिएको छैन।",
        },
    }
    return sections.get(locale_code, sections["en_US"])


# ─── Self-test ───

if __name__ == "__main__":
    # Quick self-tests
    print("=== Currency Tests ===")
    print(f"USD 1234567.89: {format_currency(1234567.89, 'en_US')}")
    print(f"NPR 1234567.89: {format_currency(1234567.89, 'ne_NP')}")
    print(f"NPR 123456789: {format_currency(123456789, 'ne_NP')}")
    print(f"NPR 123456789 (Devanagari): {format_currency(123456789, 'ne_NP', use_nepali_digits=True)}")

    print("\n=== Date Tests ===")
    test_date = datetime.date(2026, 11, 12)
    print(f"EN: {format_date(test_date, 'en_US')}")
    print(f"NE: {format_date(test_date, 'ne_NP')}")
    print(f"NE (Devanagari): {format_date(test_date, 'ne_NP', use_nepali_digits=True)}")

    test_dt = datetime.datetime(2026, 11, 12, 14, 30)
    print(f"EN DT: {format_datetime(test_dt, 'en_US')}")
    print(f"NE DT: {format_datetime(test_dt, 'ne_NP')}")

    print("\n=== Number Tests ===")
    print(f"EN 1234567: {format_number(1234567, 'en_US')}")
    print(f"NE 1234567: {format_number(1234567, 'ne_NP')}")
    print(f"NE 1234567 (Devanagari): {format_number(1234567, 'ne_NP', use_nepali_digits=True)}")

    print("\n=== Label Tests ===")
    for sev in ["critical", "high", "medium", "low", "info"]:
        print(f"  {sev}: EN={get_severity_label(sev, 'en_US')} NE={get_severity_label(sev, 'ne_NP')}")

    print("\n=== Layout Tests ===")
    for loc_code in ["en_US", "ne_NP"]:
        ld = get_layout_direction(loc_code)  # type: ignore[arg-type]
        print(f"  {loc_code}: dir={ld.direction}, align={ld.text_align}")

    print("\n=== Context Tests ===")
    ctx = TemplateContext(
        locale_code="ne_NP",
        client_name="Example Bank",
        client_name_nepali="उदाहरण बैंक",
        organization_name="Strix Security",
        organization_name_nepali="स्ट्रिक्स सुरक्षा",
        generated_at=datetime.datetime(2026, 11, 12, 14, 30),
    )
    print(f"  Client: {ctx.get_client_name()}")
    print(f"  Org: {ctx.get_organization_name()}")
    print(f"  Date: {ctx.get_generated_date()}")
