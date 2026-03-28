"""Attack surface mapper — aggregates all discovered vectors into a unified map."""
# For authorized security testing only.
from typing import List, Dict
import requests
from recon.endpoint_discovery import EndpointDiscovery
from recon.param_extractor import ParamExtractor
from recon.tech_fingerprint import TechFingerprint
from recon.input_analyzer import InputAnalyzer
from core.logger import log_info


class AttackSurfaceMapper:
    def __init__(self, target, session: requests.Session):
        self.target = target
        self.session = session
        self.surface = {
            "endpoints": [],
            "forms": [],
            "parameters": {},
            "tech_stack": {},
            "input_vectors": [],
        }

    def map(self) -> Dict:
        """Build complete attack surface map."""
        log_info("Building attack surface map...")
        
        # Discovery
        ed = EndpointDiscovery(self.target, self.session)
        endpoints = ed.discover()
        self.surface["endpoints"] = endpoints
        self.surface["forms"] = self.target.forms
        
        # Parameter extraction
        pe = ParamExtractor(self.session)
        for ep in endpoints[:20]:  # Limit to avoid excessive requests
            from core.utils import make_request
            resp = make_request(self.session, ep.get("method", "GET"), ep["url"])
            if resp:
                params = pe.extract_from_response(resp, ep["url"])
                ep["discovered_params"] = params
        
        # Fingerprinting
        tf = TechFingerprint(self.session)
        from core.utils import make_request
        resp = make_request(self.session, "GET", self.target.url)
        self.surface["tech_stack"] = tf.fingerprint(self.target.url, resp)
        
        # Input analysis
        ia = InputAnalyzer(self.session)
        self.surface["input_vectors"] = ia.analyze(endpoints)
        
        log_info(f"Attack surface: {len(endpoints)} endpoints, {len(self.target.forms)} forms")
        return self.surface

    def get_high_priority_vectors(self) -> List[Dict]:
        """Return highest-priority input vectors for testing."""
        vectors = []
        for ep in self.surface.get("input_vectors", []):
            for v in ep.get("vectors", []):
                if v.get("priority", 0) >= 7:
                    vectors.append({**v, "url": ep["url"], "method": ep.get("method", "GET")})
        return sorted(vectors, key=lambda x: x.get("priority", 0), reverse=True)
