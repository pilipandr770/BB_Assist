from backend.models import Scope
from backend.services.phases.active_recon_phase import explicit_scope_hosts


def test_explicit_hosts_only():
    sc = Scope(in_scope_domains=["*.sip.*.twilio.com", "api.twilio.com", "Twilio.com.", "192.168.0.1", "bad host", "*.x.com"])
    assert explicit_scope_hosts(sc) == {"api.twilio.com", "twilio.com"}
