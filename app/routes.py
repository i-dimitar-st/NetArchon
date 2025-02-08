from flask import render_template
from app.services import nat_service, dhcp_service, dns_service, firewall_service, stats_service


def setup_routes(app):

    @app.route('/')
    def index():
        # Example of returning data and rendering a basic UI
        return render_template('index.html', nat_status=nat_service.get_status(),
                               dhcp_status=dhcp_service.get_status(),
                               dns_status=dns_service.get_status())
