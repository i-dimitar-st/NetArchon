from influxdb import InfluxDBClient

def log_network_stats(stats):
    client = InfluxDBClient(host='localhost', port=8086)
    client.switch_database('network_db')
    json_body = [
        {
            "measurement": "network_stats",
            "tags": {
                "host": "gateway_machine"
            },
            "fields": stats
        }
    ]
    client.write_points(json_body)
