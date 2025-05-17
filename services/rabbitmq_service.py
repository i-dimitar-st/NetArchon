
import json
import threading
import sys
from services.logger.logger import MainLogger


# fmt: off
sys.path.append('/projects/gitlab/netarchon/venv/lib/python3.12/site-packages')
import pika # type: ignore
# fmt: on

rabbidmq_logger = MainLogger.get_logger(service_name="RABBIT-MQ", log_level="debug")


class RabbitMqConsumer:
    def __init__(self, message_queue: str = "message_queue_dhcp", consumer_tag: str = 'default_consumer'):
        """Initializes the RabbitMqConsumer with one message queue and consumer tag"""
        self.stop_event = threading.Event()
        self.message_queue = message_queue
        self.consumer_tag = consumer_tag

    def process_message(self, ch, method, properties, body):
        """Handles requests from RabbitMQ and stores in-memory."""
        try:
            message = json.loads(body.decode('utf-8'))
            rabbidmq_logger.info(f"Received message:{message}")
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            rabbidmq_logger.error(f"Error processing request: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag)

    def listen_message(self):
        """Starts listening for requests on RabbitMQ."""
        rabbidmq_logger.info(f"Starting RabbitMQ listener for message queue: {self.message_queue}...")

        try:
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            channel.queue_declare(queue=self.message_queue, durable=True)
            channel.basic_consume(queue=self.message_queue, on_message_callback=self.process_message,
                                  consumer_tag=self.consumer_tag)

            while not self.stop_event.is_set():
                connection.process_data_events(time_limit=1)

            connection.close()
            rabbidmq_logger.info("RabbitMQ listener stopped gracefully.")

        except Exception as e:
            rabbidmq_logger.error(f"Error starting RabbitMQ listener:{e}")

    def start(self):
        """Starts both RabbitMQ listeners in separate threads."""
        rabbitmq_thread = threading.Thread(target=self.listen_message, name="rabbitmq-listener", daemon=True)
        rabbitmq_thread.start()
        rabbidmq_logger.info(f"RabbitMQ listeners {self.consumer_tag} thread started.")

    def stop(self):
        """Stops both RabbitMQ listeners gracefully."""
        rabbidmq_logger.info("Stopping RabbitMQ listeners...")
        self.stop_event.set()  # Set the stop event to signal the threads to stop
        rabbidmq_logger.info("Stop event set. Listeners will stop after processing the current message.")
