from flask import Flask, render_template
from app.routes import setup_routes

app = Flask(__name__)

# Setup the routes
setup_routes(app)

if __name__ == '__main__':
    app.run(debug=True)
