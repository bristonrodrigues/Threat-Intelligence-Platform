from flask import Flask
from flask import request
from flask import jsonify

from ml_model import predict_url
from feature_extractor import extract_features


app = Flask(__name__)


@app.route('/')

def home():

    return "Threat Intelligence Platform Running"


@app.route('/predict', methods=['POST'])

def predict():

    data = request.json

    url = data['url']

    # Extract Features

    features = extract_features(url)

    # Predict Using ML Model

    result = predict_url(features)

    # Add URL in Response

    result["url"] = url

    return jsonify(result)


if __name__ == '__main__':

    app.run(debug=True)