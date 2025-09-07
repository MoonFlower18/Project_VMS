from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_results():
    data = request.get_json()
    print("Получены результаты сканирования:", data)
    return jsonify({"status": "success"}), 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)