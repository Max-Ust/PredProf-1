#!/usr/bin/env python3
from flask import Flask, request
from storage import Storage
import json

app = Flask(__name__)


@app.route('/scheme', methods=['GET'])
def index():
    return json.dumps(st.storageStructure)


@app.route('/', methods=['POST'])
def addItems():
    putData = request.get_json()
    addItemsResponse = True
    for item in putData:
        localResponse = st.putInStorage(item['uuid'], item['destination'])
        if localResponse is False:
            addItemsResponse = False
    if addItemsResponse is True:
        return {"status": "ok"}
    else:
        return {"status": "error"}, 400


@app.route('/position', methods=['GET'])
def getItems():
    destination = request.args.getlist('destination')
    getItemsResponse = st.getFromStorage(destination)
    if getItemsResponse >= 0:
        return {"status": "ok"}
    elif getItemsResponse == -1:
        return {"status": "position is empty"}, 404
    elif getItemsResponse == -2:
        return {"status": "position does not exist"}, 400


if __name__ == '__main__':
    st = Storage()
    st.generateStorage()
    app.run(debug=True)
