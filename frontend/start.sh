#!/bin/bash

# Inicia la aplicación Flask
python app.py &

# Inicia el servidor Flask en el host 0.0.0.0
flask run --host=0.0.0.0
