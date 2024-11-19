# frontend/Dockerfile
FROM python:3.9
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
#CMD ["python", "app.py"]
RUN pip install python-dotenv
CMD ["flask", "run", "--host=0.0.0.0"]

CMD ["python", "app.py"]

# Da permisos de ejecución al script start.sh
#RUN chmod +x start.sh

# Expón el puerto (si es necesario)
#EXPOSE 5000

# Usa el script start.sh como el comando de inicio
#CMD ["./start.sh"]
