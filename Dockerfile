FROM python:3.12-slim

WORKDIR /app

# Copia todo primero (si requirements no entra, lo veremos en el log)
COPY . .

# Debug: lista qué hay en /app
RUN echo "=== LS /app ===" && ls -la /app && echo "=== FIND requirements ===" && find /app -maxdepth 2 -type f -iname "*require*" -print

# Instala usando ruta absoluta si existe
RUN pip install --no-cache-dir -r /app/requirements.txt

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]





