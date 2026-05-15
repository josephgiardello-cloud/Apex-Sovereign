FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY BaseT8.py config.py verify_proof.py run_offline.py bootstrap_offline.py preflight_offline.py ./

EXPOSE 8000

CMD ["uvicorn", "BaseT8:app", "--host", "0.0.0.0", "--port", "8000"]
