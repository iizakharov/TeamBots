FROM python:3.8.10

WORKDIR /usr/local/bin

# переменные окружения для python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# устанавливаем зависимости
RUN pip install --upgrade pip setuptools wheel
COPY requirements.txt .
RUN pip install -r requirements.txt


COPY . .

CMD ["python3", "main.py"]

