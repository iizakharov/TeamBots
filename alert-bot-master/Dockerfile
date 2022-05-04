FROM python:3.8.3-alpine

WORKDIR /usr/local/bin

# переменные окружения для python
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# устанавливаем зависимости
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

#CMD ["python3", "db_manage.py"]
CMD ["python3", "main.py"]
