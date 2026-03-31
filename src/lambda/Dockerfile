FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt .

COPY auditors/ auditors/

COPY handler.py .

RUN pip install -r requirements.txt --no-cache-dir

CMD ["handler.lambda_handler"]