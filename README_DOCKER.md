## Start
1) Copy .env.example -> .env
2) docker compose up --build

## URLs
Frontend: http://localhost:4200
Gateway: http://localhost:8080
Jaeger: http://localhost:16686
RabbitMQ: http://localhost:15672
Neo4j: http://localhost:7474
HDFS: http://localhost:9870

## Reset (delete DB data)
docker compose down -v
