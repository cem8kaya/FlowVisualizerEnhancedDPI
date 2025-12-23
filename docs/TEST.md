 rm -rf build && mkdir build && cd build && cmake .. -DBUILD_TESTS=ON && make -j4 && ./tests/test_parser_fields

 cd build && cmake .. && make -j4 && ./tests/test_parser_fields

cd build && cmake .. && make test_parser_fields test_ladder_generator test_participant_detection && ./tests/test_ladder_generator && ./tests/test_participant_detection && ./tests/test_parser_fields


~/…/FlowVisualizerEnhancedDPI $ docker build -t callflow-app .

~/…/FlowVisualizerEnhancedDPI $ docker run -d --name callflowd -p 8080:8080 -p 8081:8081 -v $(pwd)/data:/app/data -v $(pwd)/output:/app/output -v $(pwd)/db:/app/db callflowd:latest

 ### Build and Run with Docker Compose

```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f callflowd

# Stop services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v



docker builder prune
docker build --no-cache -t callflow-visualizer .
docker run -d --name callflowd -p 8080:8080 -p 8081:8081 -v $(pwd)/data:/app/data -v $(pwd)/output:/app/output -v $(pwd)/db:/app/db callflowd:latest

```

### Access the Application

- Web UI: http://localhost:8080
- WebSocket: ws://localhost:8081
- API: http://localhost:8080/api/v1/
- Health Check: http://localhost:8080/health
- Metrics: http://localhost:9090/metrics
